package http

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/malivvan/tls"
)

// This file implements client fingerprinting primitives for the server side.
//
// The fingerprint of an incoming connection is captured at three levels:
//
//   - TLS: the raw ClientHello of the TLS handshake, from which JA3 and JA4
//     fingerprints are computed (see ParseClientHello, ComputeJA3, ComputeJA4).
//   - HTTP/2: the client's initial SETTINGS frame (values and wire order),
//     connection-level WINDOW_UPDATE increments and PRIORITY frames.
//   - HTTP: the order in which the client sent the request headers (and, for
//     HTTP/2, the pseudo-header order).
//
// All of this is exposed per request through Request.Fingerprint, and the
// per-request header order through Request.HeaderOrder and
// Request.PseudoHeaderOrder. No server configuration is required: the
// fingerprint is captured automatically for every connection that was
// established with github.com/malivvan/tls (which is the TLS library this
// package always uses internally).

// SettingID is the numeric identifier of a single HTTP/2 SETTINGS parameter.
//
// It is the same type as http2.SettingID (golang.org/x/net/http2) and is
// provided here so that fingerprint data can be consumed without importing a
// second HTTP/2 API.
type SettingID uint16

// HTTP/2 SETTINGS parameter identifiers, as defined by RFC 7540, Section 6.5.2
// and its extensions.
const (
	SettingHeaderTableSize       SettingID = 0x1 // RFC 7540, Section 6.5.2
	SettingEnablePush            SettingID = 0x2 // RFC 7540, Section 6.5.2
	SettingMaxConcurrentStreams  SettingID = 0x3 // RFC 7540, Section 6.5.2
	SettingInitialWindowSize     SettingID = 0x4 // RFC 7540, Section 6.5.2
	SettingMaxFrameSize          SettingID = 0x5 // RFC 7540, Section 6.5.2
	SettingMaxHeaderListSize     SettingID = 0x6 // RFC 7540, Section 6.5.2
	SettingEnableConnectProtocol SettingID = 0x8 // RFC 8441
	SettingNoRFC7540Priorities   SettingID = 0x9 // RFC 9218
)

// Setting is a single HTTP/2 SETTINGS parameter.
type Setting struct {
	// ID is the setting identifier.
	ID SettingID
	// Val is the setting value.
	Val uint32
}

// PriorityParam are the fields prior to a PRIORITY frame or the priority field
// in a HEADERS frame, as defined by RFC 7540, Section 6.3 and 5.3.1.
type PriorityParam struct {
	// StreamDep is a 31-bit stream identifier for the stream that this
	// stream depends on. Zero means no dependency.
	StreamDep uint32
	// Exclusive is whether the dependency is exclusive.
	Exclusive bool
	// Weight is the stream weight, in the range [1, 256].
	Weight uint8
}

// Priority is a PRIORITY frame sent by the client, as defined by RFC 7540,
// Section 6.3.
type Priority struct {
	PriorityParam
	// StreamID is the stream that this frame applies to.
	StreamID uint32
}

// TLSFingerprint describes the TLS ClientHello of an incoming connection.
//
// It is computed automatically by the server for every TLS connection and is
// reachable through Request.Fingerprint.TLS. It can also be computed from raw
// bytes captured elsewhere (e.g. with tcpdump) via ParseClientHello.
type TLSFingerprint struct {
	// Raw is the raw ClientHello handshake message, including the 4-byte
	// handshake header (message type + length), as it appeared on the wire
	// inside the TLS record.
	Raw []byte

	// Version is the legacy protocol version field of the ClientHello
	// (e.g. tls.VersionTLS12). Note that for TLS 1.3 connections clients
	// usually still put TLS 1.2 here; see SupportedVersions for the real
	// version list.
	Version uint16
	// Random is the 32-byte client random.
	Random []byte
	// SessionID is the client's session ID, if any.
	SessionID []byte

	// CipherSuites is the ordered list of cipher suites offered by the
	// client, as sent on the wire (including GREASE values, if any).
	CipherSuites []uint16
	// Extensions is the ordered list of extension type identifiers sent by
	// the client, as sent on the wire (including GREASE values, if any).
	Extensions []uint16
	// SupportedCurves is the content of the supported_groups (0x000a)
	// extension, in wire order.
	SupportedCurves []uint16
	// SupportedPoints is the content of the ec_point_formats (0x000b)
	// extension, in wire order.
	SupportedPoints []byte
	// SignatureAlgorithms is the content of the signature_algorithms
	// (0x000d) extension, in wire order.
	SignatureAlgorithms []uint16
	// SupportedVersions is the content of the supported_versions (0x002b)
	// extension, in wire order.
	SupportedVersions []uint16
	// ALPN is the ordered list of application protocols offered by the
	// client in the ALPN (0x0010) extension.
	ALPN []string
	// ServerName is the SNI host name from the server_name (0x0000)
	// extension, or "" if the client did not send one.
	ServerName string

	// JA3 is the raw JA3 string: the comma-separated, lowercase hex values
	// of version, cipher suites, extensions, supported curves and
	// ec_point_formats, in wire order, with GREASE values removed.
	JA3 string
	// JA3Hash is the MD5 hash of JA3. This is the value usually referred
	// to as "the JA3 fingerprint".
	JA3Hash string

	// JA4 is the JA4 TLS fingerprint, a truncated-sha256 based fingerprint
	// defined by FoxIO (https://github.com/FoxIO-LLC/ja4).
	JA4 string
	// JA4Raw is the raw ("-r") JA4 fingerprint: the sorted, GREASE-free
	// cipher, extension and signature algorithm lists that JA4 is hashed
	// from.
	JA4Raw string
}

// HTTP2Fingerprint describes the HTTP/2 connection behavior of an incoming
// client connection. It is captured automatically by the server for every
// HTTP/2 connection (both ALPN-negotiated and h2c) and is reachable through
// Request.Fingerprint.HTTP2. It is nil for HTTP/1.x connections.
//
// The ordering of the Settings slice is the order the settings appeared on
// the wire, which is a distinguishing client characteristic: browsers send
// their settings in a fixed order.
type HTTP2Fingerprint struct {
	// Settings are the SETTINGS parameters received from the client, in
	// wire order. To bound memory usage, at most MaxFingerprintSettings
	// parameters (a full SETTINGS frame) are recorded; browsers send a
	// handful.
	Settings []Setting
	// WindowUpdates are the increments of connection-level (stream 0)
	// WINDOW_UPDATE frames received from the client, in wire order. At
	// most MaxFingerprintFrames increments are recorded.
	WindowUpdates []uint32
	// Priorities are the PRIORITY frames received from the client, in wire
	// order. At most MaxFingerprintFrames frames are recorded.
	Priorities []Priority
}

// Caps on the recorded fingerprint data, to bound the memory a malicious
// client can make the server spend on capture. Real browsers send far less
// (a single SETTINGS frame, one connection WINDOW_UPDATE and a handful of
// PRIORITY frames).
const (
	// MaxFingerprintSettings is the maximum number of SETTINGS parameters
	// recorded per connection (a full SETTINGS frame is at most 100
	// entries).
	MaxFingerprintSettings = 100
	// MaxFingerprintFrames is the maximum number of connection-level
	// WINDOW_UPDATE increments and PRIORITY frames recorded per
	// connection.
	MaxFingerprintFrames = 100
)

// Fingerprint describes an incoming client connection. It is attached to
// every Request served by the server as Request.Fingerprint.
//
// The TLS and HTTP2 sub-structs are shared by all requests of the same
// connection; HTTP2 contains only data captured before the request headers
// were processed.
type Fingerprint struct {
	// TLS is the TLS ClientHello fingerprint. It is nil for plaintext
	// (non-TLS) connections.
	TLS *TLSFingerprint
	// HTTP2 is the HTTP/2 connection fingerprint. It is nil for HTTP/1.x
	// connections.
	HTTP2 *HTTP2Fingerprint
}

// Clone returns a deep copy of f, safe to store or attach to a request that
// is handled concurrently with further frame processing on the connection.
func (f *HTTP2Fingerprint) Clone() *HTTP2Fingerprint {
	if f == nil {
		return nil
	}
	c := *f
	c.Settings = append([]Setting(nil), f.Settings...)
	c.WindowUpdates = append([]uint32(nil), f.WindowUpdates...)
	c.Priorities = append([]Priority(nil), f.Priorities...)
	return &c
}

// isGREASEValue reports whether v is a GREASE value as defined by
// https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01
// (0x0a0a, 0x1a1a, ..., 0xfafa).
func isGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// parsedClientHello is the result of parsing a raw ClientHello message body.
type parsedClientHello struct {
	raw                []byte
	version            uint16
	random             []byte
	sessionID          []byte
	cipherSuites       []uint16
	compressionMethods []byte
	extensions         []parsedClientHelloExtension
}

type parsedClientHelloExtension struct {
	id   uint16
	data []byte
}

// typeClientHello is the TLS handshake message type of a ClientHello.
const typeClientHello = 1

// parseClientHello parses a raw ClientHello. data may be either the full
// handshake message (including the 4-byte type+length header) or the message
// body. It returns nil if the data is not a well-formed ClientHello.
func parseClientHello(data []byte) *parsedClientHello {
	if len(data) < 4 {
		return nil
	}
	// Strip the 4-byte handshake header (type + length) if present.
	if data[0] == typeClientHello {
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if n != len(data)-4 {
			return nil
		}
		data = data[4:]
	}
	if len(data) < 2+32+1+2+1 {
		return nil
	}
	ch := &parsedClientHello{raw: data}
	ch.version = uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	ch.random = data[:32]
	data = data[32:]
	sidLen := int(data[0])
	data = data[1:]
	if len(data) < sidLen+2 {
		return nil
	}
	ch.sessionID = data[:sidLen]
	data = data[sidLen:]
	csLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if csLen%2 != 0 || len(data) < csLen+1 {
		return nil
	}
	for i := 0; i < csLen; i += 2 {
		ch.cipherSuites = append(ch.cipherSuites, uint16(data[i])<<8|uint16(data[i+1]))
	}
	data = data[csLen:]
	cmLen := int(data[0])
	data = data[1:]
	if len(data) < cmLen+2 {
		return nil
	}
	ch.compressionMethods = data[:cmLen]
	data = data[cmLen:]
	extLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < extLen {
		return nil
	}
	data = data[:extLen]
	for len(data) >= 4 {
		id := uint16(data[0])<<8 | uint16(data[1])
		l := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < l {
			return nil
		}
		ch.extensions = append(ch.extensions, parsedClientHelloExtension{id: id, data: data[:l]})
		data = data[l:]
	}
	if len(data) != 0 {
		return nil
	}
	return ch
}

// extension returns the extension with the given id, or nil.
func (ch *parsedClientHello) extension(id uint16) *parsedClientHelloExtension {
	for i := range ch.extensions {
		if ch.extensions[i].id == id {
			return &ch.extensions[i]
		}
	}
	return nil
}

// extensionIDs returns the ordered list of extension type identifiers.
func (ch *parsedClientHello) extensionIDs() []uint16 {
	ids := make([]uint16, len(ch.extensions))
	for i, e := range ch.extensions {
		ids[i] = e.id
	}
	return ids
}

// parseSupportedCurves parses the supported_groups (0x000a) extension.
func (ch *parsedClientHello) parseSupportedCurves() []uint16 {
	e := ch.extension(0x000a)
	if e == nil || len(e.data) < 2 {
		return nil
	}
	n := int(e.data[0])<<8 | int(e.data[1])
	if len(e.data) < 2+n {
		return nil
	}
	curves := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		curves = append(curves, uint16(e.data[2+i])<<8|uint16(e.data[3+i]))
	}
	return curves
}

// parseSignatureAlgorithms parses the signature_algorithms (0x000d) extension.
func (ch *parsedClientHello) parseSignatureAlgorithms() []uint16 {
	e := ch.extension(0x000d)
	if e == nil || len(e.data) < 2 {
		return nil
	}
	n := int(e.data[0])<<8 | int(e.data[1])
	if len(e.data) < 2+n {
		return nil
	}
	sig := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		sig = append(sig, uint16(e.data[2+i])<<8|uint16(e.data[3+i]))
	}
	return sig
}

// parseSupportedVersions parses the supported_versions (0x002b) extension.
func (ch *parsedClientHello) parseSupportedVersions() []uint16 {
	e := ch.extension(0x002b)
	if e == nil || len(e.data) < 1 {
		return nil
	}
	n := int(e.data[0])
	if len(e.data) < 1+n {
		return nil
	}
	vers := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		vers = append(vers, uint16(e.data[1+i])<<8|uint16(e.data[2+i]))
	}
	return vers
}

// parseALPN parses the ALPN (0x0010) extension.
func (ch *parsedClientHello) parseALPN() []string {
	e := ch.extension(0x0010)
	if e == nil || len(e.data) < 2 {
		return nil
	}
	n := int(e.data[0])<<8 | int(e.data[1])
	if len(e.data) < 2+n {
		return nil
	}
	var protos []string
	data := e.data[2 : 2+n]
	for len(data) >= 1 {
		l := int(data[0])
		data = data[1:]
		if len(data) < l {
			return nil
		}
		protos = append(protos, string(data[:l]))
		data = data[l:]
	}
	return protos
}

// parseServerName parses the server_name (0x0000) extension.
func (ch *parsedClientHello) parseServerName() string {
	e := ch.extension(0x0000)
	if e == nil || len(e.data) < 2 {
		return ""
	}
	n := int(e.data[0])<<8 | int(e.data[1])
	if len(e.data) < 2+n {
		return ""
	}
	data := e.data[2 : 2+n]
	for len(data) >= 3 {
		// name type (1 byte) + length (2 bytes) + name
		nt := data[0]
		l := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < l {
			return ""
		}
		if nt == 0 { // host_name
			return string(data[:l])
		}
		data = data[l:]
	}
	return ""
}

// ParseClientHello parses a raw TLS ClientHello and computes the associated
// TLS fingerprint.
//
// data may be the raw handshake message as captured on the wire (including
// the 4-byte handshake header) or the ClientHello message body. It returns
// nil if data is not a well-formed ClientHello.
func ParseClientHello(data []byte) *TLSFingerprint {
	ch := parseClientHello(data)
	if ch == nil {
		return nil
	}
	fp := &TLSFingerprint{
		Raw:                 append([]byte(nil), data...),
		Version:             ch.version,
		Random:              append([]byte(nil), ch.random...),
		SessionID:           append([]byte(nil), ch.sessionID...),
		CipherSuites:        append([]uint16(nil), ch.cipherSuites...),
		Extensions:          ch.extensionIDs(),
		SupportedCurves:     ch.parseSupportedCurves(),
		SupportedPoints:     nil,
		SignatureAlgorithms: ch.parseSignatureAlgorithms(),
		SupportedVersions:   ch.parseSupportedVersions(),
		ALPN:                ch.parseALPN(),
		ServerName:          ch.parseServerName(),
	}
	if e := ch.extension(0x000b); e != nil {
		fp.SupportedPoints = append([]byte(nil), e.data...)
	}
	fp.JA3, fp.JA3Hash = ComputeJA3(data)
	fp.JA4, fp.JA4Raw = ComputeJA4(data)
	return fp
}

// FingerprintFromTLSConn computes the TLS fingerprint of a connection whose
// TLS handshake has completed. It uses the raw ClientHello recorded by
// github.com/malivvan/tls during the handshake (Conn.ClientHello), so it
// only works with connections established by that library — which is the TLS
// implementation this package always uses internally. It returns nil if the
// connection carries no recorded ClientHello.
func FingerprintFromTLSConn(tlsConn *tls.Conn) *TLSFingerprint {
	if tlsConn == nil || tlsConn.ClientHello == "" {
		return nil
	}
	raw, err := hex.DecodeString(tlsConn.ClientHello)
	if err != nil {
		return nil
	}
	return ParseClientHello(raw)
}

// Clone returns a deep copy of f, safe to attach to a request that is
// handled concurrently with further frame processing on the connection. The
// TLS sub-struct is shared with the original.
func (f *Fingerprint) Clone() *Fingerprint {
	if f == nil {
		return nil
	}
	c := *f
	c.HTTP2 = f.HTTP2.Clone()
	return &c
}

// hexList formats a list of uint16 values as lowercase, comma-separated hex
// values ("1301,1302,..."), skipping GREASE values.
func hexList(vals []uint16) string {
	var b strings.Builder
	for _, v := range vals {
		if isGREASEValue(v) {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", v)
	}
	return b.String()
}

// hexListSorted is like hexList but sorts the values in ascending hex order.
func hexListSorted(vals []uint16) string {
	sorted := append([]uint16(nil), vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return hexList(sorted)
}

// ComputeJA3 computes the JA3 fingerprint of a raw TLS ClientHello.
//
// The JA3 string is the comma-separated lowercase hex of the TLS version,
// cipher suites, extensions, supported curves and ec point formats, in wire
// order, with GREASE values removed. The hash is the MD5 of that string.
//
// See https://github.com/salesforce/ja3 for the full specification.
// data may include the 4-byte handshake header; it is stripped if present.
func ComputeJA3(data []byte) (ja3, ja3Hash string) {
	ch := parseClientHello(data)
	if ch == nil {
		return "", ""
	}
	curves := ch.parseSupportedCurves()
	var points []byte
	if e := ch.extension(0x000b); e != nil {
		points = e.data
	}
	s := strings.Join([]string{
		fmt.Sprintf("%04x", ch.version),
		hexList(ch.cipherSuites),
		hexList(ch.extensionIDs()),
		hexList(curves),
		hexBytes(points),
	}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// hexBytes formats a byte slice as lowercase, comma-separated hex values.
func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%02x", v)
	}
	return sb.String()
}

// ja4Version maps a TLS version to the two-character JA4 code.
func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN returns the two-character ALPN field of a JA4 fingerprint.
func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if isASCIIAlphaNumeric(first) && isASCIIAlphaNumeric(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(p))
	return h[:1] + h[len(h)-1:]
}

func isASCIIAlphaNumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// ja4Count formats a count as a two-digit decimal number, capped at 99.
func ja4Count(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// ComputeJA4 computes the JA4 and JA4_r fingerprints of a raw TLS ClientHello.
//
// JA4 is a truncated-sha256 based fingerprint of the TLS version, SNI
// presence, cipher suite count, extension count and ALPN value, combined with
// hashes of the sorted cipher list and the sorted extension list followed by
// the signature algorithms. JA4_r ("raw") is the same header with the full
// sorted lists instead of the hashes.
//
// See https://github.com/FoxIO-LLC/ja4 for the full specification.
// data may include the 4-byte handshake header; it is stripped if present.
func ComputeJA4(data []byte) (ja4, ja4Raw string) {
	ch := parseClientHello(data)
	if ch == nil {
		return "", ""
	}

	// TLS version: highest value of the supported_versions extension if
	// present, else the legacy protocol version field.
	version := ch.version
	if sv := ch.parseSupportedVersions(); len(sv) > 0 {
		max := uint16(0)
		for _, v := range sv {
			if isGREASEValue(v) {
				continue
			}
			if v > max {
				max = v
			}
		}
		if max != 0 {
			version = max
		}
	}

	sni := "i"
	if ch.extension(0x0000) != nil {
		sni = "d"
	}

	ciphers := ch.cipherSuites
	exts := ch.extensionIDs()
	sig := ch.parseSignatureAlgorithms()

	// Counts ignore GREASE values.
	cipherCount := 0
	for _, c := range ciphers {
		if !isGREASEValue(c) {
			cipherCount++
		}
	}
	extCount := 0
	for _, e := range exts {
		if !isGREASEValue(e) {
			extCount++
		}
	}

	header := "t" + ja4Version(version) + sni + ja4Count(cipherCount) + ja4Count(extCount) + ja4ALPN(ch.parseALPN())

	// Cipher hash: sha256 of the sorted cipher list, truncated to 12 chars.
	cipherList := hexListSorted(ciphers)
	var cipherHash string
	if len(cipherList) == 0 {
		cipherHash = "000000000000"
	} else {
		sum := sha256.Sum256([]byte(cipherList))
		cipherHash = hex.EncodeToString(sum[:])[:12]
	}

	// Extension hash: sha256 of the sorted extension list (SNI and ALPN
	// removed) followed by the signature algorithms in wire order,
	// truncated to 12 chars.
	var extList []uint16
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extList = append(extList, e)
	}
	sortedExtList := hexListSorted(extList)
	var extHash string
	if len(sortedExtList) == 0 {
		extHash = "000000000000"
	} else {
		sigList := hexList(sig)
		input := sortedExtList
		if sigList != "" {
			input += "_" + sigList
		}
		sum := sha256.Sum256([]byte(input))
		extHash = hex.EncodeToString(sum[:])[:12]
	}

	ja4 = header + "_" + cipherHash + "_" + extHash
	ja4Raw = header + "_" + cipherList + "_" + sortedExtList + "_" + hexList(sig)
	return ja4, ja4Raw
}
