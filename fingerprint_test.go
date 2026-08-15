package http

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/malivvan/tls"
)

// buildClientHello generates the raw ClientHello of a uTLS profile without a
// network connection.
func buildClientHello(t *testing.T, id tls.ClientHelloID) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uconn := tls.UClient(c1, &tls.Config{ServerName: "example.com"}, id, false, false, false)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		t.Fatalf("MarshalClientHello: %v", err)
	}
	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		t.Fatal("empty ClientHello raw bytes")
	}
	return raw
}

// TestComputeJA3AndJA4KnownBrowsers verifies the fingerprint computation
// against the JA4 fingerprints of real browsers published in the JA4
// database (https://tls.peet.ws and FoxIO's JA4 collection). JA4 hashes
// sorted, order-independent inputs, so the uTLS profiles reproduce them
// exactly even where the raw cipher order of a specific capture differs.
func TestComputeJA3AndJA4KnownBrowsers(t *testing.T) {
	cases := []struct {
		id       tls.ClientHelloID
		ja4      string
		ja4First string // expected prefix of the raw variant (header)
	}{
		{tls.HelloChrome_120, "t13d1516h2_8daaf6152771_02713d6af862", "t13d1516h2_"},
		{tls.HelloFirefox_120, "t13d1715h2_5b57614c22b0_5c2c66f702b0", "t13d1715h2_"},
	}
	for _, tc := range cases {
		raw := buildClientHello(t, tc.id)
		ja3, ja3Hash := ComputeJA3(raw)
		ja4, ja4Raw := ComputeJA4(raw)
		if ja3 == "" || ja3Hash == "" {
			t.Errorf("%v: empty JA3 output", tc.id.Str())
		}
		// JA3 must be GREASE-free and deterministic.
		if strings.Contains(ja3, "0a0a") {
			t.Errorf("%v: JA3 contains GREASE: %s", tc.id.Str(), ja3)
		}
		ja32, hash2 := ComputeJA3(raw)
		if ja32 != ja3 || hash2 != ja3Hash {
			t.Errorf("%v: JA3 not deterministic", tc.id.Str())
		}
		if ja4 != tc.ja4 {
			t.Errorf("%v: JA4 = %q, want %q", tc.id.Str(), ja4, tc.ja4)
		}
		if !strings.HasPrefix(ja4Raw, tc.ja4First) {
			t.Errorf("%v: JA4 raw = %q, want prefix %q", tc.id.Str(), ja4Raw, tc.ja4First)
		}
		// The JA3 of different browsers must differ.
	}
	rawChrome := buildClientHello(t, tls.HelloChrome_120)
	rawFirefox := buildClientHello(t, tls.HelloFirefox_120)
	chromeJA3, _ := ComputeJA3(rawChrome)
	firefoxJA3, _ := ComputeJA3(rawFirefox)
	if chromeJA3 == firefoxJA3 {
		t.Error("Chrome and Firefox JA3 must differ")
	}
}

// TestComputeJA4SpecExample verifies the JA4 computation against the example
// of the official JA4 specification (https://github.com/FoxIO-LLC/ja4):
// JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1.
func TestComputeJA4SpecExample(t *testing.T) {
	hello := buildSyntheticClientHello(t, []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}, []uint16{
		0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
		0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
	}, []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
	})
	ja4, ja4Raw := ComputeJA4(hello)
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if ja4 != want {
		t.Errorf("ComputeJA4 = %q, want %q", ja4, want)
	}
	wantRaw := "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
	if ja4Raw != wantRaw {
		t.Errorf("ComputeJA4 raw = %q, want %q", ja4Raw, wantRaw)
	}
}

// buildSyntheticClientHello builds a ClientHello with the given cipher
// suites, extensions and signature algorithms. The supported_versions
// extension advertises TLS 1.3, the ALPN extension "h2", the SNI extension
// "example.com", supported_groups {0x001d} and ec_point_formats {0}.
func buildSyntheticClientHello(t *testing.T, ciphers, extensions, sigalgs []uint16) []byte {
	t.Helper()
	var body bytes.Buffer
	// legacy protocol version: TLS 1.2 (the supported_versions extension
	// determines the JA4 "13").
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32)) // random
	body.Write([]byte{0x00})     // no session ID
	body.Write([]byte{byte(len(ciphers) * 2 >> 8), byte(len(ciphers) * 2)})
	for _, c := range ciphers {
		body.Write([]byte{byte(c >> 8), byte(c)})
	}
	body.Write([]byte{0x01, 0x00}) // compression: none
	// extensions
	exts := make([][]byte, 0, len(extensions))
	writeExt := func(id uint16, data []byte) {
		ext := []byte{byte(id >> 8), byte(id), byte(len(data) >> 8), byte(len(data))}
		exts = append(exts, append(ext, data...))
	}
	writeSNI := func() {
		name := []byte("example.com")
		data := []byte{0x00, 0x0d, 0x00, byte(len(name))}
		writeExt(0x0000, append(data, name...))
	}
	writeALPN := func() {
		// ProtocolNameList: 2-byte length (3: [02 68 32]) + 1-byte len + "h2".
		writeExt(0x0010, []byte{0x00, 0x03, 0x02, 'h', '2'})
	}
	for _, id := range extensions {
		switch id {
		case 0x0000:
			writeSNI()
		case 0x0010:
			writeALPN()
		case 0x000d:
			// signature_algorithms: 2-byte length + 2-byte entries.
			data := []byte{byte(len(sigalgs) * 2 >> 8), byte(len(sigalgs) * 2)}
			for _, s := range sigalgs {
				data = append(data, byte(s>>8), byte(s))
			}
			writeExt(id, data)
		case 0x002b:
			writeExt(id, []byte{0x02, 0x03, 0x04}) // supported_versions: TLS 1.3
		case 0x000a:
			writeExt(id, []byte{0x00, 0x02, 0x00, 0x1d}) // supported_groups: x25519
		case 0x000b:
			writeExt(id, []byte{0x01, 0x00}) // ec_point_formats: uncompressed
		default:
			writeExt(id, nil)
		}
	}
	extBlock := make([]byte, 0, 2)
	for _, e := range exts {
		extBlock = append(extBlock, e...)
	}
	body.Write([]byte{byte(len(extBlock) >> 8), byte(len(extBlock))})
	body.Write(extBlock)

	// Wrap in the 4-byte handshake header to test header stripping.
	msg := body.Bytes()
	hello := []byte{0x01, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	hello = append(hello, msg...)
	return hello
}

func TestComputeJA4Format(t *testing.T) {
	for _, id := range []tls.ClientHelloID{tls.HelloChrome_120, tls.HelloFirefox_120, tls.HelloSafari_16_0} {
		raw := buildClientHello(t, id)
		ja4, ja4Raw := ComputeJA4(raw)
		// "t" + version(2) + sni(1) + ciphers(2) + exts(2) + alpn(2) + "_" + 12 + "_" + 12
		if len(ja4) != 36 {
			t.Errorf("%v: unexpected JA4 length %d: %q", id.Str(), len(ja4), ja4)
		}
		if ja4[0] != 't' {
			t.Errorf("%v: JA4 must start with 't' for TLS over TCP: %q", id.Str(), ja4)
		}
		if len(ja4Raw) <= len(ja4) {
			t.Errorf("%v: JA4 raw variant should be longer than the hashed variant", id.Str())
		}
	}
}

func TestParseClientHello(t *testing.T) {
	raw := buildClientHello(t, tls.HelloChrome_120)
	fp := ParseClientHello(raw)
	if fp == nil {
		t.Fatal("ParseClientHello returned nil")
	}
	if fp.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", fp.ServerName, "example.com")
	}
	if len(fp.CipherSuites) == 0 {
		t.Error("no cipher suites parsed")
	}
	if len(fp.Extensions) == 0 {
		t.Error("no extensions parsed")
	}
	if len(fp.SupportedVersions) == 0 {
		t.Error("no supported versions parsed")
	} else {
		found13 := false
		for _, v := range fp.SupportedVersions {
			if v == tls.VersionTLS13 {
				found13 = true
			}
		}
		if !found13 {
			t.Errorf("SupportedVersions = %v, want it to include TLS 1.3", fp.SupportedVersions)
		}
	}
	if len(fp.ALPN) == 0 || fp.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", fp.ALPN)
	}
	if fp.JA3Hash == "" || fp.JA4 == "" {
		t.Error("JA3Hash/JA4 not computed")
	}
	// ParseClientHello must accept the body without the handshake header too.
	if fp2 := ParseClientHello(raw[4:]); fp2 == nil || fp2.JA3Hash != fp.JA3Hash {
		t.Error("ParseClientHello failed on header-less body")
	}
	// And must reject garbage.
	if fp := ParseClientHello([]byte{0x01, 0x02}); fp != nil {
		t.Error("ParseClientHello accepted garbage")
	}
}
