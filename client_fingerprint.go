package http

import (
	"fmt"
	"strings"

	"github.com/malivvan/tls"
)

// This file provides ready-made HTTP clients that mimic the connection
// establishment and HTTP/2 behavior of real browsers, in order to avoid TLS
// (JA3/JA4) and HTTP/2 fingerprinting by remote servers.
//
// A browser-mimicking client combines three layers of impersonation:
//
//  1. TLS: the ClientHello of the browser (cipher suites, extensions, curves,
//     ALPN, ...), via tls.ClientHelloID and the uTLS fork
//     (github.com/malivvan/tls). This defeats JA3/JA4 fingerprinting.
//  2. HTTP/2: the initial SETTINGS frame (values and wire order), the
//     connection-level WINDOW_UPDATE, the PRIORITY frames sent at connection
//     start and the priority attached to request HEADERS frames.
//  3. HTTP: the pseudo-header and regular header order of requests. Use the
//     HeaderOrderKey and PHeaderOrderKey request header keys to control it
//     per request; the Transport.PseudoHeaderOrder field sets the default
//     pseudo-header order.
//
// The per-request header order is still up to the caller: browsers send a
// fixed, per-request header order (Host, Connection, sec-ch-ua, ...) that
// depends on the request type. Set it with HeaderOrderKey on each request
// (see the README) to complete the impersonation.

// browserProfile describes the HTTP/2 behavior of a browser family. The
// values are the observed SETTINGS frames, flow control windows, PRIORITY
// frames and header priorities of the respective browser, as documented by
// the tls-client ecosystem and captured from real browsers.
type browserProfile struct {
	settings          []Setting
	connectionFlow    uint32
	priorities        []Priority
	headerPriority    *PriorityParam
	pseudoHeaderOrder []string
}

var (
	// chromeProfile mimics Google Chrome (Chromium). The SETTINGS frame
	// and connection flow control window match Chrome's observed values
	// and wire order. Modern Chrome (120+) sends neither PRIORITY frames
	// nor a priority on request HEADERS.
	chromeProfile = browserProfile{
		settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingInitialWindowSize, Val: 6291456},
			{ID: SettingMaxHeaderListSize, Val: 262144},
		},
		connectionFlow:    15663105,
		pseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}

	// firefoxProfile mimics Mozilla Firefox. Firefox sends a fixed set of
	// PRIORITY frames at connection start, attaches a fixed priority to
	// its request HEADERS and does not send SETTINGS_ENABLE_PUSH.
	firefoxProfile = browserProfile{
		settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingInitialWindowSize, Val: 131072},
			{ID: SettingMaxFrameSize, Val: 16384},
		},
		connectionFlow: 12517377,
		priorities: []Priority{
			{StreamID: 3, PriorityParam: PriorityParam{StreamDep: 0, Exclusive: false, Weight: 200}},
			{StreamID: 5, PriorityParam: PriorityParam{StreamDep: 0, Exclusive: false, Weight: 100}},
			{StreamID: 7, PriorityParam: PriorityParam{StreamDep: 0, Exclusive: false, Weight: 0}},
			{StreamID: 9, PriorityParam: PriorityParam{StreamDep: 7, Exclusive: false, Weight: 0}},
			{StreamID: 11, PriorityParam: PriorityParam{StreamDep: 3, Exclusive: false, Weight: 0}},
			{StreamID: 13, PriorityParam: PriorityParam{StreamDep: 0, Exclusive: false, Weight: 240}},
		},
		headerPriority:    &PriorityParam{StreamDep: 13, Exclusive: false, Weight: 41},
		pseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
	}

	// safariProfile mimics Apple Safari / iOS WebKit. The SETTINGS frame
	// and connection flow control window match Safari's observed values
	// and wire order.
	safariProfile = browserProfile{
		settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingMaxConcurrentStreams, Val: 100},
			{ID: SettingInitialWindowSize, Val: 2097152},
			{ID: SettingMaxFrameSize, Val: 16384},
		},
		connectionFlow:    10485760,
		pseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
	}
)

// version maps are the ClientHelloID variants exported by
// github.com/malivvan/tls for each browser family. Version keys accept
// "auto" (or "") for the latest known version, and a browser version
// number with dots normalized to underscores, e.g. "16.0" for iOS/Safari.
var chromeVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloChrome_Auto, "58": tls.HelloChrome_58, "62": tls.HelloChrome_62,
	"70": tls.HelloChrome_70, "72": tls.HelloChrome_72, "83": tls.HelloChrome_83,
	"87": tls.HelloChrome_87, "96": tls.HelloChrome_96, "100": tls.HelloChrome_100,
	"102": tls.HelloChrome_102, "103": tls.HelloChrome_103, "104": tls.HelloChrome_104,
	"105": tls.HelloChrome_105, "106": tls.HelloChrome_106, "107": tls.HelloChrome_107,
	"108": tls.HelloChrome_108, "109": tls.HelloChrome_109, "110": tls.HelloChrome_110,
	"111": tls.HelloChrome_111, "112": tls.HelloChrome_112, "120": tls.HelloChrome_120,
	"131": tls.HelloChrome_131, "133": tls.HelloChrome_133,
}

var firefoxVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloFirefox_Auto, "55": tls.HelloFirefox_55, "56": tls.HelloFirefox_56,
	"63": tls.HelloFirefox_63, "65": tls.HelloFirefox_65, "99": tls.HelloFirefox_99,
	"102": tls.HelloFirefox_102, "104": tls.HelloFirefox_104, "105": tls.HelloFirefox_105,
	"106": tls.HelloFirefox_106, "108": tls.HelloFirefox_108, "110": tls.HelloFirefox_110,
	"120": tls.HelloFirefox_120,
}

var safariVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloSafari_Auto, "15_6_1": tls.HelloSafari_15_6_1, "16_0": tls.HelloSafari_16_0,
}

var iosVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloIOS_Auto, "11_1": tls.HelloIOS_11_1, "12_1": tls.HelloIOS_12_1,
	"13": tls.HelloIOS_13, "14": tls.HelloIOS_14, "15_5": tls.HelloIOS_15_5,
	"15_6": tls.HelloIOS_15_6, "16_0": tls.HelloIOS_16_0,
}

var edgeVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloEdge_Auto, "85": tls.HelloEdge_85, "106": tls.HelloEdge_106,
}

var operaVersions = map[string]tls.ClientHelloID{
	"auto": tls.HelloOpera_Auto, "89": tls.HelloOpera_89, "90": tls.HelloOpera_90,
	"91": tls.HelloOpera_91,
}

// normalizeVersion normalizes a version string for lookup in the version
// maps: empty or "auto" becomes "auto", and "." is replaced by "_".
func normalizeVersion(version string) string {
	version = strings.ReplaceAll(version, ".", "_")
	if version == "" {
		return "auto"
	}
	return version
}

// resolveClientHelloID looks up a ClientHelloID for the given browser family
// and version.
func resolveClientHelloID(family, version string, versions map[string]tls.ClientHelloID) (tls.ClientHelloID, error) {
	id, ok := versions[normalizeVersion(version)]
	if !ok {
		return tls.ClientHelloID{}, fmt.Errorf("http: unsupported %s version %q: no ClientHello profile available; use \"auto\" or one of the versions exported by github.com/malivvan/tls (Hello%s_*)", family, version, family)
	}
	return id, nil
}

// newBrowserClient builds a *Client whose Transport impersonates the given
// browser profile.
func newBrowserClient(helloID tls.ClientHelloID, profile *browserProfile) *Client {
	tr := &Transport{
		ClientHelloID:       helloID,
		ForceAttemptHTTP2:   true,
		Proxy:               ProxyFromEnvironment,
		HTTP2Settings:       profile.settings,
		HTTP2ConnectionFlow: profile.connectionFlow,
		HTTP2Priorities:     profile.priorities,
		HTTP2HeaderPriority: profile.headerPriority,
		PseudoHeaderOrder:   profile.pseudoHeaderOrder,
	}
	return &Client{Transport: tr}
}

// NewClient returns a *Client whose Transport impersonates the given TLS
// ClientHello during the TLS handshake. helloID is any of the pre-defined
// tls.Hello* IDs, or a custom tls.ClientHelloID built with
// tls.ClientHelloIDToSpec.
//
// The returned client negotiates HTTP/2 when the server supports it, like a
// browser. The HTTP/2 connection behavior (SETTINGS, PRIORITY frames) stays
// at the net/http defaults; use NewChromeClient and friends for full browser
// impersonation, or configure the returned client's Transport fields
// (HTTP2Settings, HTTP2Priorities, HTTP2HeaderPriority, PseudoHeaderOrder)
// yourself.
func NewClient(helloID tls.ClientHelloID) *Client {
	tr := &Transport{
		ClientHelloID:     helloID,
		ForceAttemptHTTP2: true,
		Proxy:             ProxyFromEnvironment,
	}
	return &Client{Transport: tr}
}

// NewChromeClient returns a *Client that mimics Google Chrome: the TLS
// ClientHello, the HTTP/2 SETTINGS frame, the connection PRIORITY frames and
// the request header priority are all set to Chrome's observed behavior.
//
// version is a Chrome major version supported by github.com/malivvan/tls
// ("auto" or "" for the latest known version; e.g. "133", "120", "105").
// It returns an error if no ClientHello profile exists for the version.
func NewChromeClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("Chrome", version, chromeVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &chromeProfile), nil
}

// NewFirefoxClient returns a *Client that mimics Mozilla Firefox. See
// NewChromeClient for the version argument.
func NewFirefoxClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("Firefox", version, firefoxVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &firefoxProfile), nil
}

// NewSafariClient returns a *Client that mimics Apple Safari. See
// NewChromeClient for the version argument (e.g. "16.0", "15.6.1").
func NewSafariClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("Safari", version, safariVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &safariProfile), nil
}

// NewIOSClient returns a *Client that mimics Apple iOS (WebKit). See
// NewChromeClient for the version argument (e.g. "16.0", "15.6", "14").
func NewIOSClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("IOS", version, iosVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &safariProfile), nil
}

// NewEdgeClient returns a *Client that mimics Microsoft Edge. Edge is
// Chromium-based, so the HTTP/2 behavior matches the Chrome profile. See
// NewChromeClient for the version argument.
func NewEdgeClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("Edge", version, edgeVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &chromeProfile), nil
}

// NewOperaClient returns a *Client that mimics the Opera browser. Opera is
// Chromium-based, so the HTTP/2 behavior matches the Chrome profile. See
// NewChromeClient for the version argument.
func NewOperaClient(version string) (*Client, error) {
	id, err := resolveClientHelloID("Opera", version, operaVersions)
	if err != nil {
		return nil, err
	}
	return newBrowserClient(id, &chromeProfile), nil
}
