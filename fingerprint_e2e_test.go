package http_test

import (
	"crypto/x509"
	"reflect"
	"sync"
	"testing"

	"github.com/malivvan/tls"

	"github.com/malivvan/http"
	"github.com/malivvan/http/httptest"
)

// captureServer is a test helper that records the fingerprint of the requests
// it serves.
type captureServer struct {
	ts *httptest.Server

	mu   sync.Mutex
	reqs []*http.Request
}

// Expected browser HTTP/2 fingerprints (values observed from real browsers,
// mirrored by the http.NewChromeClient/NewFirefoxClient profiles).
var (
	chromeSettings = []http.Setting{
		{ID: http.SettingHeaderTableSize, Val: 65536},
		{ID: http.SettingEnablePush, Val: 0},
		{ID: http.SettingInitialWindowSize, Val: 6291456},
		{ID: http.SettingMaxHeaderListSize, Val: 262144},
	}
	firefoxSettings = []http.Setting{
		{ID: http.SettingHeaderTableSize, Val: 65536},
		{ID: http.SettingInitialWindowSize, Val: 131072},
		{ID: http.SettingMaxFrameSize, Val: 16384},
	}
	firefoxPriorities = []http.Priority{
		{StreamID: 3, PriorityParam: http.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 200}},
		{StreamID: 5, PriorityParam: http.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 100}},
		{StreamID: 7, PriorityParam: http.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 0}},
		{StreamID: 9, PriorityParam: http.PriorityParam{StreamDep: 7, Exclusive: false, Weight: 0}},
		{StreamID: 11, PriorityParam: http.PriorityParam{StreamDep: 3, Exclusive: false, Weight: 0}},
		{StreamID: 13, PriorityParam: http.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 240}},
	}
)

func newCaptureServer(t *testing.T, enableHTTP2 bool) *captureServer {
	t.Helper()
	cs := &captureServer{}
	cs.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.reqs = append(cs.reqs, r)
		cs.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	cs.ts.EnableHTTP2 = enableHTTP2
	cs.ts.StartTLS()
	t.Cleanup(cs.ts.Close)
	return cs
}

// transportForServer builds a Transport that trusts the httptest certificate
// and impersonates the given ClientHello.
func transportForServer(cs *captureServer, id tls.ClientHelloID, forceHTTP1 bool) *http.Transport {
	pool := x509.NewCertPool()
	pool.AddCert(cs.ts.Certificate())
	return &http.Transport{
		ClientHelloID:      id,
		ForceHTTP1:         forceHTTP1,
		ForceAttemptHTTP2:  !forceHTTP1,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{RootCAs: pool},
	}
}

func (cs *captureServer) lastRequest() *http.Request {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.reqs) == 0 {
		return nil
	}
	return cs.reqs[len(cs.reqs)-1]
}

// TestFingerprintHTTP2EndToEnd verifies that a http.NewChromeClient connection is
// fingerprinted by the server: TLS ClientHello (JA3/JA4), HTTP/2 SETTINGS
// (values and order), connection WINDOW_UPDATE and the per-request
// pseudo-header and header order.
func TestFingerprintHTTP2EndToEnd(t *testing.T) {
	cs := newCaptureServer(t, true)
	client, err := http.NewChromeClient("120")
	if err != nil {
		t.Fatal(err)
	}
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: testPool(cs)}
	client.Transport.(*http.Transport).DisableCompression = true

	req, err := http.NewRequest(http.MethodGet, cs.ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = http.Header{
		"User-Agent":        {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		"Accept":            {"text/html,application/xhtml+xml"},
		"Accept-Language":   {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {"user-agent", "accept", "accept-language"},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	r := cs.lastRequest()
	if r == nil {
		t.Fatal("server received no request")
	}
	if r.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 request, got %s", r.Proto)
	}

	// TLS fingerprint.
	fp := r.Fingerprint
	if fp == nil || fp.TLS == nil {
		t.Fatal("missing TLS fingerprint")
	}
	// The server is reached via an IP address, so no SNI is sent.
	if fp.TLS.ServerName != "" {
		t.Errorf("TLS ServerName = %q, want \"\" (no SNI for IP addresses)", fp.TLS.ServerName)
	}
	if len(fp.TLS.CipherSuites) < 10 {
		t.Errorf("suspiciously few cipher suites: %d", len(fp.TLS.CipherSuites))
	}
	if len(fp.TLS.JA4) == 0 || len(fp.TLS.JA3Hash) == 0 {
		t.Error("JA3/JA4 not computed")
	}
	// Recomputing the fingerprint from the raw bytes must agree.
	if fp2 := http.ParseClientHello(fp.TLS.Raw); fp2.JA3Hash != fp.TLS.JA3Hash || fp2.JA4 != fp.TLS.JA4 {
		t.Error("ParseClientHello disagrees with captured fingerprint")
	}

	// HTTP/2 fingerprint: the client must have sent exactly the Chrome
	// settings in the Chrome wire order.
	h2fp := fp.HTTP2
	if h2fp == nil {
		t.Fatal("missing HTTP/2 fingerprint")
	}
	if !reflect.DeepEqual(h2fp.Settings, chromeSettings) {
		t.Errorf("HTTP2 settings = %v, want %v", h2fp.Settings, chromeSettings)
	}
	// Chrome's connection flow control window.
	if len(h2fp.WindowUpdates) == 0 || h2fp.WindowUpdates[0] != 15663105 {
		t.Errorf("WindowUpdates = %v, want first increment 15663105", h2fp.WindowUpdates)
	}
	// Modern Chrome sends no PRIORITY frames.
	if len(h2fp.Priorities) != 0 {
		t.Errorf("Priorities = %v, want none for Chrome", h2fp.Priorities)
	}

	// Per-request header order.
	if !reflect.DeepEqual(r.PseudoHeaderOrder, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Errorf("PseudoHeaderOrder = %v", r.PseudoHeaderOrder)
	}
	if !reflect.DeepEqual(r.HeaderOrder, []string{"user-agent", "accept", "accept-language"}) {
		t.Errorf("HeaderOrder = %v", r.HeaderOrder)
	}
}

// TestFingerprintFirefoxHTTP2 verifies the Firefox profile: PRIORITY frames
// and the request HEADERS priority are sent and captured.
func TestFingerprintFirefoxHTTP2(t *testing.T) {
	cs := newCaptureServer(t, true)
	client, err := http.NewFirefoxClient("120")
	if err != nil {
		t.Fatal(err)
	}
	tr := client.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: testPool(cs)}
	tr.DisableCompression = true

	resp, err := client.Get(cs.ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	r := cs.lastRequest()
	if r == nil {
		t.Fatal("server received no request")
	}
	if r.Fingerprint == nil || r.Fingerprint.HTTP2 == nil {
		t.Fatal("missing HTTP/2 fingerprint")
	}
	h2fp := r.Fingerprint.HTTP2
	if !reflect.DeepEqual(h2fp.Settings, firefoxSettings) {
		t.Errorf("HTTP2 settings = %v, want %v", h2fp.Settings, firefoxSettings)
	}
	if len(h2fp.WindowUpdates) == 0 || h2fp.WindowUpdates[0] != 12517377 {
		t.Errorf("WindowUpdates = %v, want first increment 12517377", h2fp.WindowUpdates)
	}
	if !reflect.DeepEqual(h2fp.Priorities, firefoxPriorities) {
		t.Errorf("Priorities = %v, want %v", h2fp.Priorities, firefoxPriorities)
	}
	if !reflect.DeepEqual(r.PseudoHeaderOrder, []string{":method", ":path", ":authority", ":scheme"}) {
		t.Errorf("PseudoHeaderOrder = %v", r.PseudoHeaderOrder)
	}
}

// TestFingerprintHTTP1 verifies fingerprinting over HTTP/1.1 with a
// ForceHTTP1 transport: the TLS ClientHello is captured and its JA4
// fingerprint must match the real Chrome 120 value, and the header order
// must reflect the wire order (Host first, then the ordered headers).
func TestFingerprintHTTP1(t *testing.T) {
	cs := newCaptureServer(t, false) // HTTP/1.1 only
	tr := transportForServer(cs, tls.HelloChrome_120, true)
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, cs.ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = http.Header{
		"User-Agent":        {"Mozilla/5.0"},
		"Accept":            {"text/html"},
		http.HeaderOrderKey: {"user-agent", "accept"},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	r := cs.lastRequest()
	if r == nil {
		t.Fatal("server received no request")
	}
	if r.ProtoMajor != 1 {
		t.Fatalf("expected HTTP/1.1 request, got %s", r.Proto)
	}
	if r.Fingerprint == nil || r.Fingerprint.TLS == nil {
		t.Fatal("missing TLS fingerprint")
	}
	// The impersonated ClientHello must produce the real Chrome 120 JA4.
	// (ServerName is an IP here, so no SNI is sent: "i", and the SNI
	// extension is dropped from the count. ForceHTTP1 switches the ALPN
	// to http/1.1 only: "h1".)
	if got := r.Fingerprint.TLS.JA4; got != "t13i1515h1_8daaf6152771_02713d6af862" {
		t.Errorf("JA4 = %q, want the real Chrome 120 fingerprint", got)
	}
	if r.Fingerprint.HTTP2 != nil {
		t.Error("HTTP2 fingerprint present on HTTP/1.1 request")
	}
	// Host is written through the header map (ordered writes), so it
	// follows the entries listed in HeaderOrderKey.
	wantOrder := []string{"user-agent", "accept", "host"}
	if !reflect.DeepEqual(r.HeaderOrder, wantOrder) {
		t.Errorf("HeaderOrder = %v, want %v", r.HeaderOrder, wantOrder)
	}
}

// TestFingerprintPlaintext verifies that plaintext connections carry a
// Fingerprint without a TLS part, and that header order is still captured.
func TestFingerprintPlaintext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Fingerprint != nil && r.Fingerprint.TLS != nil {
			t.Error("plaintext request has TLS fingerprint")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// TestNewBrowserClients exercises the browser constructors.
func TestNewBrowserClients(t *testing.T) {
	mk := []struct {
		name string
		fn   func(string) (*http.Client, error)
	}{
		{"Chrome", func(v string) (*http.Client, error) { return http.NewChromeClient(v) }},
		{"Firefox", func(v string) (*http.Client, error) { return http.NewFirefoxClient(v) }},
		{"Safari", func(v string) (*http.Client, error) { return http.NewSafariClient(v) }},
		{"IOS", func(v string) (*http.Client, error) { return http.NewIOSClient(v) }},
		{"Edge", func(v string) (*http.Client, error) { return http.NewEdgeClient(v) }},
		{"Opera", func(v string) (*http.Client, error) { return http.NewOperaClient(v) }},
	}
	for _, m := range mk {
		c, err := m.fn("auto")
		if err != nil {
			t.Errorf("%s(auto): %v", m.name, err)
			continue
		}
		if c == nil || c.Transport == nil {
			t.Errorf("%s(auto): nil client", m.name)
		}
		if c.Transport.(*http.Transport).ClientHelloID.Client == "" {
			t.Errorf("%s(auto): ClientHelloID not set", m.name)
		}
		if c.Transport.(*http.Transport).ForceAttemptHTTP2 != true {
			t.Errorf("%s(auto): ForceAttemptHTTP2 not set", m.name)
		}
	}
	// Unknown versions must error.
	for _, m := range mk {
		if _, err := m.fn("9999"); err == nil {
			t.Errorf("%s(9999): expected error", m.name)
		}
	}
	// NewClient with a zero ClientHelloID must still work (plain TLS).
	if c := http.NewClient(tls.ClientHelloID{}); c == nil {
		t.Error("http.NewClient(zero ID) returned nil")
	}
}

func testPool(cs *captureServer) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cs.ts.Certificate())
	return pool
}

// TestClientHelloIDHTTP2 confirms the whole impersonation stack works over
// HTTP/2: UConn in addTLS, TLSNextProto dispatch with a UConn, Chrome-like
// settings and the h2 upgrade path.
func TestClientHelloIDHTTP2(t *testing.T) {
	cs := newCaptureServer(t, true)
	tr := transportForServer(cs, tls.HelloChrome_120, false)
	client := &http.Client{Transport: tr}
	resp, err := client.Get(cs.ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	r := cs.lastRequest()
	if r == nil {
		t.Fatal("server received no request")
	}
	if r.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 request, got %s", r.Proto)
	}
	if r.TLS == nil || !r.TLS.NegotiatedProtocolIsMutual {
		t.Fatalf("unexpected TLS state: %+v", r.TLS)
	}
}

// TestForceHTTP1 confirms ForceHTTP1 disables HTTP/2 entirely.
func TestForceHTTP1(t *testing.T) {
	cs := newCaptureServer(t, true) // server supports h2, client must refuse it
	tr := transportForServer(cs, tls.HelloChrome_105, true)
	client := &http.Client{Transport: tr}
	resp, err := client.Get(cs.ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	r := cs.lastRequest()
	if r == nil {
		t.Fatal("server received no request")
	}
	if r.ProtoMajor != 1 {
		t.Fatalf("expected HTTP/1.1 request despite h2 server, got %s", r.Proto)
	}
}

// TestFingerprintClone verifies that cloned fingerprints are independent.
func TestFingerprintClone(t *testing.T) {
	f := &http.Fingerprint{
		TLS: &http.TLSFingerprint{JA3Hash: "abc"},
		HTTP2: &http.HTTP2Fingerprint{
			Settings:      []http.Setting{{ID: http.SettingEnablePush, Val: 1}},
			WindowUpdates: []uint32{1},
			Priorities:    []http.Priority{{StreamID: 3}},
		},
	}
	c := f.Clone()
	if c == f || c.HTTP2 == f.HTTP2 {
		t.Fatal("Clone must deep-copy the HTTP2 part")
	}
	c.HTTP2.Settings[0].Val = 99
	if f.HTTP2.Settings[0].Val != 1 {
		t.Error("Clone shares settings storage")
	}
	if c.TLS != f.TLS {
		t.Error("Clone should share the TLS part")
	}
}
