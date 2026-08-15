//go:build !js

package websocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	tls "github.com/malivvan/tls"

	"github.com/malivvan/http"
	"github.com/malivvan/http/websocket/errd"
)

// DialOptions represents Dial's options.
type DialOptions struct {
	// HTTPClient is used for the connection.
	// Its Transport must return writable bodies for WebSocket handshakes.
	// http.Transport does beginning with Go 1.12.
	HTTPClient *http.Client

	// HTTPHeader specifies the HTTP headers included in the handshake request.
	HTTPHeader http.Header

	// Host optionally overrides the Host HTTP header to send. If empty, the value
	// of URL.Host will be used.
	Host string

	// Subprotocols lists the WebSocket subprotocols to negotiate with the server.
	Subprotocols []string

	// CompressionMode controls the compression mode.
	// Defaults to CompressionDisabled.
	//
	// See docs on CompressionMode for details.
	CompressionMode CompressionMode

	// CompressionThreshold controls the minimum size of a message before compression is applied.
	//
	// Defaults to 512 bytes for CompressionNoContextTakeover and 128 bytes
	// for CompressionContextTakeover.
	CompressionThreshold int

	// OnPingReceived is an optional callback invoked synchronously when a ping frame is received.
	//
	// The payload contains the application data of the ping frame.
	// If the callback returns false, the subsequent pong frame will not be sent.
	// To avoid blocking, any expensive processing should be performed asynchronously using a goroutine.
	OnPingReceived func(ctx context.Context, payload []byte) bool

	// OnPongReceived is an optional callback invoked synchronously when a pong frame is received.
	//
	// The payload contains the application data of the pong frame.
	// To avoid blocking, any expensive processing should be performed asynchronously using a goroutine.
	//
	// Unlike OnPingReceived, this callback does not return a value because a pong frame
	// is a response to a ping and does not trigger any further frame transmission.
	OnPongReceived func(ctx context.Context, payload []byte)

	// PrepareRequest is an optional callback invoked synchronously after
	// the handshake request is fully constructed but before it is sent.
	// It receives the request and may modify it, for example to add
	// cookies or set the User-Agent. Returning an error aborts the dial.
	//
	// The callback runs before the request is sent in both the
	// HTTPClient and HeaderOrder modes.
	PrepareRequest func(r *http.Request) error

	// HeaderOrder specifies the order in which HTTP headers appear in
	// the handshake request. When non-empty, Dial bypasses HTTPClient
	// and writes the request directly to a new connection so that the
	// header order matches the given sequence. Use it to mimic the
	// connection establishment of a specific browser.
	//
	// Headers not listed in HeaderOrder are appended after the listed
	// ones, each in alphabetical order. The Host header is always
	// written first. Header names listed in HeaderOrder are written with
	// their exact casing; other headers use canonical casing. Headers
	// are written without any defaults, so set User-Agent and friends
	// via HTTPHeader or PrepareRequest.
	//
	// When HeaderOrder is set, HTTPClient is ignored and redirects and
	// HTTP proxies are not supported.
	HeaderOrder []string

	// NetDialContext is an optional custom dial function used to obtain
	// the connection the handshake is written to. When set, Dial always
	// writes the handshake request directly to the connection returned
	// by this function (like HeaderOrder does) instead of going through
	// HTTPClient. This allows callers to inject connections with custom
	// TLS fingerprinting (e.g. a uTLS dialer), proxy support or
	// bandwidth tracking.
	//
	// The function receives the network ("tcp") and the address
	// (host:port) to dial. For "wss" URLs the caller is responsible for
	// performing the TLS handshake on the returned connection. When
	// NetDialContext is set, HTTPClient is ignored.
	NetDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NetDialTLSContext is like NetDialContext but is only invoked for
	// "wss"/"https" URLs. It receives the network ("tcp") and the
	// address (host:port) to dial and must return a connection that has
	// already completed its TLS handshake (e.g. one produced by a uTLS
	// dialer with a browser ClientHello fingerprint). When set, it
	// takes precedence over NetDialContext for secure URLs and
	// HTTPClient is ignored for those URLs.
	NetDialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// SecWebSocketExtensions overrides the value of the
	// Sec-WebSocket-Extensions header sent in the handshake request.
	// When empty, the value derived from CompressionMode is used
	// (e.g. "permessage-deflate"). Set it to advertise the exact
	// extension parameters of a specific browser, e.g.
	// "permessage-deflate; client_max_window_bits". The CompressionMode
	// still controls whether permessage-deflate is negotiated and used
	// for frames after the handshake.
	SecWebSocketExtensions string
}

func (opts *DialOptions) cloneWithDefaults(ctx context.Context) (context.Context, context.CancelFunc, *DialOptions) {
	var cancel context.CancelFunc

	var o DialOptions
	if opts != nil {
		o = *opts
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	if o.HTTPClient.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.HTTPClient.Timeout)

		newClient := *o.HTTPClient
		newClient.Timeout = 0
		o.HTTPClient = &newClient
	}
	if o.HTTPHeader == nil {
		o.HTTPHeader = http.Header{}
	}
	newClient := *o.HTTPClient
	oldCheckRedirect := o.HTTPClient.CheckRedirect
	newClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		switch req.URL.Scheme {
		case "ws":
			req.URL.Scheme = "http"
		case "wss":
			req.URL.Scheme = "https"
		}
		if oldCheckRedirect != nil {
			return oldCheckRedirect(req, via)
		}
		return nil
	}
	o.HTTPClient = &newClient

	return ctx, cancel, &o
}

// Dial performs a WebSocket handshake on url.
//
// The response is the WebSocket handshake response from the server.
// You never need to close resp.Body yourself.
//
// If an error occurs, the returned response may be non nil.
// However, you can only read the first 1024 bytes of the body.
//
// This function requires at least Go 1.12 as it uses a new feature
// in net/http to perform WebSocket handshakes.
// See docs on the HTTPClient option and https://github.com/golang/go/issues/26937#issuecomment-415855861
//
// URLs with http/https schemes will work and are interpreted as ws/wss.
func Dial(ctx context.Context, u string, opts *DialOptions) (*Conn, *http.Response, error) {
	return dial(ctx, u, opts, nil)
}

func dial(ctx context.Context, urls string, opts *DialOptions, rand io.Reader) (_ *Conn, _ *http.Response, err error) {
	defer errd.Wrap(&err, "failed to WebSocket dial")

	var cancel context.CancelFunc
	ctx, cancel, opts = opts.cloneWithDefaults(ctx)
	if cancel != nil {
		defer cancel()
	}

	secWebSocketKey, err := secWebSocketKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Sec-WebSocket-Key: %w", err)
	}

	var copts *compressionOptions
	if opts.CompressionMode != CompressionDisabled {
		copts = opts.CompressionMode.opts()
	}

	resp, err := handshakeRequest(ctx, urls, opts, copts, secWebSocketKey)
	if err != nil {
		return nil, resp, err
	}
	respBody := resp.Body
	resp.Body = nil
	defer func() {
		if err != nil {
			// We read a bit of the body for easier debugging.
			r := io.LimitReader(respBody, 1024)

			timer := time.AfterFunc(time.Second*3, func() {
				respBody.Close()
			})
			defer timer.Stop()

			b, _ := io.ReadAll(r)
			respBody.Close()
			resp.Body = io.NopCloser(bytes.NewReader(b))
		}
	}()

	copts, err = verifyServerResponse(opts, copts, secWebSocketKey, resp)
	if err != nil {
		return nil, resp, err
	}

	rwc, ok := respBody.(io.ReadWriteCloser)
	if !ok {
		return nil, resp, fmt.Errorf("response body is not a io.ReadWriteCloser: %T", respBody)
	}

	return newConn(connConfig{
		subprotocol:    resp.Header.Get("Sec-WebSocket-Protocol"),
		rwc:            rwc,
		client:         true,
		copts:          copts,
		flateThreshold: opts.CompressionThreshold,
		onPingReceived: opts.OnPingReceived,
		onPongReceived: opts.OnPongReceived,
		br:             getBufioReader(rwc),
		bw:             getBufioWriter(rwc),
	}), resp, nil
}

func handshakeRequest(ctx context.Context, urls string, opts *DialOptions, copts *compressionOptions, secWebSocketKey string) (*http.Response, error) {
	u, err := url.Parse(urls)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return nil, fmt.Errorf("unexpected url scheme: %q", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new http request: %w", err)
	}
	if len(opts.Host) > 0 {
		req.Host = opts.Host
	}
	req.Header = opts.HTTPHeader.Clone()
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", secWebSocketKey)
	if len(opts.Subprotocols) > 0 {
		req.Header.Set("Sec-WebSocket-Protocol", strings.Join(opts.Subprotocols, ","))
	}
	if copts != nil {
		req.Header.Set("Sec-WebSocket-Extensions", copts.String())
	}
	if opts.SecWebSocketExtensions != "" {
		// Browser-exact extension string, e.g. "permessage-deflate; client_max_window_bits".
		req.Header.Set("Sec-WebSocket-Extensions", opts.SecWebSocketExtensions)
	}

	if opts.PrepareRequest != nil {
		if err := opts.PrepareRequest(req); err != nil {
			return nil, fmt.Errorf("failed to prepare request: %w", err)
		}
	}

	if len(opts.HeaderOrder) > 0 || opts.NetDialContext != nil || opts.NetDialTLSContext != nil {
		// The handshake is written directly to a connection. This is used
		// for browser header ordering and/or when a custom dial function
		// (e.g. a TLS-fingerprinting dialer) is supplied.
		return handshakeRequestOrdered(ctx, u, req, opts.HeaderOrder, opts.NetDialContext, opts.NetDialTLSContext)
	}

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send handshake request: %w", err)
	}
	return resp, nil
}

// handshakeRequestOrdered performs the handshake request over a direct
// connection, writing the HTTP headers in the order given by headerOrder
// to mimic the connection establishment of a specific browser. When
// headerOrder is empty, the headers are written in alphabetical order
// after the Host header. netDial, if non-nil, is used to establish the
// connection instead of the default net/tls dialers. For secure URLs,
// netDialTLS takes precedence over netDial; it must return a connection
// with a completed TLS handshake.
func handshakeRequestOrdered(ctx context.Context, u *url.URL, req *http.Request, headerOrder []string, netDial func(ctx context.Context, network, addr string) (net.Conn, error), netDialTLS func(ctx context.Context, network, addr string) (net.Conn, error)) (*http.Response, error) {
	addr := u.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if u.Scheme == "https" {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}

	conn, err := dialHandshakeConn(ctx, u, addr, netDial, netDialTLS)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	bw := getBufioWriter(conn)
	host := req.Host
	if host == "" {
		host = u.Host
		if hs := req.Header.Get("Host"); hs != "" {
			host = hs
		}
	}
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	// The Host header is always written first, but its casing follows the
	// HeaderOrder entry (browsers differ: Chrome writes "host", Firefox
	// and Safari write "Host").
	hostHeaderName := "Host"
	for _, k := range headerOrder {
		if textproto.CanonicalMIMEHeaderKey(k) == "Host" {
			hostHeaderName = k
			break
		}
	}
	fmt.Fprintf(bw, "%s: %s\r\n", hostHeaderName, host)
	// Headers listed in HeaderOrder are written first, with their exact
	// casing as browsers would. Remaining headers follow alphabetically
	// with canonical casing.
	written := make(map[string]bool, len(req.Header))
	for _, k := range headerOrder {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if ck == "Host" || written[ck] {
			continue
		}
		vs, ok := req.Header[ck]
		if !ok {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(bw, "%s: %s\r\n", k, v)
		}
		written[ck] = true
	}
	rest := make([]string, 0, len(req.Header)-len(written))
	for k := range req.Header {
		if k == "Host" || written[k] {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		for _, v := range req.Header[k] {
			fmt.Fprintf(bw, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(bw, "\r\n")
	if err := bw.Flush(); err != nil {
		putBufioWriter(bw)
		conn.Close()
		return nil, fmt.Errorf("failed to write handshake request: %w", err)
	}
	putBufioWriter(bw)

	br := getBufioReader(conn)
	resp, err := http.ReadResponse(br, req)
	b, _ := br.Peek(br.Buffered())
	putBufioReader(br)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	// Clear the deadline set for the handshake; the connection now
	// belongs to the returned response body.
	conn.SetDeadline(time.Time{})

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Expose the raw connection as the response body. Any bytes the
		// server sent immediately after the response head are preserved.
		resp.Body = &upgradeConn{
			r: io.MultiReader(bytes.NewReader(b), conn),
			w: conn,
			c: conn,
		}
	}

	return resp, nil
}

// dialHandshakeConn dials a plain or TLS connection for the handshake.
// When netDialTLS is non-nil and the URL is secure it is used instead of
// the default dialers and must return a connection with a completed TLS
// handshake. When netDial is non-nil it is used for all other cases; the
// caller is responsible for performing the TLS handshake for "https" URLs.
func dialHandshakeConn(ctx context.Context, u *url.URL, addr string, netDial func(ctx context.Context, network, addr string) (net.Conn, error), netDialTLS func(ctx context.Context, network, addr string) (net.Conn, error)) (net.Conn, error) {
	if u.Scheme == "https" && netDialTLS != nil {
		conn, err := netDialTLS(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial WebSocket server: %w", err)
		}
		return conn, nil
	}

	if netDial != nil {
		conn, err := netDial(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial WebSocket server: %w", err)
		}
		return conn, nil
	}

	if u.Scheme == "https" {
		d := tls.Dialer{
			NetDialer: new(net.Dialer),
			Config: &tls.Config{
				ServerName: u.Hostname(),
			},
		}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial WebSocket server: %w", err)
		}
		return conn, nil
	}

	conn, err := new(net.Dialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial WebSocket server: %w", err)
	}
	return conn, nil
}

// upgradeConn adapts a raw connection to io.ReadWriteCloser. Reads come
// from r so that bytes buffered during the handshake are not lost.
type upgradeConn struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (u *upgradeConn) Read(p []byte) (int, error) {
	return u.r.Read(p)
}

func (u *upgradeConn) Write(p []byte) (int, error) {
	return u.w.Write(p)
}

func (u *upgradeConn) Close() error {
	return u.c.Close()
}

func secWebSocketKey(rr io.Reader) (string, error) {
	if rr == nil {
		rr = rand.Reader
	}
	b := make([]byte, 16)
	_, err := io.ReadFull(rr, b)
	if err != nil {
		return "", fmt.Errorf("failed to read random data from rand.Reader: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func verifyServerResponse(opts *DialOptions, copts *compressionOptions, secWebSocketKey string, resp *http.Response) (*compressionOptions, error) {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("expected handshake response status code %v but got %v", http.StatusSwitchingProtocols, resp.StatusCode)
	}

	if !headerContainsTokenIgnoreCase(resp.Header, "Connection", "Upgrade") {
		return nil, fmt.Errorf("WebSocket protocol violation: Connection header %q does not contain Upgrade", resp.Header.Get("Connection"))
	}

	if !headerContainsTokenIgnoreCase(resp.Header, "Upgrade", "WebSocket") {
		return nil, fmt.Errorf("WebSocket protocol violation: Upgrade header %q does not contain websocket", resp.Header.Get("Upgrade"))
	}

	if resp.Header.Get("Sec-WebSocket-Accept") != secWebSocketAccept(secWebSocketKey) {
		return nil, fmt.Errorf("WebSocket protocol violation: invalid Sec-WebSocket-Accept %q, key %q",
			resp.Header.Get("Sec-WebSocket-Accept"),
			secWebSocketKey,
		)
	}

	err := verifySubprotocol(opts.Subprotocols, resp)
	if err != nil {
		return nil, err
	}

	return verifyServerExtensions(copts, resp.Header)
}

func verifySubprotocol(subprotos []string, resp *http.Response) error {
	proto := resp.Header.Get("Sec-WebSocket-Protocol")
	if proto == "" {
		return nil
	}

	for _, sp2 := range subprotos {
		if strings.EqualFold(sp2, proto) {
			return nil
		}
	}

	return fmt.Errorf("WebSocket protocol violation: unexpected Sec-WebSocket-Protocol from server: %q", proto)
}

func verifyServerExtensions(copts *compressionOptions, h http.Header) (*compressionOptions, error) {
	exts := websocketExtensions(h)
	if len(exts) == 0 {
		return nil, nil
	}

	ext := exts[0]
	if ext.name != "permessage-deflate" || len(exts) > 1 || copts == nil {
		return nil, fmt.Errorf("WebSocket protocol violation: unsupported extensions from server: %+v", exts[1:])
	}

	_copts := *copts
	copts = &_copts

	for _, p := range ext.params {
		switch p {
		case "client_no_context_takeover":
			copts.clientNoContextTakeover = true
			continue
		case "server_no_context_takeover":
			copts.serverNoContextTakeover = true
			continue
		}
		if strings.HasPrefix(p, "server_max_window_bits=") {
			// We can't adjust the deflate window, but decoding with a larger window is acceptable.
			continue
		}
		if p == "client_max_window_bits" || strings.HasPrefix(p, "client_max_window_bits=") {
			// RFC 7692: the server may constrain the client's window bits.
			continue
		}

		return nil, fmt.Errorf("unsupported permessage-deflate parameter: %q", p)
	}

	return copts, nil
}

var bufioReaderPool sync.Pool

func getBufioReader(r io.Reader) *bufio.Reader {
	br, ok := bufioReaderPool.Get().(*bufio.Reader)
	if !ok {
		return bufio.NewReader(r)
	}
	br.Reset(r)
	return br
}

func putBufioReader(br *bufio.Reader) {
	bufioReaderPool.Put(br)
}

var bufioWriterPool sync.Pool

func getBufioWriter(w io.Writer) *bufio.Writer {
	bw, ok := bufioWriterPool.Get().(*bufio.Writer)
	if !ok {
		return bufio.NewWriter(w)
	}
	bw.Reset(w)
	return bw
}

func putBufioWriter(bw *bufio.Writer) {
	bufioWriterPool.Put(bw)
}
