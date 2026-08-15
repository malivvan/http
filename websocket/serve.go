//go:build !js

package websocket

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"path"

	tls "github.com/malivvan/tls"

	"github.com/malivvan/http"
	"github.com/malivvan/http/websocket/errd"
)

// Serve performs a WebSocket handshake on a raw net.Conn. It reads the
// client's HTTP upgrade request from conn, validates it and writes the
// 101 response, upgrading conn to a WebSocket.
//
// Serve is useful when the connection was obtained outside of net/http,
// for example from a raw TCP listener, a TLS listener or a connection
// pool. The AcceptOptions behave as in Accept, including origin
// verification and the OnRequest callback.
//
// On error, Serve writes an HTTP error response to conn and closes it.
func Serve(conn net.Conn, opts *AcceptOptions) (*Conn, error) {
	return serve(conn, opts)
}

func serve(conn net.Conn, opts *AcceptOptions) (_ *Conn, err error) {
	defer errd.Wrap(&err, "failed to serve WebSocket connection")
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	// Server connections do not return bufio objects to the pool on
	// close (see msgReader.close and msgWriter.close), so do not use
	// the pooled variants here. accept uses the hijacker's ReadWriter.
	br := bufio.NewReader(conn)
	r, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP request: %w", err)
	}

	// ReadRequest does not set these; the server does.
	r.RemoteAddr = conn.RemoteAddr().String()
	if tc, ok := conn.(*tls.Conn); ok {
		cs := tc.ConnectionState()
		r.TLS = &cs
	}

	opts = opts.cloneWithDefaults()

	rec := &errorHeaderRecorder{h: http.Header{}}
	errCode, err := verifyClientRequest(rec, r)
	if err != nil {
		writeServeError(conn, errCode, err, rec.Header())
		return nil, err
	}

	if !opts.InsecureSkipVerify {
		err = authenticateOrigin(r, opts.OriginPatterns)
		if err != nil {
			if errors.Is(err, path.ErrBadPattern) {
				log.Printf("websocket: %v", err)
				err = errors.New(http.StatusText(http.StatusForbidden))
			}
			writeServeError(conn, http.StatusForbidden, err, nil)
			return nil, err
		}
	}

	if opts.OnRequest != nil {
		if err := opts.OnRequest(r); err != nil {
			writeServeError(conn, http.StatusForbidden, err, nil)
			return nil, err
		}
	}

	subproto := selectSubprotocol(r, opts.Subprotocols)

	copts, ok := selectDeflate(websocketExtensions(r.Header), opts.CompressionMode)

	bw := bufio.NewWriter(conn)
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", http.StatusSwitchingProtocols, http.StatusText(http.StatusSwitchingProtocols))
	fmt.Fprintf(bw, "Upgrade: websocket\r\n")
	fmt.Fprintf(bw, "Connection: Upgrade\r\n")
	fmt.Fprintf(bw, "Sec-WebSocket-Accept: %s\r\n", secWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
	if subproto != "" {
		fmt.Fprintf(bw, "Sec-WebSocket-Protocol: %s\r\n", subproto)
	}
	if ok {
		fmt.Fprintf(bw, "Sec-WebSocket-Extensions: %s\r\n", copts.String())
	}
	fmt.Fprintf(bw, "\r\n")
	if err := bw.Flush(); err != nil {
		return nil, fmt.Errorf("failed to write handshake response: %w", err)
	}

	return newConn(connConfig{
		subprotocol:    subproto,
		rwc:            conn,
		client:         false,
		copts:          copts,
		flateThreshold: opts.CompressionThreshold,
		onPingReceived: opts.OnPingReceived,
		onPongReceived: opts.OnPongReceived,

		br: br,
		bw: bw,
	}), nil
}

// errorHeaderRecorder captures the headers verifyClientRequest sets on
// failure so they can be written into Serve's error response.
type errorHeaderRecorder struct {
	h http.Header
}

func (r *errorHeaderRecorder) Header() http.Header {
	return r.h
}

func (r *errorHeaderRecorder) WriteHeader(int) {}

func (r *errorHeaderRecorder) Write(p []byte) (int, error) {
	return len(p), nil
}

func writeServeError(conn net.Conn, code int, err error, h http.Header) {
	body := err.Error() + "\n"

	bw := bufio.NewWriter(conn)
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(bw, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(bw, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(bw, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(bw, "Connection: close\r\n")
	fmt.Fprintf(bw, "\r\n")
	bw.WriteString(body)
	bw.Flush()
}
