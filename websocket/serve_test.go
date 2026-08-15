//go:build !js

package websocket_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/malivvan/http"
	"github.com/malivvan/http/websocket"
	"github.com/stretchr/testify/assert"
)

func TestServe(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		c, err := websocket.Serve(server, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer c.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		typ, p, err := c.Read(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		if typ != websocket.MessageText || string(p) != "hi" {
			serverErr <- fmt.Errorf("unexpected message: %v %q", typ, p)
			return
		}
		serverErr <- c.Write(ctx, websocket.MessageText, []byte("yo"))
	}()

	// Mimic a browser handshake by hand.
	key, err := websocket.SecWebSocketKey(rand.Reader)
	assert.NoError(t, err)

	br := bufio.NewReader(client)
	fmt.Fprintf(client, "GET / HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Connection: keep-alive, Upgrade\r\n")
	fmt.Fprintf(client, "Pragma: no-cache\r\n")
	fmt.Fprintf(client, "Upgrade: websocket\r\n")
	fmt.Fprintf(client, "Origin: https://example.com\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(client, "\r\n")

	resp, err := http.ReadResponse(br, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "status")
	assert.Equal(t, websocket.SecWebSocketAccept(key), resp.Header.Get("Sec-WebSocket-Accept"), "accept key")

	// Send a masked text frame as a browser would.
	assert.NoError(t, writeClientTextFrame(client, []byte("hi")))

	// Read the unmasked text frame written by the server.
	op, p, err := readServerFrame(br)
	assert.NoError(t, err)
	assert.Equal(t, byte(1), op, "opcode")
	assert.Equal(t, "yo", string(p), "payload")

	assert.NoError(t, <-serverErr)
}

func TestServeError(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := websocket.Serve(server, nil)
		serverErr <- err
	}()

	// Not a WebSocket handshake.
	fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode, "status")

	err = <-serverErr
	assert.ErrorContains(t, err, "protocol violation")
}

func TestServeRejectOrigin(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := websocket.Serve(server, nil)
		serverErr <- err
	}()

	key, err := websocket.SecWebSocketKey(rand.Reader)
	assert.NoError(t, err)

	fmt.Fprintf(client, "GET / HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Connection: Upgrade\r\n")
	fmt.Fprintf(client, "Upgrade: websocket\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(client, "Origin: https://harhar.com\r\n")
	fmt.Fprintf(client, "\r\n")

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "status")

	err = <-serverErr
	assert.ErrorContains(t, err, "not authorized")
}

func TestServeOnRequest(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	var gotRemote string
	serverErr := make(chan error, 1)
	go func() {
		_, err := websocket.Serve(server, &websocket.AcceptOptions{
			OnRequest: func(r *http.Request) error {
				gotRemote = r.RemoteAddr
				return errors.New("rejected")
			},
		})
		serverErr <- err
	}()

	key, err := websocket.SecWebSocketKey(rand.Reader)
	assert.NoError(t, err)

	fmt.Fprintf(client, "GET / HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Connection: Upgrade\r\n")
	fmt.Fprintf(client, "Upgrade: websocket\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(client, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(client, "\r\n")

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "status")

	err = <-serverErr
	assert.ErrorContains(t, err, "rejected")
	assert.Equal(t, client.LocalAddr().String(), gotRemote, "remote addr")
}

// recordingConn records every read into b, preserving the raw request
// bytes for wire-order verification.
type recordingConn struct {
	net.Conn
	b *bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.b.Write(p[:n])
	return n, err
}

// writeClientTextFrame writes a masked text frame as a browser would.
func writeClientTextFrame(w io.Writer, p []byte) error {
	var h [6]byte
	h[0] = 0x81 // FIN | text
	h[1] = 0x80 | byte(len(p))
	mask := [4]byte{0x01, 0x02, 0x03, 0x04}
	copy(h[2:], mask[:])
	if _, err := w.Write(h[:]); err != nil {
		return err
	}

	masked := make([]byte, len(p))
	for i, b := range p {
		masked[i] = b ^ mask[i%4]
	}
	_, err := w.Write(masked)
	return err
}

// readServerFrame reads an unmasked frame written by the server and
// returns its opcode and payload.
func readServerFrame(br *bufio.Reader) (byte, []byte, error) {
	b0, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	b1, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	n := int(b1 & 0x7f)
	switch {
	case n == 126:
		var b [2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(b[:]))
	case n == 127:
		var b [8]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint64(b[:]))
	}

	p := make([]byte, n)
	if _, err := io.ReadFull(br, p); err != nil {
		return 0, nil, err
	}
	return b0 & 0x0f, p, nil
}

// headerKeysFromRaw returns the header keys of a raw HTTP request in
// wire order. The first line is the request line and is skipped.
func headerKeysFromRaw(raw string) []string {
	var keys []string
	for _, l := range strings.Split(strings.TrimRight(raw, "\r\n"), "\r\n")[1:] {
		k, _, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}
