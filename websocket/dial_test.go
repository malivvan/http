//go:build !js

package websocket_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/malivvan/http"
	"github.com/malivvan/http/httptest"
	"github.com/malivvan/http/websocket"
	"github.com/malivvan/http/websocket/util"
	"github.com/malivvan/http/websocket/xsync"
	"github.com/stretchr/testify/assert"
)

func TestBadDials(t *testing.T) {
	t.Parallel()

	t.Run("badReq", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name   string
			url    string
			opts   *websocket.DialOptions
			rand   util.ReaderFunc
			nilCtx bool
		}{
			{
				name: "badURL",
				url:  "://noscheme",
			},
			{
				name: "badURLScheme",
				url:  "ftp://nhooyr.io",
			},
			{
				name: "badTLS",
				url:  "wss://totallyfake.nhooyr.io",
			},
			{
				name: "badReader",
				rand: func(p []byte) (int, error) {
					return 0, io.EOF
				},
			},
			{
				name:   "nilContext",
				url:    "http://localhost",
				nilCtx: true,
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				var ctx context.Context
				var cancel func()
				if !tc.nilCtx {
					ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
					defer cancel()
				}

				if tc.rand == nil {
					tc.rand = rand.Reader.Read
				}

				_, _, err := websocket.ExportedDial(ctx, tc.url, tc.opts, tc.rand)
				assert.Error(t, err)
			})
		}
	})

	t.Run("badResponse", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		_, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
			HTTPClient: mockHTTPClient(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					Body: io.NopCloser(strings.NewReader("hi")),
				}, nil
			}),
		})
		assert.ErrorContains(t, err, "failed to WebSocket dial: expected handshake response status code 101 but got 0")
	})

	t.Run("badBody", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		rt := func(r *http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("Connection", "Upgrade")
			h.Set("Upgrade", "websocket")
			h.Set("Sec-WebSocket-Accept", websocket.SecWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))

			return &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Header:     h,
				Body:       io.NopCloser(strings.NewReader("hi")),
			}, nil
		}

		_, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
			HTTPClient: mockHTTPClient(rt),
		})
		assert.ErrorContains(t, err, "response body is not a io.ReadWriteCloser")
	})
}

func Test_verifyHostOverride(t *testing.T) {
	testCases := []struct {
		name string
		host string
		exp  string
	}{
		{
			name: "noOverride",
			host: "",
			exp:  "example.com",
		},
		{
			name: "hostOverride",
			host: "example.net",
			exp:  "example.net",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			rt := func(r *http.Request) (*http.Response, error) {
				assert.Equal(t, tc.exp, r.Host, "Host")

				h := http.Header{}
				h.Set("Connection", "Upgrade")
				h.Set("Upgrade", "websocket")
				h.Set("Sec-WebSocket-Accept", websocket.SecWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))

				return &http.Response{
					StatusCode: http.StatusSwitchingProtocols,
					Header:     h,
					Body:       mockBody{bytes.NewBufferString("hi")},
				}, nil
			}

			c, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
				HTTPClient: mockHTTPClient(rt),
				Host:       tc.host,
			})
			assert.NoError(t, err)
			c.CloseNow()
		})
	}
}

type mockBody struct {
	*bytes.Buffer
}

func (mb mockBody) Close() error {
	return nil
}

func Test_verifyServerHandshake(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		response func(w http.ResponseWriter)
		success  bool
	}{
		{
			name: "badStatus",
			response: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
			},
			success: false,
		},
		{
			name: "badConnection",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "???")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "badUpgrade",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "???")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "badSecWebSocketAccept",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.Header().Set("Sec-WebSocket-Accept", "xd")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "badSecWebSocketProtocol",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.Header().Set("Sec-WebSocket-Protocol", "xd")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "unsupportedExtension",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.Header().Set("Sec-WebSocket-Extensions", "meow")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "unsupportedDeflateParam",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.Header().Set("Sec-WebSocket-Extensions", "permessage-deflate; meow")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: false,
		},
		{
			name: "success",
			response: func(w http.ResponseWriter) {
				w.Header().Set("Connection", "Upgrade")
				w.Header().Set("Upgrade", "websocket")
				w.WriteHeader(http.StatusSwitchingProtocols)
			},
			success: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			tc.response(w)
			resp := w.Result()

			r := httptest.NewRequest("GET", "/", nil)
			key, err := websocket.SecWebSocketKey(rand.Reader)
			assert.NoError(t, err)
			r.Header.Set("Sec-WebSocket-Key", key)

			if resp.Header.Get("Sec-WebSocket-Accept") == "" {
				resp.Header.Set("Sec-WebSocket-Accept", websocket.SecWebSocketAccept(key))
			}

			opts := &websocket.DialOptions{
				Subprotocols: strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ","),
			}
			_, err = websocket.VerifyServerResponse(opts, websocket.CompressionModeOpts(opts.CompressionMode), key, resp)
			if tc.success {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func mockHTTPClient(fn roundTripperFunc) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestDialRedirect(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
		HTTPClient: mockHTTPClient(func(r *http.Request) (*http.Response, error) {
			resp := &http.Response{
				Header: http.Header{},
			}
			if r.URL.Scheme != "https" {
				resp.Header.Set("Location", "wss://example.com")
				resp.StatusCode = http.StatusFound
				return resp, nil
			}
			resp.Header.Set("Connection", "Upgrade")
			resp.Header.Set("Upgrade", "meow")
			resp.StatusCode = http.StatusSwitchingProtocols
			return resp, nil
		}),
	})
	assert.ErrorContains(t, err, "failed to WebSocket dial: WebSocket protocol violation: Upgrade header \"meow\" does not contain websocket")
}

type forwardProxy struct {
	hc *http.Client
}

func newForwardProxy() *forwardProxy {
	return &forwardProxy{
		hc: &http.Client{},
	}
}

func (fc *forwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	r = r.WithContext(ctx)
	r.RequestURI = ""
	resp, err := fc.hc.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)
	w.Header().Set("PROXIED", "true")
	w.WriteHeader(resp.StatusCode)

	if resprw, ok := resp.Body.(io.ReadWriter); ok {
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		brw.Flush()

		errc1 := xsync.Go(func() error {
			_, err := io.Copy(c, resprw)
			return err
		})
		errc2 := xsync.Go(func() error {
			_, err := io.Copy(resprw, c)
			return err
		})
		select {
		case <-errc1:
		case <-errc2:
		case <-r.Context().Done():
		}
	} else {
		io.Copy(w, resp.Body)
	}
}

func TestDialViaProxy(t *testing.T) {
	t.Parallel()

	ps := httptest.NewServer(newForwardProxy())
	defer ps.Close()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := echoServer(w, r, nil)
		assert.NoError(t, err)
	}))
	defer s.Close()

	psu, err := url.Parse(ps.URL)
	assert.NoError(t, err)
	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxyTransport.Proxy = http.ProxyURL(psu)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, s.URL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: proxyTransport,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "true", resp.Header.Get("PROXIED"), "")

	assertEcho(t, ctx, c)
	assertClose(t, c)
}

func TestPrepareRequest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	rt := func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "test-cookie", r.Header.Get("Cookie"), "cookie")

		h := http.Header{}
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", "websocket")
		h.Set("Sec-WebSocket-Accept", websocket.SecWebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))

		return &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Header:     h,
			Body:       mockBody{bytes.NewBufferString("hi")},
		}, nil
	}

	c, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
		HTTPClient: mockHTTPClient(rt),
		PrepareRequest: func(r *http.Request) error {
			r.Header.Set("Cookie", "test-cookie")
			return nil
		},
	})
	assert.NoError(t, err)
	c.CloseNow()
}

func TestPrepareRequestError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, _, err := websocket.Dial(ctx, "ws://example.com", &websocket.DialOptions{
		PrepareRequest: func(r *http.Request) error {
			return errors.New("prepare failed")
		},
	})
	assert.ErrorContains(t, err, "failed to prepare request: prepare failed")
}

func TestHeaderOrder(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	var recorded bytes.Buffer
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		c, err := websocket.Serve(&recordingConn{Conn: conn, b: &recorded}, &websocket.AcceptOptions{
			OriginPatterns: []string{"example.com"},
		})
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
		if typ != websocket.MessageText || string(p) != "hello" {
			serverErr <- fmt.Errorf("unexpected message: %v %q", typ, p)
			return
		}
		serverErr <- c.Write(ctx, websocket.MessageText, []byte("world"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	order := []string{
		"Connection",
		"Pragma",
		"Cache-Control",
		"Upgrade",
		"Origin",
		"User-Agent",
		"Sec-WebSocket-Version",
		"Sec-WebSocket-Key",
	}
	c, _, err := websocket.Dial(ctx, "ws://"+ln.Addr().String(), &websocket.DialOptions{
		HTTPHeader: http.Header{
			"User-Agent":    {"mimic-agent"},
			"Pragma":        {"no-cache"},
			"Cache-Control": {"no-cache"},
			"Origin":        {"https://example.com"},
		},
		HeaderOrder: order,
	})
	assert.NoError(t, err)
	defer c.CloseNow()

	assert.NoError(t, c.Write(ctx, websocket.MessageText, []byte("hello")))

	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer readCancel()
	typ, p, err := c.Read(readCtx)
	assert.NoError(t, err)
	assert.Equal(t, websocket.MessageText, typ, "message type")
	assert.Equal(t, "world", string(p), "message")

	assert.NoError(t, <-serverErr)

	// The Host header is always written first, followed by the headers
	// in HeaderOrder and then any remaining headers alphabetically.
	expKeys := append([]string{"Host"}, order...)
	gotKeys := headerKeysFromRaw(recorded.String())
	assert.Equal(t, expKeys, gotKeys, "header order")
}

func TestHeaderOrderWithTLS(t *testing.T) {
	t.Parallel()

	// wss:// with HeaderOrder dials with TLS and verifies the server
	// certificate like a browser would. Against a plain TCP listener the
	// TLS handshake must fail cleanly instead of sending the request.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, _, err = websocket.Dial(ctx, "wss://"+ln.Addr().String(), &websocket.DialOptions{
		HeaderOrder: []string{"Connection", "Upgrade"},
	})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "failed to dial WebSocket server")
}
