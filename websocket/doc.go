//go:build !js

// Package websocket implements the RFC 6455 WebSocket protocol.
//
// https://tools.ietf.org/html/rfc6455
//
// Use Dial to dial a WebSocket server.
//
// Use Accept to accept a WebSocket client. Accept also supports
// fingerprinting incoming connections via the OnRequest callback in
// AcceptOptions.
//
// Use Serve to accept a WebSocket client on a raw net.Conn obtained
// outside of net/http, for example from a TCP or TLS listener.
//
// Dial can mimic the connection establishment of common browsers: use
// PrepareRequest in DialOptions to modify the handshake request before
// it is sent, or HeaderOrder to control the exact wire order of the
// request headers.
//
// Conn represents the resulting WebSocket connection.
//
// The examples are the best way to understand how to correctly use the library.
//
// The wsjson subpackage contain helpers for JSON and protobuf messages.
//
// More documentation at https://github.com/malivvan/http/websocket.
//
// # Wasm
//
// The client side supports compiling to Wasm.
// It wraps the WebSocket browser API.
//
// See https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
//
// Some important caveats to be aware of:
//
//   - Accept always errors out
//   - Serve is unavailable
//   - Conn.Ping is no-op
//   - Conn.CloseNow is Close(StatusGoingAway, "")
//   - HTTPClient, HTTPHeader, Host, CompressionMode, PrepareRequest and
//     HeaderOrder in DialOptions are no-op
//   - *http.Response from Dial is &http.Response{} with a 101 status code on success
package websocket // import "github.com/malivvan/http/websocket"
