# http-go

# Vendor
- `.` github.com/bogdanfinn/fhttp v0.6.8
- `./websocket` github.com/malivvan/http/websocket v1.8.15

> `./websocket` was adapted to improve fingerprinting and spoofing

## Features

### Browser impersonation (client)

The package provides ready-made HTTP clients that mimic the connection
establishment and handling of real browsers, in order to avoid TLS
(JA3/JA4) and HTTP/2 fingerprinting by remote servers. Three layers are
impersonated:

1. **TLS**: the browser's ClientHello (cipher suites, extensions, curves,
   ALPN, ...) via `Transport.ClientHelloID` and `github.com/malivvan/tls`
   (a uTLS fork).
2. **HTTP/2**: the initial SETTINGS frame (values and wire order), the
   connection-level WINDOW_UPDATE, the PRIORITY frames sent at connection
   start and the priority attached to request HEADERS frames.
3. **HTTP**: the pseudo-header and regular header order of requests.

```go
import http "github.com/malivvan/http"

// A Chrome 120-mimicking client (TLS ClientHello + HTTP/2 behavior).
chrome, err := http.NewChromeClient("120")

// Firefox, Safari, iOS, Edge and Opera equivalents.
firefox, err := http.NewFirefoxClient("auto") // latest known profile
safari, err := http.NewSafariClient("16.0")

// Generic client with any ClientHelloID from github.com/malivvan/tls.
client := http.NewClient(tls.HelloChrome_Auto)

// Manual equivalent: configure a Transport yourself.
tr := &http.Transport{
    ClientHelloID:        tls.HelloChrome_133,
    ForceAttemptHTTP2:    true,
    HTTP2Settings:        []http.Setting{
        {ID: http.SettingHeaderTableSize, Val: 65536},
        {ID: http.SettingEnablePush, Val: 0},
        {ID: http.SettingInitialWindowSize, Val: 6291456},
        {ID: http.SettingMaxHeaderListSize, Val: 262144},
    },
    HTTP2ConnectionFlow:  15663105, // Chrome's connection flow control window
    HTTP2HeaderPriority:  &http.PriorityParam{StreamDep: 13, Weight: 41}, // Firefox-style
    HTTP2Priorities:      []http.Priority{ /* ... */ },
    PseudoHeaderOrder:    []string{":method", ":authority", ":scheme", ":path"},
}
```

`Transport.ForceHTTP1` disables HTTP/2 negotiation (browser-style ALPN
`http/1.1` only), and `Transport.WithRandomTLSExtensionOrder` shuffles the
ClientHello extensions per connection.

The per-request header order is still up to the caller: browsers send a
fixed, per-request header order (`Host`, `Connection`, `sec-ch-ua`, ...)
that depends on the request type. Set it with `HeaderOrderKey` on each
request (see below) to complete the impersonation.

### Ordered Headers

The package allows for both pseudo header order and normal header order. Most of the code is taken from [this Pull Request](https://go-review.googlesource.com/c/go/+/105755/).

**Note on HTTP/1.1 header order**
Although the header key is capitalized, the header order slice must be in lowercase.

```go
	req.Header = http.Header{
		"X-NewRelic-ID":         {"12345"},
		"x-api-key":             {"ABCDE12345"},
		"MESH-Commerce-Channel": {"android-app-phone"},
		"mesh-version":          {"cart=4"},
		"X-Request-Auth":        {"hawkHeader"},
		"X-acf-sensor-data":     {"3456"},
		"Content-Type":          {"application/json; charset=UTF-8"},
		"Accept":                {"application/json"},
		"Transfer-Encoding":     {"chunked"},
		"Host":                  {"example.com"},
		"Connection":            {"Keep-Alive"},
		"Accept-Encoding":       {"gzip"},
		HeaderOrderKey: {
			"x-newrelic-id",
			"x-api-key",
			"mesh-commerce-channel",
			"mesh-version",
			"user-agent",
			"x-request-auth",
			"x-acf-sensor-data",
			"transfer-encoding",
			"content-type",
			"accept",
			"host",
			"connection",
			"accept-encoding",
		},
		PHeaderOrderKey: {
			":method",
			":path",
			":authority",
			":scheme",
		},
	}
```

### Connection settings

fhhtp has Chrome-like connection settings, as shown below:

```text
SETTINGS_HEADER_TABLE_SIZE = 65536 (2^16)
SETTINGS_ENABLE_PUSH = 1
SETTINGS_MAX_CONCURRENT_STREAMS = 1000
SETTINGS_INITIAL_WINDOW_SIZE = 6291456
SETTINGS_MAX_FRAME_SIZE = 16384 (2^14)
SETTINGS_MAX_HEADER_LIST_SIZE = 262144 (2^18)
```

The default net/http settings, on the other hand, are the following:

```text
SETTINGS_HEADER_TABLE_SIZE = 4096
SETTINGS_ENABLE_PUSH = 0
SETTINGS_MAX_CONCURRENT_STREAMS = unlimited
SETTINGS_INITIAL_WINDOW_SIZE = 4194304
SETTINGS_MAX_FRAME_SIZE = 16384
SETTINGS_MAX_HEADER_LIST_SIZE = 10485760
```

The ENABLE_PUSH implementation was merged from [this Pull Request](https://go-review.googlesource.com/c/net/+/181497/).

### gzip, deflate, and br encoding

`gzip`, `deflate`, and `br` encoding are all supported by the package.

### Pseudo header order

fhttp supports pseudo header order for http2, helping mitigate fingerprinting. You can read more about how it works [here](https://www.akamai.com/uk/en/multimedia/documents/white-paper/passive-fingerprinting-of-http2-clients-white-paper.pdf).

### Fingerprinting incoming connections (server)

The server captures, for every incoming connection, everything that
identifies the client — no configuration required:

- **TLS**: the raw ClientHello of the handshake, with JA3/JA4 fingerprints
  and parsed fields (cipher suites, extensions, curves, signature
  algorithms, ALPN, SNI, ...).
- **HTTP/2**: the client's initial SETTINGS frame (values and wire order),
  connection-level WINDOW_UPDATE increments and PRIORITY frames.
- **HTTP**: the order in which the client sent the request headers (and,
  for HTTP/2, the pseudo-header order).

```go
func handler(w http.ResponseWriter, r *http.Request) {
    fp := r.Fingerprint // *http.Fingerprint; nil for plaintext connections
    if fp == nil {
        return
    }
    if tls := fp.TLS; tls != nil {
        log.Printf("ja3=%s ja4=%s sni=%q ciphers=%d exts=%d",
            tls.JA3Hash, tls.JA4, tls.ServerName,
            len(tls.CipherSuites), len(tls.Extensions))
    }
    if h2 := fp.HTTP2; h2 != nil {
        log.Printf("h2 settings=%v window=%v priorities=%v",
            h2.Settings, h2.WindowUpdates, h2.Priorities)
    }
    log.Printf("header order: %v", r.HeaderOrder)
    log.Printf("h2 pseudo-header order: %v", r.PseudoHeaderOrder)
}
```

Fingerprints can also be computed from raw bytes captured elsewhere (e.g.
with tcpdump) via `ParseClientHello`, `ComputeJA3` and `ComputeJA4`, which
accept a ClientHello handshake message (with or without its 4-byte header).

### Backward compatible with net/http

Although this library is an extension of `net/http`, it is also meant to be backward compatible. Replacing

```go
import (
   "net/http"
)
```

with

```go
import (
    "github.com/malivvan/http"
)
```

SHOULD not break anything.

## Credits

Special thanks to the following people for helping me with this project.

- [cc](https://github.com/x04/) for guiding me when I first started this project and inspiring me with [cclient](https://github.com/x04/cclient)

- [umasi](https://github.com/umasii) for being good rubber ducky and giving me tips for http2 headers
