package websocket_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/malivvan/http"
	"github.com/malivvan/http/websocket"
	"github.com/malivvan/http/websocket/wstest"
	"github.com/stretchr/testify/assert"
)

func TestWasm(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c, resp, err := websocket.Dial(ctx, os.Getenv("WS_ECHO_SERVER_URL"), &websocket.DialOptions{
		Subprotocols: []string{"echo"},
	})
	assert.NoError(t, err)
	defer c.Close(websocket.StatusInternalError, "")

	assert.Equal(t, "echo", c.Subprotocol(), "subprotocol")
	assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "response code")

	c.SetReadLimit(65536)
	for range 10 {
		err = wstest.Echo(ctx, c, 65536)
		assert.NoError(t, err)
	}

	err = c.Close(websocket.StatusNormalClosure, "")
	assert.NoError(t, err)
}

func TestWasmDialTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	beforeDial := time.Now()
	_, _, err := websocket.Dial(ctx, "ws://example.com:9893", &websocket.DialOptions{
		Subprotocols: []string{"echo"},
	})
	assert.Error(t, err)
	if time.Since(beforeDial) >= time.Second {
		t.Fatal("wasm context dial timeout is not working", time.Since(beforeDial))
	}
}
