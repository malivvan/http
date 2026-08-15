// Package wsjson provides helpers for reading and writing JSON messages.
package wsjson // import "github.com/malivvan/http/websocket/wsjson"

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/malivvan/http/websocket"
	"github.com/malivvan/http/websocket/bpool"
	"github.com/malivvan/http/websocket/errd"
	"github.com/malivvan/http/websocket/util"
)

// ReadJSON reads a JSON message from c into v.
// It will reuse buffers in between calls to avoid allocations.
func ReadJSON(ctx context.Context, c *websocket.Conn, v any) error {
	return readJSON(ctx, c, v)
}

func readJSON(ctx context.Context, c *websocket.Conn, v any) (err error) {
	defer errd.Wrap(&err, "failed to read JSON message")

	_, r, err := c.Reader(ctx)
	if err != nil {
		return err
	}

	b := bpool.Get()
	defer bpool.Put(b)

	_, err = b.ReadFrom(r)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b.Bytes(), v)
	if err != nil {
		c.Close(websocket.StatusInvalidFramePayloadData, "failed to unmarshal JSON")
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// WriteJSON writes the JSON message v to c.
// It will reuse buffers in between calls to avoid allocations.
func WriteJSON(ctx context.Context, c *websocket.Conn, v any) error {
	return write(ctx, c, v)
}

func write(ctx context.Context, c *websocket.Conn, v any) (err error) {
	defer errd.Wrap(&err, "failed to write JSON message")

	// json.Marshal cannot reuse buffers between calls as it has to return
	// a copy of the byte slice but Encoder does as it directly writes to w.
	err = json.NewEncoder(util.WriterFunc(func(p []byte) (int, error) {
		err := c.Write(ctx, websocket.MessageText, p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	})).Encode(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return nil
}
