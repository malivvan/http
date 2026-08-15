//go:build !js && go1.20

package websocket

import (
	"bufio"
	"errors"
	"net"
	"testing"

	"github.com/malivvan/http"
	"github.com/malivvan/http/httptest"
	"github.com/stretchr/testify/assert"
)

func Test_hijackerHTTPResponseControllerCompatibility(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	w := mockUnwrapper{
		ResponseWriter: rr,
		unwrap: func() http.ResponseWriter {
			return mockHijacker{
				ResponseWriter: rr,
				hijack: func() (conn net.Conn, writer *bufio.ReadWriter, err error) {
					return nil, nil, errors.New("haha")
				},
			}
		},
	}

	_, _, err := http.NewResponseController(w).Hijack()
	assert.ErrorContains(t, err, "haha")
	hj, ok := hijacker(w)
	assert.Equal(t, ok, true, "hijacker found")
	_, _, err = hj.Hijack()
	assert.ErrorContains(t, err, "haha")
}
