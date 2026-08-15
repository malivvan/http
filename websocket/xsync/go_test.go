package xsync

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoRecover(t *testing.T) {
	t.Parallel()

	errs := Go(func() error {
		panic("anmol")
	})

	err := <-errs
	assert.ErrorContains(t, err, "anmol")
}
