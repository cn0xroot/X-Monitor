package fswatch

import (
	"context"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }

// ctxDone returns a context cancelled when ch is closed.
func ctxDone(ch <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-ch; cancel() }()
	return ctx
}
