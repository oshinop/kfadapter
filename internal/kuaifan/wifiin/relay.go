package wifiin

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

const relayBufferSize = 32 * 1024

type closeWriter interface {
	CloseWrite() error
}

// Relay copies both directions with fixed-size buffers. An EOF in one
// direction causes only a half-close of the peer's write side, allowing the
// reverse direction to drain. Cancellation or a real copy error closes both
// sides to unblock the peer copy.
func Relay(ctx context.Context, left, right net.Conn) error {
	results := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	cancelled := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-cancelled:
		}
	}()

	pump := func(dst, src net.Conn) {
		buf := make([]byte, relayBufferSize)
		_, err := io.CopyBuffer(dst, src, buf)
		if err == nil {
			if cw, ok := dst.(closeWriter); ok {
				err = cw.CloseWrite()
			} else {
				// A generic net.Conn cannot represent a half-close. Closing is
				// safer than leaving a permanently blocked peer goroutine.
				err = dst.Close()
			}
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			closeBoth()
		}
		results <- err
	}
	go pump(right, left)
	go pump(left, right)

	first := <-results
	second := <-results
	close(cancelled)
	if first != nil && !errors.Is(first, net.ErrClosed) {
		return first
	}
	if second != nil && !errors.Is(second, net.ErrClosed) {
		return second
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
