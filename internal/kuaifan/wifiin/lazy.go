package wifiin

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ReadDeadlineConn is the narrow connection capability needed while waiting
// for the delayed WIFIIN server IV.
type ReadDeadlineConn interface {
	SetReadDeadline(time.Time) error
}

// LazyInboundReader decrypts the server-to-client WIFIIN stream. The provider
// may defer its IV until it observes client application ciphertext. Reads may
// therefore block before the first write without a deadline; ArmForOutbound
// applies the bounded IV deadline immediately before that first write.
type LazyInboundReader struct {
	source  *HandshakeReader
	key     [KeySize]byte
	conn    ReadDeadlineConn
	timeout time.Duration

	initMu  sync.Mutex
	mu      sync.Mutex
	reader  io.Reader
	init    bool
	initErr error

	outboundStarted bool
	ivReady         bool
	deadlineArmed   bool
}

// NewLazyInboundReader creates the inbound stream reader. timeout applies only
// after ArmForOutbound is called, not merely because Relay starts its inbound
// copy goroutine.
func NewLazyInboundReader(source *HandshakeReader, key []byte, conn ReadDeadlineConn, timeout time.Duration) (*LazyInboundReader, error) {
	if source == nil {
		return nil, errors.New("wifiin: handshake reader is required")
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	if conn == nil {
		return nil, errors.New("wifiin: read deadline connection is required")
	}
	if timeout <= 0 {
		return nil, errors.New("wifiin: server IV timeout must be positive")
	}
	lazy := &LazyInboundReader{source: source, conn: conn, timeout: timeout}
	copy(lazy.key[:], key)
	return lazy, nil
}

// ArmForOutbound records the first application write and applies a bounded
// read deadline while the peer supplies its delayed IV. It is safe to call for
// every Write; only the first non-empty outbound write changes the deadline.
func (r *LazyInboundReader) ArmForOutbound() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outboundStarted = true
	if r.ivReady || r.deadlineArmed {
		return nil
	}
	if err := r.conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return fmt.Errorf("wifiin: set delayed server IV deadline: %w", err)
	}
	r.deadlineArmed = true
	return nil
}

// OutboundStarted reports whether application ciphertext has begun. SOCKS
// uses it to fully close an idle upstream on client half-close, preventing a
// server-IV reader from leaking indefinitely when no application bytes exist.
func (r *LazyInboundReader) OutboundStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outboundStarted
}

// Read initializes the receive cipher on its first non-empty read, then
// transparently decrypts the continuous CFB stream.
func (r *LazyInboundReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.initialize(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (r *LazyInboundReader) initialize() error {
	r.initMu.Lock()
	defer r.initMu.Unlock()
	if r.init {
		return r.initErr
	}
	r.init = true

	iv, err := r.source.ReadServerIV()
	if err != nil {
		r.initErr = fmt.Errorf("wifiin: delayed server IV: %w", err)
		return r.initErr
	}
	stream, err := NewDecrypter(r.key[:], iv[:])
	if err != nil {
		r.initErr = err
		return err
	}

	r.mu.Lock()
	r.ivReady = true
	clearDeadline := r.deadlineArmed
	r.mu.Unlock()
	if clearDeadline {
		if err := r.conn.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			r.initErr = fmt.Errorf("wifiin: clear delayed server IV deadline: %w", err)
			return r.initErr
		}
	}
	r.reader = &cipher.StreamReader{S: stream, R: r.source}
	return nil
}
