package socks

import (
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxConnections   = 1024
	maximumMaxConnections   = 65536
)

// SnapshotSource resolves compact tunnel pins without exposing a runtime
// snapshot or selector map to the SOCKS hot path. state.Manager is the
// production implementation.
type SnapshotSource interface {
	CompactPin(selector string, credentialGeneration uint64, now time.Time) (state.TunnelPin, error)
	SessionCurrentPin(pin state.TunnelPin, now time.Time) bool
}

// DialContextFunc dials only the selected WIFIIN node. target destinations are
// deliberately never handed to it, preventing a direct-traffic escape.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config defines the SOCKS listener's dependency boundaries.
type Config struct {
	Snapshots SnapshotSource
	Selectors *selector.Registry

	DialContext      DialContextFunc
	HandshakeTimeout time.Duration
	MaxConnections   int
}

// Server is a SOCKS5/RFC1929 frontend. Its selector registry is atomically
// replaceable for subscription rotation; every established session retains
// only a compact state tunnel pin, never a runtime snapshot.
type Server struct {
	snapshots        SnapshotSource
	dial             DialContextFunc
	handshakeTimeout time.Duration
	slots            chan struct{}
	selectors        atomic.Pointer[selector.Registry]

	lifecycleMu  sync.Mutex
	listener     net.Listener
	shuttingDown bool
	active       map[net.Conn]context.CancelFunc
	drained      chan struct{}
}

// New constructs a server. Listener selection belongs to the caller.
func New(config Config) (*Server, error) {
	if config.Snapshots == nil {
		return nil, errors.New("socks: snapshot source is required")
	}
	if config.Selectors == nil {
		return nil, errors.New("socks: selector registry is required")
	}
	timeout := config.HandshakeTimeout
	if timeout == 0 {
		timeout = defaultHandshakeTimeout
	}
	if timeout < 0 {
		return nil, errors.New("socks: handshake timeout must be positive")
	}
	maxConnections := config.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if maxConnections < 1 || maxConnections > maximumMaxConnections {
		return nil, fmt.Errorf("socks: max connections must be in 1..%d", maximumMaxConnections)
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	drained := make(chan struct{})
	close(drained)
	server := &Server{snapshots: config.Snapshots, dial: dial, handshakeTimeout: timeout, slots: make(chan struct{}, maxConnections), active: make(map[net.Conn]context.CancelFunc), drained: drained}
	server.selectors.Store(config.Selectors)
	return server, nil
}

// SetSelectors atomically adopts an immutable registry containing the current
// and, if applicable, pending subscription generation. Existing TCP flows are
// unaffected.
func (s *Server) SetSelectors(registry *selector.Registry) error {
	if s == nil || registry == nil {
		return errors.New("socks: selector registry is required")
	}
	s.selectors.Store(registry)
	return nil
}

// Shutdown stops accepting new SOCKS connections and waits for active
// handlers to drain. When ctx expires, it cancels and closes every remaining
// handler so relays and in-flight setup cannot outlive the shutdown deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("socks: server and shutdown context are required")
	}
	s.lifecycleMu.Lock()
	s.shuttingDown = true
	listener := s.listener
	s.listener = nil
	drained := s.drained
	s.lifecycleMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		s.forceActiveHandlers()
		return ctx.Err()
	}
}

func (s *Server) beginServe(listener net.Listener) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.shuttingDown {
		return errors.New("socks: server is shutting down")
	}
	if s.listener != nil {
		return errors.New("socks: server is already serving")
	}
	s.listener = listener
	return nil
}

func (s *Server) endServe(listener net.Listener) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.listener == listener {
		s.listener = nil
	}
}

func (s *Server) accepting(listener net.Listener) bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return !s.shuttingDown && s.listener == listener
}

func (s *Server) addActiveHandler(connection net.Conn, cancel context.CancelFunc) bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.shuttingDown {
		return false
	}
	if len(s.active) == 0 {
		s.drained = make(chan struct{})
	}
	s.active[connection] = cancel
	return true
}

func (s *Server) removeActiveHandler(connection net.Conn) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	delete(s.active, connection)
	if len(s.active) == 0 {
		close(s.drained)
	}
}

func (s *Server) forceActiveHandlers() {
	s.lifecycleMu.Lock()
	handlers := make([]struct {
		connection net.Conn
		cancel     context.CancelFunc
	}, 0, len(s.active))
	for connection, cancel := range s.active {
		handlers = append(handlers, struct {
			connection net.Conn
			cancel     context.CancelFunc
		}{connection: connection, cancel: cancel})
	}
	s.lifecycleMu.Unlock()
	for _, handler := range handlers {
		handler.cancel()
		_ = handler.connection.Close()
	}
}

// Serve accepts connections until ctx is canceled. Accepted handlers retain
// independent contexts and must be drained with Shutdown.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("socks: server, context, and listener are required")
	}
	if err := s.beginServe(listener); err != nil {
		return err
	}
	defer s.endServe(listener)
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || !s.accepting(listener) {
				return nil
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			handlerCtx, cancel := context.WithCancel(context.Background())
			if !s.addActiveHandler(connection, cancel) {
				cancel()
				_ = connection.Close()
				<-s.slots
				continue
			}
			go func(connection net.Conn, handlerCtx context.Context, cancel context.CancelFunc) {
				defer func() { <-s.slots }()
				defer s.removeActiveHandler(connection)
				defer cancel()
				_ = s.HandleConn(handlerCtx, connection)
			}(connection, handlerCtx, cancel)
		default:
			_ = connection.Close()
		}
	}
}

// HandleConn processes one SOCKS connection. It never logs credentials,
// tunnel material, provider extensions, or requested destinations.
func (s *Server) HandleConn(ctx context.Context, client net.Conn) error {
	if s == nil || client == nil {
		return errors.New("socks: server and client are required")
	}
	defer client.Close()
	handlerDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-handlerDone:
		}
	}()
	defer close(handlerDone)
	if err := client.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return fmt.Errorf("socks: set client setup deadline: %w", err)
	}
	if err := negotiate(client, client); err != nil {
		return err
	}
	username, password, err := readUserPassword(client)
	if err != nil {
		_ = writeAuthStatus(client, false)
		return err
	}

	// Authenticate credentials first, then retain only a compact state-owned
	// tunnel pin. No runtime snapshot or selector map escapes into this flow.
	now := time.Now()
	registry := s.selectors.Load()
	if registry == nil {
		_ = writeAuthStatus(client, false)
		return state.ErrSelectorUnknown
	}
	credentialGeneration, authenticated := registry.AuthenticateAt(username, password, now)
	if !authenticated {
		_ = writeAuthStatus(client, false)
		return state.ErrSelectorUnknown
	}
	pin, err := s.snapshots.CompactPin(username, credentialGeneration, now)
	node := pin.Node
	if err != nil || !node.TunnelEligible() {
		_ = writeAuthStatus(client, false)
		if err != nil {
			return err
		}
		return state.ErrSelectorUnknown
	}
	if err := writeAuthStatus(client, true); err != nil {
		return err
	}

	command, destination, err := readRequest(client)
	if err != nil {
		code := replyGeneralFailure
		if errors.Is(err, errAddressTypeUnsupported) {
			code = replyAddressUnsupported
		}
		_ = writeReply(client, code, target{})
		return err
	}
	if command != commandConnect && command != commandUDP {
		_ = writeReply(client, replyCommandUnsupported, target{})
		return nil
	}
	if command == commandConnect && destination.Port == 0 {
		_ = writeReply(client, replyGeneralFailure, target{})
		return errBadAddress
	}
	// Authentication may have completed before a client supplies CONNECT. Do
	// not let a stalled socket create a tunnel after logout, expiry, authority
	// refresh, selector rotation, preference exclusion, or node replacement.
	// Re-resolving returns a compact current pin and never clones a snapshot.
	now = time.Now()
	registry = s.selectors.Load()
	if registry == nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	credentialGeneration, authenticated = registry.AuthenticateAt(username, password, now)
	if !authenticated {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	revalidatedPin, resolveErr := s.snapshots.CompactPin(username, credentialGeneration, now)
	revalidatedNode := revalidatedPin.Node
	if resolveErr != nil || s.selectors.Load() != registry || !samePinAuthority(pin, revalidatedPin) || !revalidatedNode.TunnelEligible() || !sameCanonicalNode(node, revalidatedNode) {
		_ = writeReply(client, replyGeneralFailure, target{})
		if resolveErr != nil {
			return resolveErr
		}
		return state.ErrSelectorUnknown
	}
	pin, node = revalidatedPin, revalidatedNode
	if err := client.SetDeadline(time.Time{}); err != nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return fmt.Errorf("socks: clear client setup deadline: %w", err)
	}

	if !strings.EqualFold(pin.Session.TunnelMethod, "aes-256-cfb") {
		_ = writeReply(client, replyGeneralFailure, target{})
		return errors.New("socks: unsupported WIFIIN tunnel cipher")
	}

	var association *udpAssociation
	if command == commandUDP {
		association, err = newUDPAssociation(client, destination)
		if err != nil {
			code := replyGeneralFailure
			if errors.Is(err, errAddressTypeUnsupported) {
				code = replyAddressUnsupported
			}
			_ = writeReply(client, code, target{})
			return err
		}
		defer association.conn.Close()
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, s.handshakeTimeout)
	upstream, err := s.dial(dialCtx, "tcp", net.JoinHostPort(node.Host, strconv.Itoa(int(node.Port))))
	cancelDial()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		_ = writeReply(client, dialReply(err), target{})
		return fmt.Errorf("socks: connect selected upstream: %w", err)
	}
	defer upstream.Close()

	deadline := time.Now().Add(s.handshakeTimeout)
	if err := upstream.SetDeadline(deadline); err != nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return fmt.Errorf("socks: set handshake deadline: %w", err)
	}
	key := wifiin.DeriveKey(pin.Session.TunnelPassword)
	var header *wifiin.OutboundHeader
	if command == commandUDP {
		header, err = wifiin.NewUOTOutboundHeader(key[:], node.Host, node.Port, pin.Session.ProviderExtension)
	} else {
		header, err = wifiin.NewOutboundHeader(key[:], destination.Host, destination.Port, pin.Session.ProviderExtension)
	}
	if err == nil {
		err = writeAll(upstream, header.Packet)
	}
	var reader *wifiin.HandshakeReader
	if err == nil {
		reader = wifiin.NewHandshakeReader(upstream)
		err = reader.ReadACK()
	}
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return fmt.Errorf("socks: WIFIIN handshake: %w", err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		_ = writeReply(client, replyGeneralFailure, target{})
		return fmt.Errorf("socks: clear handshake deadline: %w", err)
	}
	// The upstream acknowledged the header. This is the final admission point:
	// lifecycle invalidation that linearized first prevents a new tunnel, while
	// later invalidation may drain the now-pinned established flow.
	now = time.Now()
	if !s.snapshots.SessionCurrentPin(pin, now) {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	registry = s.selectors.Load()
	if registry == nil {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	credentialGeneration, authenticated = registry.AuthenticateAt(username, password, now)
	if !authenticated {
		_ = writeReply(client, replyGeneralFailure, target{})
		return state.ErrSelectorUnknown
	}
	finalPin, finalResolveErr := s.snapshots.CompactPin(username, credentialGeneration, now)
	finalNode := finalPin.Node
	if finalResolveErr != nil || s.selectors.Load() != registry || !samePinAuthority(pin, finalPin) || !finalNode.TunnelEligible() || !sameCanonicalNode(node, finalNode) {
		_ = writeReply(client, replyGeneralFailure, target{})
		if finalResolveErr != nil {
			return finalResolveErr
		}
		return state.ErrSelectorUnknown
	}
	pin = finalPin
	if association != nil {
		if err := writeReply(client, replySucceeded, targetFromAddr(association.conn.LocalAddr())); err != nil {
			return err
		}
		return s.relayUDPAssociation(ctx, client, upstream, reader, header, key[:], association)
	}
	if err := writeReply(client, replySucceeded, targetFromAddr(upstream.LocalAddr())); err != nil {
		return err
	}

	// The server IV is deliberately lazy: real WIFIIN providers can withhold it
	// until they receive application ciphertext. Relay starts both directions,
	// and outboundCFBWriter arms the bounded IV read only on the first write.
	lazyInbound, err := wifiin.NewLazyInboundReader(reader, key[:], upstream, s.handshakeTimeout)
	if err != nil {
		return fmt.Errorf("socks: configure delayed WIFIIN IV: %w", err)
	}
	tunnel := &cipherConn{
		Conn:   upstream,
		reader: lazyInbound,
		writer: &outboundCFBWriter{
			writer:  &cipher.StreamWriter{S: header.Stream, W: upstream},
			inbound: lazyInbound,
			conn:    upstream,
		},
	}
	return wifiin.Relay(ctx, client, tunnel)
}

type cipherConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c *cipherConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *cipherConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *cipherConn) CloseWrite() error {
	if closer, ok := c.writer.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

type outboundCFBWriter struct {
	writer  io.Writer
	inbound *wifiin.LazyInboundReader
	conn    net.Conn
}

func (w *outboundCFBWriter) Write(p []byte) (int, error) {
	if len(p) != 0 {
		if err := w.inbound.ArmForOutbound(); err != nil {
			return 0, err
		}
	}
	return w.writer.Write(p)
}

func (w *outboundCFBWriter) CloseWrite() error {
	if !w.inbound.OutboundStarted() {
		return w.conn.Close()
	}
	if closer, ok := w.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return w.conn.Close()
}

func samePinAuthority(left, right state.TunnelPin) bool {
	if !left.ExpiresAt.Equal(right.ExpiresAt) {
		return false
	}
	return constantTimeEqual(left.Session.UserID, right.Session.UserID) &&
		constantTimeEqual(left.Session.LoginToken, right.Session.LoginToken) &&
		constantTimeEqual(left.Session.ProviderToken, right.Session.ProviderToken) &&
		constantTimeEqual(left.Session.TunnelPassword, right.Session.TunnelPassword) &&
		constantTimeEqual(left.Session.TunnelMethod, right.Session.TunnelMethod) &&
		constantTimeEqual(left.Session.ProviderExtension, right.Session.ProviderExtension)
}

func constantTimeEqual(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sameCanonicalNode(left, right state.Node) bool {
	leftIdentity, leftErr := selector.Canonicalize(selector.NodeIdentity{NodeID: left.ID, Provider: left.Provider, Host: left.Host, Port: int(left.Port)})
	rightIdentity, rightErr := selector.Canonicalize(selector.NodeIdentity{NodeID: right.ID, Provider: right.Provider, Host: right.Host, Port: int(right.Port)})
	return leftErr == nil && rightErr == nil && leftIdentity == rightIdentity
}

func targetFromAddr(address net.Addr) target {
	switch value := address.(type) {
	case *net.TCPAddr:
		if value != nil && value.Port > 0 && value.Port <= 65535 {
			return target{Host: value.IP.String(), Port: uint16(value.Port)}
		}
	case *net.UDPAddr:
		if value != nil && value.Port > 0 && value.Port <= 65535 {
			return target{Host: value.IP.String(), Port: uint16(value.Port)}
		}
	}
	return target{}
}

func dialReply(err error) byte {
	if errors.Is(err, context.DeadlineExceeded) {
		return replyTTLExpired
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return replyTTLExpired
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return replyConnectionForbidden
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return replyNetworkUnreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return replyHostUnreachable
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return replyConnectionRefused
	}
	return replyGeneralFailure
}
