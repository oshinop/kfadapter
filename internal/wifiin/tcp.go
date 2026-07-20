package wifiin

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// OuterType is the WIFIIN TCP stream packet type.
	OuterType byte = 0x03
	// UOTOuterType selects WIFIIN's UDP-over-TCP stream protocol.
	UOTOuterType byte = 0x23

	providerProduct = "cc.fancast.major"
	providerOS      = "MAC"
	providerVersion = "1.0.46"

	maxTargetHostBytes        = 255
	maxProviderFieldBytes     = 4096
	maxProviderExtensionBytes = 3*maxProviderFieldBytes + 128
)

var (
	ErrInvalidTarget       = errors.New("wifiin: invalid target")
	ErrInvalidProviderData = errors.New("wifiin: invalid provider extension field")
	ErrInvalidACK          = errors.New("wifiin: server acknowledgement is not 00 00 00")
	ErrTruncatedACK        = errors.New("wifiin: truncated server acknowledgement")
)

// ProviderExtension builds the exact sensitive extension expected by the
// verified WIFIIN TCP header. Callers must treat its result as secret.
func ProviderExtension(providerToken, orderID, userID string) (string, error) {
	for _, field := range []string{providerToken, orderID, userID} {
		if !validProviderField(field) {
			return "", ErrInvalidProviderData
		}
	}
	return "|" + providerToken + "|" + providerProduct + "|" + orderID + "|" + userID + "|" + providerOS + "|" + providerVersion, nil
}

func validProviderField(field string) bool {
	if len(field) == 0 || len(field) > maxProviderFieldBytes {
		return false
	}
	for index := range len(field) {
		value := field[index]
		if value < 0x21 || value > 0x7e || value == '|' {
			return false
		}
	}
	return true
}

// OutboundHeader is the full verified WIFIIN initial TCP packet and its
// continuous application-data encryption context.
type OutboundHeader struct {
	Packet []byte
	IV     [IVSize]byte
	Stream cipher.Stream
}

// NewOutboundHeader constructs a WIFIIN TCP packet using a fresh random IV.
// The returned Stream continues encrypting application bytes for this
// connection's client-to-server direction.
func NewOutboundHeader(key []byte, targetHost string, targetPort uint16, providerExtra string) (*OutboundHeader, error) {
	return newOutboundHeader(key, targetHost, targetPort, providerExtra, OuterType, rand.Reader)
}

// NewUOTOutboundHeader constructs the initial packet for a WIFIIN
// UDP-over-TCP stream. targetHost and targetPort identify the selected WIFIIN
// node itself; individual UDP destinations are carried by UOT frames.
func NewUOTOutboundHeader(key []byte, targetHost string, targetPort uint16, providerExtra string) (*OutboundHeader, error) {
	return newOutboundHeader(key, targetHost, targetPort, providerExtra, UOTOuterType, rand.Reader)
}

// NewOutboundHeaderWithIV is deterministic for a supplied IV. It exists for
// conformance tests and callers that already obtained one fresh random IV.
func NewOutboundHeaderWithIV(key []byte, targetHost string, targetPort uint16, providerExtra string, iv [IVSize]byte) (*OutboundHeader, error) {
	return newOutboundHeaderWithIV(key, targetHost, targetPort, providerExtra, OuterType, iv)
}

func newOutboundHeader(key []byte, targetHost string, targetPort uint16, providerExtra string, outerType byte, random io.Reader) (*OutboundHeader, error) {
	var iv [IVSize]byte
	if _, err := io.ReadFull(random, iv[:]); err != nil {
		return nil, fmt.Errorf("wifiin: read outbound IV: %w", err)
	}
	return newOutboundHeaderWithIV(key, targetHost, targetPort, providerExtra, outerType, iv)
}

func newOutboundHeaderWithIV(key []byte, targetHost string, targetPort uint16, providerExtra string, outerType byte, iv [IVSize]byte) (*OutboundHeader, error) {
	plain, err := headerPlaintext(targetHost, targetPort, providerExtra)
	if err != nil {
		return nil, err
	}
	stream, err := NewEncrypter(key, iv[:])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)

	// The length covers IV plus encrypted header, but not the trailing port.
	encryptedLength := IVSize + len(ciphertext)
	packet := make([]byte, 1+2+encryptedLength+2)
	packet[0] = outerType
	binary.BigEndian.PutUint16(packet[1:3], uint16(encryptedLength))
	copy(packet[3:3+IVSize], iv[:])
	copy(packet[3+IVSize:3+encryptedLength], ciphertext)
	binary.BigEndian.PutUint16(packet[3+encryptedLength:], targetPort)

	return &OutboundHeader{Packet: packet, IV: iv, Stream: stream}, nil
}

func headerPlaintext(targetHost string, targetPort uint16, providerExtra string) ([]byte, error) {
	if targetPort == 0 || !validASCIIHost(targetHost) || !ValidProviderExtension(providerExtra) {
		return nil, ErrInvalidTarget
	}
	if len(targetHost)+len(providerExtra) > 0xffff-IVSize {
		return nil, ErrInvalidTarget
	}
	plain := make([]byte, len(targetHost)+len(providerExtra))
	copy(plain, targetHost)
	copy(plain[len(targetHost):], providerExtra)
	return plain, nil
}

func validASCIIHost(host string) bool {
	if len(host) == 0 || len(host) > maxTargetHostBytes {
		return false
	}
	for index := range len(host) {
		value := host[index]
		if value < 0x21 || value > 0x7e || value == '|' {
			return false
		}
	}
	return true
}

// ValidProviderExtension reports whether extra is a canonical WIFIIN provider extension.
func ValidProviderExtension(extra string) bool {
	if len(extra) == 0 || len(extra) > maxProviderExtensionBytes {
		return false
	}
	parts := strings.Split(extra, "|")
	if len(parts) != 7 || parts[0] != "" || parts[2] != providerProduct || parts[5] != providerOS || parts[6] != providerVersion {
		return false
	}
	return validProviderField(parts[1]) && validProviderField(parts[3]) && validProviderField(parts[4])
}

// HandshakeReader consumes the required plaintext acknowledgement while
// retaining any bytes coalesced after it. It is then the reader used for the
// server IV and encrypted server-to-client stream.
type HandshakeReader struct {
	r           io.Reader
	pending     []byte
	readErr     error
	ackConsumed bool
}

// NewHandshakeReader returns an acknowledgement state machine over r.
func NewHandshakeReader(r io.Reader) *HandshakeReader { return &HandshakeReader{r: r} }

// ReadACK consumes exactly three plaintext bytes and accepts only 00 00 00.
// It handles arbitrary transport fragmentation and does not consume bytes
// after the acknowledgement.
func (r *HandshakeReader) ReadACK() error {
	if r.ackConsumed {
		return nil
	}
	for len(r.pending) < 3 {
		if err := r.fill(); err != nil {
			if errors.Is(err, io.EOF) {
				return ErrTruncatedACK
			}
			return fmt.Errorf("wifiin: read acknowledgement: %w", err)
		}
	}
	if r.pending[0] != 0 || r.pending[1] != 0 || r.pending[2] != 0 {
		return ErrInvalidACK
	}
	r.pending = r.pending[3:]
	r.ackConsumed = true
	return nil
}

// ReadServerIV reads the next 16 bytes after a successful acknowledgement.
func (r *HandshakeReader) ReadServerIV() ([IVSize]byte, error) {
	var iv [IVSize]byte
	if err := r.ReadACK(); err != nil {
		return iv, err
	}
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return iv, fmt.Errorf("wifiin: read server IV: %w", err)
	}
	return iv, nil
}

// Read first serves bytes coalesced with the acknowledgement, then delegates
// to the upstream reader. It is safe to pass directly to cipher.StreamReader.
func (r *HandshakeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) != 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.readErr != nil {
		err := r.readErr
		r.readErr = nil
		return 0, err
	}
	return r.r.Read(p)
}

func (r *HandshakeReader) fill() error {
	if r.readErr != nil {
		err := r.readErr
		r.readErr = nil
		return err
	}
	var buf [32 * 1024]byte
	for {
		n, err := r.r.Read(buf[:])
		if n > 0 {
			r.pending = append(r.pending, buf[:n]...)
			if err != nil {
				r.readErr = err
			}
			return nil
		}
		if err != nil {
			return err
		}
		// io.Reader is prohibited from indefinitely returning (0, nil).
		return io.ErrNoProgress
	}
}
