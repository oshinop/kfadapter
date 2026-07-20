package wifiin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	maxUOTBodySize     = 1<<16 - 1
	initialUOTBuffer   = 2048
	uotFlowIDSize      = 2
	socksUDPHeaderSize = 3
)

var (
	ErrInvalidUDPDatagram    = errors.New("wifiin: invalid SOCKS UDP datagram")
	ErrFragmentedUDP         = errors.New("wifiin: fragmented SOCKS UDP datagram")
	ErrUnsupportedUDPAddress = errors.New("wifiin: unsupported UDP address type")
	ErrInvalidUOTFrame       = errors.New("wifiin: invalid UDP-over-TCP frame")
)

// UOTWriter serializes SOCKS UDP datagrams into the verified WIFIIN
// UDP-over-TCP stream format. The supplied writer must be the continuous
// client-to-server AES-CFB stream established by a type-0x23 handshake.
// UOTWriter is not safe for concurrent use.
type UOTWriter struct {
	w     io.Writer
	frame []byte
}

func NewUOTWriter(w io.Writer) (*UOTWriter, error) {
	if w == nil {
		return nil, errors.New("wifiin: UOT writer is required")
	}
	return &UOTWriter{w: w, frame: make([]byte, initialUOTBuffer)}, nil
}

// WriteSOCKSDatagram writes one RFC 1928 UDP datagram. flowID identifies the
// client's UDP flow and is echoed by the WIFIIN server in response frames.
func (w *UOTWriter) WriteSOCKSDatagram(flowID uint16, datagram []byte) error {
	if len(datagram) < socksUDPHeaderSize || datagram[0] != 0 || datagram[1] != 0 {
		return ErrInvalidUDPDatagram
	}
	if datagram[2] != 0 {
		return ErrFragmentedUDP
	}
	addressLength, err := uotAddressLength(datagram[socksUDPHeaderSize:], false)
	if err != nil {
		return ErrInvalidUDPDatagram
	}
	inner := datagram[socksUDPHeaderSize:]
	// The production client emits only type-1 destinations. Live WIFIIN nodes
	// close the UOT stream when sent domain or IPv6 destination frames.
	if inner[0] != 0x01 {
		return ErrUnsupportedUDPAddress
	}
	bodyLength := len(inner) + uotFlowIDSize
	if bodyLength > maxUOTBodySize {
		return fmt.Errorf("%w: frame body is too large", ErrInvalidUDPDatagram)
	}
	frameLength := 2 + bodyLength
	if cap(w.frame) < frameLength {
		w.frame = make([]byte, frameLength)
	} else {
		w.frame = w.frame[:frameLength]
	}
	binary.BigEndian.PutUint16(w.frame[:2], uint16(bodyLength))
	copy(w.frame[2:2+addressLength], inner[:addressLength])
	flowOffset := 2 + addressLength
	binary.BigEndian.PutUint16(w.frame[flowOffset:flowOffset+uotFlowIDSize], flowID)
	copy(w.frame[flowOffset+uotFlowIDSize:], inner[addressLength:])
	if err := writeFull(w.w, w.frame); err != nil {
		return fmt.Errorf("wifiin: write UOT frame: %w", err)
	}
	return nil
}

// UOTReader deserializes a continuous decrypted WIFIIN UDP-over-TCP stream.
// It handles arbitrary TCP fragmentation and coalescing. UOTReader is not safe
// for concurrent use.
type UOTReader struct {
	r    io.Reader
	body []byte
}

func NewUOTReader(r io.Reader) (*UOTReader, error) {
	if r == nil {
		return nil, errors.New("wifiin: UOT reader is required")
	}
	return &UOTReader{r: r, body: make([]byte, initialUOTBuffer)}, nil
}

// ReadSOCKSDatagram reads one UOT response into dst and restores the RFC 1928
// three-byte UDP prefix. It returns the response flow ID separately.
func (r *UOTReader) ReadSOCKSDatagram(dst []byte) (n int, flowID uint16, err error) {
	var prefix [2]byte
	for {
		if _, err := io.ReadFull(r.r, prefix[:]); err != nil {
			return 0, 0, fmt.Errorf("wifiin: read UOT frame length: %w", err)
		}
		bodyLength := int(binary.BigEndian.Uint16(prefix[:]))
		if bodyLength == 0 {
			// The official client accepts zero-length keepalives between frames.
			continue
		}
		if cap(r.body) < bodyLength {
			r.body = make([]byte, bodyLength)
		} else {
			r.body = r.body[:bodyLength]
		}
		if _, err := io.ReadFull(r.r, r.body); err != nil {
			return 0, 0, fmt.Errorf("wifiin: read UOT frame body: %w", err)
		}
		addressLength, err := uotAddressLength(r.body, true)
		if err != nil || addressLength+uotFlowIDSize > bodyLength {
			return 0, 0, ErrInvalidUOTFrame
		}
		outputLength := socksUDPHeaderSize + bodyLength - uotFlowIDSize
		if len(dst) < outputLength {
			return 0, 0, io.ErrShortBuffer
		}
		dst[0], dst[1], dst[2] = 0, 0, 0
		copy(dst[socksUDPHeaderSize:socksUDPHeaderSize+addressLength], r.body[:addressLength])
		// The reference decoder selects the address type from the low nibble.
		dst[socksUDPHeaderSize] &= 0x0f
		flowOffset := addressLength
		flowID = binary.BigEndian.Uint16(r.body[flowOffset : flowOffset+uotFlowIDSize])
		copy(dst[socksUDPHeaderSize+addressLength:outputLength], r.body[flowOffset+uotFlowIDSize:])
		return outputLength, flowID, nil
	}
}

func uotAddressLength(packet []byte, maskType bool) (int, error) {
	if len(packet) < 1 {
		return 0, ErrInvalidUOTFrame
	}
	addressType := packet[0]
	if maskType {
		addressType &= 0x0f
	}
	var length int
	switch addressType {
	case 0x01:
		length = 1 + 4 + 2
	case 0x04:
		length = 1 + 16 + 2
	case 0x03:
		if len(packet) < 2 || packet[1] == 0 {
			return 0, ErrInvalidUOTFrame
		}
		length = 1 + 1 + int(packet[1]) + 2
	default:
		return 0, ErrInvalidUOTFrame
	}
	if len(packet) < length {
		return 0, ErrInvalidUOTFrame
	}
	return length, nil
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := w.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
