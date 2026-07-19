package wifiin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrUDPUnavailable is returned by production call paths. Candidate codecs in
// this file are deliberately named TestOnly and must not enable UDP relay.
var ErrUDPUnavailable = errors.New("wifiin: UDP is unavailable pending a live fixture")

var (
	errInvalidUDPDatagram = errors.New("wifiin: invalid candidate SOCKS UDP datagram")
	errFragmentedUDP      = errors.New("wifiin: fragmented SOCKS UDP datagram")
)

// EncodeCandidateUDPTestOnly implements the unverified legacy-SS candidate
// mapping for deterministic protocol tests. It must not be used by a running
// SOCKS server. random must provide a fresh 16-byte IV per datagram.
func EncodeCandidateUDPTestOnly(key []byte, socksDatagram []byte, random io.Reader) ([]byte, error) {
	inner, err := candidateUDPInner(socksDatagram)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, fmt.Errorf("wifiin: read candidate UDP IV: %w", err)
	}
	stream, err := NewEncrypter(key, iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, IVSize+len(inner))
	copy(out, iv)
	stream.XORKeyStream(out[IVSize:], inner)
	return out, nil
}

// DecodeCandidateUDPTestOnly decodes the unverified legacy-SS candidate
// response into the SOCKS UDP datagram format. It is test-only and does not
// validate any WIFIIN provider authentication.
func DecodeCandidateUDPTestOnly(key []byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) <= IVSize {
		return nil, errInvalidUDPDatagram
	}
	stream, err := NewDecrypter(key, encrypted[:IVSize])
	if err != nil {
		return nil, err
	}
	inner := make([]byte, len(encrypted)-IVSize)
	stream.XORKeyStream(inner, encrypted[IVSize:])
	if _, err := candidateAddressLength(inner); err != nil {
		return nil, err
	}
	out := make([]byte, 3+len(inner))
	copy(out[3:], inner)
	return out, nil
}

func candidateUDPInner(d []byte) ([]byte, error) {
	if len(d) < 4 || d[0] != 0 || d[1] != 0 {
		return nil, errInvalidUDPDatagram
	}
	if d[2] != 0 {
		return nil, errFragmentedUDP
	}
	inner := d[3:]
	if _, err := candidateAddressLength(inner); err != nil {
		return nil, err
	}
	return inner, nil
}

func candidateAddressLength(inner []byte) (int, error) {
	if len(inner) < 1 {
		return 0, errInvalidUDPDatagram
	}
	var addressLength int
	switch inner[0] {
	case 0x01:
		addressLength = 1 + 4 + 2
	case 0x04:
		addressLength = 1 + 16 + 2
	case 0x03:
		if len(inner) < 2 {
			return 0, errInvalidUDPDatagram
		}
		addressLength = 1 + 1 + int(inner[1]) + 2
	default:
		return 0, errInvalidUDPDatagram
	}
	if len(inner) < addressLength {
		return 0, errInvalidUDPDatagram
	}
	return addressLength, nil
}

// LegacyInitialOTATestOnly encodes the unverified one-time-authentication
// payload described in the reverse-engineering notes. The returned bytes are
// encrypted with a new CFB context seeded by iv. It is never selected at
// runtime.
func LegacyInitialOTATestOnly(masterKey, iv, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("wifiin: OTA plaintext is empty")
	}
	plain := make([]byte, len(plaintext), len(plaintext)+10)
	copy(plain, plaintext)
	plain[0] |= 0x10
	tag := hmacSHA1(append(copyBytes(iv), masterKey...), plain)
	plain = append(plain, tag[:10]...)
	stream, err := NewEncrypter(masterKey, iv)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(plain, plain)
	return plain, nil
}

// LegacyChunkOTATestOnly returns an unencrypted candidate authenticated TCP
// chunk. A caller testing it may pass the result through the continuous CFB
// stream for that connection. sequence is not incremented here so tests can
// assert the exact wire input deterministically.
func LegacyChunkOTATestOnly(initialOutboundIV []byte, sequence uint32, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, errors.New("wifiin: OTA payload exceeds uint16 length")
	}
	key := make([]byte, len(initialOutboundIV)+4)
	copy(key, initialOutboundIV)
	binary.BigEndian.PutUint32(key[len(initialOutboundIV):], sequence)
	tag := hmacSHA1(key, payload)
	out := make([]byte, 2+10+len(payload))
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:12], tag[:10])
	copy(out[12:], payload)
	return out, nil
}

func hmacSHA1(key, input []byte) [20]byte {
	// Kept here rather than enabling any auth mode in the active TCP path.
	h := newHMACSHA1(key)
	_, _ = h.Write(input)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}
