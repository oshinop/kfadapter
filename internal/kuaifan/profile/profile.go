// Package profile defines KuaiFan client-specific wire fingerprints and
// request schemas without performing network I/O or retaining credentials.
package profile

import (
	"crypto/md5" // #nosec G501 -- provider compatibility algorithm.
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	maxFieldBytes       = 4096
	base64Alphabet      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	DefaultSyntheticMAC = "020000000000"
)

// ID identifies an immutable KuaiFan client wire profile.
type ID string

const (
	IOSID     ID = "ios"
	WindowsID ID = "windows"
)

var (
	ErrInvalidVerifyInput = errors.New("control profile: invalid verify input")
	ErrInvalidLine        = errors.New("control profile: invalid line")
)

// Definition exposes the immutable request identity shared with the control
// transport. Profile-specific login field types remain concrete so callers can
// clear their transient password immediately after encoding.
type Definition interface {
	ID() ID
	UserAgent() string
	ConfigFields() any
	RequiresPostLoginRefresh() bool
	ValidateLine(provider, password string) (eligible bool, err error)
}

// LoginInput is the transient account input used to build either client schema.
type LoginInput struct {
	Account        string
	Password       string
	InstallationID string
}

func withinLimit(value string) bool { return len(value) <= maxFieldBytes }

// RandomInt returns an unbiased integer in [0,n) from reader. It is shared by
// profile verifiers, Windows nonces, encrypted envelopes, and retry jitter.
func RandomInt(reader io.Reader, n int) (int, error) {
	if reader == nil || n <= 0 {
		return 0, ErrInvalidVerifyInput
	}
	if n <= 256 {
		limit := 256 - 256%n
		for {
			var sample [1]byte
			if _, err := io.ReadFull(reader, sample[:]); err != nil {
				return 0, err
			}
			if int(sample[0]) < limit {
				return int(sample[0]) % n, nil
			}
		}
	}
	const sampleSpace = uint64(1) << 32
	limit := sampleSpace - sampleSpace%uint64(n)
	for {
		var sample [4]byte
		if _, err := io.ReadFull(reader, sample[:]); err != nil {
			return 0, err
		}
		value := uint64(sample[0])<<24 | uint64(sample[1])<<16 | uint64(sample[2])<<8 | uint64(sample[3])
		if value < limit {
			return int(value % uint64(n)), nil // #nosec G115 -- result is strictly less than positive int n.
		}
	}
}

func computeVerify(subject, timestamp string, randomness io.Reader, validSubject func(string) bool) (string, error) {
	if randomness == nil {
		randomness = rand.Reader
	}
	if len(timestamp) < 4 || !withinLimit(timestamp) || !validSubject(subject) {
		return "", ErrInvalidVerifyInput
	}
	for _, digit := range timestamp[len(timestamp)-4:] {
		if digit < '0' || digit > '9' {
			return "", ErrInvalidVerifyInput
		}
	}
	joined := subject + timestamp
	half := len(joined) / 2
	if half == 0 {
		return "", ErrInvalidVerifyInput
	}
	offset, err := RandomInt(randomness, half)
	if err != nil {
		return "", fmt.Errorf("control profile: generate verify split: %w", err)
	}
	split := half + offset
	if offset%2 == 1 {
		split = half - offset
	}
	if split <= 0 || split >= len(joined) {
		return "", ErrInvalidVerifyInput
	}
	left, right := joined[:split], joined[split:]
	if len(left) == 0 || len(right) == 0 || split > len(base64Alphabet) {
		return "", ErrInvalidVerifyInput
	}
	digits := [4]int{}
	for index, digit := range timestamp[len(timestamp)-4:] {
		digits[index] = int(digit - '0')
	}
	material := joined + string([]byte{
		left[digits[0]%len(left)],
		left[len(left)-1-(digits[1]%len(left))],
		right[digits[2]%len(right)],
		right[len(right)-1-(digits[3]%len(right))],
	})
	digest := md5.Sum([]byte(material)) // #nosec G401 -- provider compatibility verifier.
	hexDigest := make([]byte, hex.EncodedLen(len(digest)))
	hex.Encode(hexDigest, digest[:])
	encoded := base64.StdEncoding.EncodeToString(hexDigest)
	if len(encoded) < 10 {
		return "", ErrInvalidVerifyInput
	}
	randomCharacters := make([]byte, 3)
	for index := range randomCharacters {
		var sample [1]byte
		if _, err := io.ReadFull(randomness, sample[:]); err != nil {
			return "", fmt.Errorf("control profile: generate verify characters: %w", err)
		}
		randomCharacters[index] = base64Alphabet[int(sample[0])&63]
	}
	return encoded[:10] + string(randomCharacters) + string(base64Alphabet[split-1]) + encoded[10:], nil
}
