// Package wifiin implements the observed Fanster-branded WIFIIN tunnel wire format.
package wifiin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- WIFIIN requires the legacy Shadowsocks MD5 chain.
	"errors"
	"fmt"
)

const (
	// KeySize is the AES-256 key length used by the verified WIFIIN path.
	KeySize = 32
	// IVSize is the AES block size and CFB IV length.
	IVSize = aes.BlockSize
)

var (
	ErrInvalidKey = errors.New("wifiin: AES-256 key must be 32 bytes")
	ErrInvalidIV  = errors.New("wifiin: AES-CFB IV must be 16 bytes")
)

// DeriveKey derives the AES-256 key with classic Shadowsocks/OpenSSL
// EVP_BytesToKey(MD5, iterations=1). This is deliberately independent of the
// control-plane PBKDF2 construction.
func DeriveKey(password string) [KeySize]byte {
	var key [KeySize]byte
	passwordBytes := []byte(password)
	var previous []byte
	derived := 0
	for derived < len(key) {
		h := md5.New() // #nosec G401 -- legacy WIFIIN protocol compatibility.
		_, _ = h.Write(previous)
		_, _ = h.Write(passwordBytes)
		previous = h.Sum(nil)
		derived += copy(key[derived:], previous)
	}
	return key
}

// NewEncrypter returns a fresh AES-256-CFB encryption context. A context is
// directional and must never be shared or reused with a different IV.
func NewEncrypter(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != IVSize {
		return nil, ErrInvalidIV
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

// NewDecrypter returns a fresh AES-256-CFB decryption context. A context is
// directional and must never be shared or reused with a different IV.
func NewDecrypter(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != IVSize {
		return nil, ErrInvalidIV
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func newBlock(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidKey, len(key))
	}
	return aes.NewCipher(key)
}
