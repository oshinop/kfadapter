// Package control implements the KuaiFan HTTPS control-plane protocol.
package control

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxPlaintextBytes bounds every decrypted response before JSON parsing.
	MaxPlaintextBytes = 1 << 20
	blockSize         = aes.BlockSize
)

var (
	ErrMalformedCiphertext = errors.New("control: malformed ciphertext")
	ErrInvalidPadding      = errors.New("control: invalid PKCS#7 padding")
	ErrResponseTooLarge    = errors.New("control: response exceeds limit")
	ErrTrailingJSON        = errors.New("control: trailing JSON data")
	ErrInvalidEnvelope     = errors.New("control: invalid response envelope")
)

type codecMaterial struct {
	password string
	iv       string
	salt     string
}

var (
	normalMaterial = codecMaterial{
		password: "J22472m312506083",
		iv:       "156782572202746I",
		salt:     "41EAbXqlospdtruz",
	}
	authorityMaterial = codecMaterial{
		password: "19hlcHCh13070t43",
		iv:       "yx30x0j603N9zjgm",
		salt:     "k760jv5Ab1HdPffs",
	}
)

// Codec is an immutable AES-256-CBC codec for one of the protocol's two
// fixed compatibility parameter sets.
type Codec struct {
	key [32]byte
	iv  [aes.BlockSize]byte
}

// NormalCodec returns the codec used for every ordinary request and response.
func NormalCodec() Codec { return newCodec(normalMaterial) }

// AuthorityCodec returns the codec used only for the encrypted authority
// authKey field.
func AuthorityCodec() Codec { return newCodec(authorityMaterial) }

// EncodeRequest encodes an ordinary control-plane JSON body with the normal
// protocol constants.
func EncodeRequest(v any) ([]byte, error) { return NormalCodec().EncodeJSON(v) }

// DecodeResponse decodes exactly one ordinary encrypted response JSON value.
func DecodeResponse(body []byte, out any) error { return NormalCodec().DecodeJSON(body, out) }

func newCodec(material codecMaterial) Codec {
	var c Codec
	key := pbkdf2SHA1([]byte(material.password), []byte(material.salt)[:16], 100, len(c.key))
	copy(c.key[:], key)
	copy(c.iv[:], material.iv)
	return c
}

// EncodeJSON marshals v as UTF-8 JSON, PKCS#7 pads it, encrypts it, and
// returns the standard Base64 text that is used directly as the HTTP body.
func (c Codec) EncodeJSON(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("control: marshal request: %w", err)
	}
	return c.Encode(plain)
}

// Encode encrypts one UTF-8 JSON byte sequence. It is public for protocol
// fixtures; callers normally use EncodeJSON.
func (c Codec) Encode(plain []byte) ([]byte, error) {
	if len(plain) > MaxPlaintextBytes {
		return nil, ErrResponseTooLarge
	}
	padded := pkcs7Pad(plain, blockSize)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(padded)))
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(aesBlock(c.key[:]), c.iv[:]).CryptBlocks(ciphertext, padded)
	base64.StdEncoding.Encode(out, ciphertext)
	return out, nil
}

// Decode decodes one strictly Base64 AES-CBC body and validates its PKCS#7
// padding. The decrypted response is bounded to MaxPlaintextBytes.
func (c Codec) Decode(body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > base64.StdEncoding.EncodedLen(MaxPlaintextBytes+blockSize) {
		return nil, ErrResponseTooLarge
	}
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(ciphertext, body)
	if err != nil {
		return nil, fmt.Errorf("%w: base64", ErrMalformedCiphertext)
	}
	ciphertext = ciphertext[:n]
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, ErrMalformedCiphertext
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(aesBlock(c.key[:]), c.iv[:]).CryptBlocks(plain, ciphertext)
	plain, err = pkcs7Unpad(plain, blockSize)
	if err != nil {
		return nil, err
	}
	if len(plain) > MaxPlaintextBytes {
		return nil, ErrResponseTooLarge
	}
	return plain, nil
}

// DecodeJSON performs Decode and requires exactly one JSON value. It rejects
// trailing bytes, including a second otherwise-valid JSON document.
func (c Codec) DecodeJSON(body []byte, out any) error {
	plain, err := c.Decode(body)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("control: decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrTrailingJSON
		}
		return fmt.Errorf("%w: %v", ErrTrailingJSON, err)
	}
	return nil
}

func aesBlock(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // the fixed protocol key length is a compile-time invariant
	}
	return block
}

func pkcs7Pad(in []byte, size int) []byte {
	padding := size - len(in)%size
	out := make([]byte, len(in)+padding)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func pkcs7Unpad(in []byte, size int) ([]byte, error) {
	if len(in) == 0 || len(in)%size != 0 {
		return nil, ErrInvalidPadding
	}
	padding := int(in[len(in)-1])
	if padding == 0 || padding > size || padding > len(in) {
		return nil, ErrInvalidPadding
	}
	// Do not early-exit: padding validity should not create an oracle.
	var invalid byte
	for _, b := range in[len(in)-padding:] {
		invalid |= b ^ byte(padding)
	}
	if invalid != 0 {
		return nil, ErrInvalidPadding
	}
	return in[:len(in)-padding], nil
}

// pbkdf2SHA1 is PBKDF2-HMAC-SHA1 implemented locally to keep the protocol
// package dependency-free. It is deliberately limited to this fixed legacy
// compatibility use; it is not a password-storage primitive.
func pbkdf2SHA1(password, salt []byte, rounds, length int) []byte {
	if rounds <= 0 || length <= 0 {
		return nil
	}
	result := make([]byte, 0, length)
	counter := uint32(1)
	for len(result) < length {
		mac := hmac.New(sha1.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < rounds; i++ {
			mac = hmac.New(sha1.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
		counter++
	}
	return result[:length]
}
