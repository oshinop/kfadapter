package wifiin

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- legacy OTA candidate compatibility only.
	"hash"
)

func newHMACSHA1(key []byte) hash.Hash {
	return hmac.New(sha1.New, key) // #nosec G401 -- legacy OTA candidate compatibility only.
}

func copyBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
