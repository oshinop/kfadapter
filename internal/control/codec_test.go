package control

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNormalCodecGolden(t *testing.T) {
	t.Parallel()
	codec := NormalCodec()
	encoded, err := codec.Encode([]byte(`{"alpha":"beta"}`))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const golden = "2UPPJU3hXkuPUJ3fCTqeC8HMA7g/x0QLRCdRAqc1RbE="
	if string(encoded) != golden {
		t.Fatalf("ciphertext = %q, want %q", encoded, golden)
	}
	decoded, err := codec.Decode([]byte(golden))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := string(decoded), `{"alpha":"beta"}`; got != want {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
}

func TestCodecRejectsMalformedPaddingAndJSON(t *testing.T) {
	t.Parallel()
	codec := NormalCodec()
	for _, body := range [][]byte{
		[]byte("not-base64"),
		[]byte(""),
		[]byte("YQ=="), // ciphertext isn't an AES block
	} {
		if _, err := codec.Decode(body); err == nil {
			t.Fatalf("Decode(%q) unexpectedly succeeded", body)
		}
	}
	trailing, err := codec.Encode([]byte(`{"status":1}{}`))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := codec.DecodeJSON(trailing, &value); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("DecodeJSON trailing error = %v, want ErrTrailingJSON", err)
	}

	tooLarge, err := codec.Encode(bytes.Repeat([]byte{'x'}, MaxPlaintextBytes+1))
	if !errors.Is(err, ErrResponseTooLarge) || tooLarge != nil {
		t.Fatalf("oversized Encode = (%d bytes, %v)", len(tooLarge), err)
	}
	if _, err := codec.Decode([]byte(strings.Repeat("A", base64MaximumEncodedSize()+1))); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized Decode error = %v, want ErrResponseTooLarge", err)
	}
}
