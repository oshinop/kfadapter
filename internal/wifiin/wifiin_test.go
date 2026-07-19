package wifiin

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDeriveKeyClassicShadowsocksMD5(t *testing.T) {
	want := "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08"
	got := DeriveKey("password")
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("derived key = %x, want %s", got, want)
	}
}

func TestOutboundHeaderDeterministicVector(t *testing.T) {
	key := DeriveKey("password")
	var iv [IVSize]byte
	for i := range iv {
		iv[i] = byte(i)
	}
	h, err := NewOutboundHeaderWithIV(key[:], "example.com", 443, "|provider-token|cc.fancast.major|order|user|MAC|1.0.46", iv)
	if err != nil {
		t.Fatal(err)
	}
	want := "030051000102030405060708090a0b0c0d0e0fb6b3ef54a3ac17e248bb77086209be34e448ecea07fc316341d92e2e11733287e6690a1353b4c564be5791e87f262c3685f54d5560e63aab590706e457b15e916501bb"
	if got := hex.EncodeToString(h.Packet); got != want {
		t.Fatalf("header = %s, want %s", got, want)
	}

	plain := []byte("stream-data")
	ciphertext := append([]byte(nil), plain...)
	h.Stream.XORKeyStream(ciphertext, ciphertext)
	stream, err := NewDecrypter(key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	// Advance an independent decryptor through the encrypted header before
	// decrypting later stream bytes; CFB context continuity is mandatory.
	stream.XORKeyStream(make([]byte, 65), h.Packet[3+IVSize:len(h.Packet)-2])
	stream.XORKeyStream(ciphertext, ciphertext)
	if !bytes.Equal(ciphertext, plain) {
		t.Fatalf("continuous stream decrypted %q, want %q", ciphertext, plain)
	}
}

func TestProviderExtensionExact(t *testing.T) {
	got, err := ProviderExtension("token", "order", "user")
	if err != nil {
		t.Fatal(err)
	}
	if want := "|token|cc.fancast.major|order|user|MAC|1.0.46"; got != want {
		t.Fatalf("extension = %q, want %q", got, want)
	}
	if _, err := ProviderExtension("token|split", "order", "user"); !errors.Is(err, ErrInvalidProviderData) {
		t.Fatalf("invalid extension error = %v", err)
	}
}

func TestOutboundHeaderRejectsInvalidProviderFieldBytes(t *testing.T) {
	key := DeriveKey("password")
	var iv [IVSize]byte
	for _, invalid := range []string{"tökén", "has space", "has\x7fdel", "split|field"} {
		for field := range 3 {
			parts := []string{"token", "order", "user"}
			parts[field] = invalid
			extra := "|" + parts[0] + "|cc.fancast.major|" + parts[1] + "|" + parts[2] + "|MAC|1.0.46"
			if _, err := NewOutboundHeaderWithIV(key[:], "example.com", 443, extra, iv); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("field %d value %q error = %v, want %v", field, invalid, err, ErrInvalidTarget)
			}
		}
	}
}

func TestHandshakeReaderFragmentedAndCoalesced(t *testing.T) {
	iv := []byte("0123456789abcdef")
	ciphertext := []byte{0xa1, 0xb2, 0xc3}
	for _, chunks := range [][][]byte{
		{{0}, {0, 0}, append(iv, ciphertext...)},
		{append([]byte{0, 0, 0}, append(iv, ciphertext...)...)},
	} {
		r := NewHandshakeReader(&chunkReader{chunks: chunks})
		if err := r.ReadACK(); err != nil {
			t.Fatalf("ReadACK: %v", err)
		}
		gotIV, err := r.ReadServerIV()
		if err != nil {
			t.Fatalf("ReadServerIV: %v", err)
		}
		if !bytes.Equal(gotIV[:], iv) {
			t.Fatalf("IV = %x, want %x", gotIV, iv)
		}
		gotCiphertext, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("remaining ciphertext: %v", err)
		}
		if !bytes.Equal(gotCiphertext, ciphertext) {
			t.Fatalf("remaining ciphertext = %x, want %x", gotCiphertext, ciphertext)
		}
	}
}

func TestHandshakeReaderRejectsInvalidOrTruncatedACK(t *testing.T) {
	bad := NewHandshakeReader(&chunkReader{chunks: [][]byte{{0, 1, 0}}})
	if err := bad.ReadACK(); !errors.Is(err, ErrInvalidACK) {
		t.Fatalf("bad ACK error = %v", err)
	}
	short := NewHandshakeReader(&chunkReader{chunks: [][]byte{{0, 0}}})
	if err := short.ReadACK(); !errors.Is(err, ErrTruncatedACK) {
		t.Fatalf("short ACK error = %v", err)
	}
}

func TestCandidateUDPDeterministicAndDisabled(t *testing.T) {
	key := DeriveKey("password")
	request := append([]byte{0, 0, 0, 3, 11}, []byte("example.com")...)
	request = append(request, 1, 187)
	request = append(request, []byte("hello")...)
	got, err := EncodeCandidateUDPTestOnly(key[:], request, bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))
	if err != nil {
		t.Fatal(err)
	}
	want := "000102030405060708090a0b0c0d0e0fd0c0eb41b2ad02a04efa791b7f7a6a2ab7811f1d"
	if encoded := hex.EncodeToString(got); encoded != want {
		t.Fatalf("candidate UDP = %s, want %s", encoded, want)
	}
	decoded, err := DecodeCandidateUDPTestOnly(key[:], got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, request) {
		t.Fatalf("decoded UDP = %x, want %x", decoded, request)
	}
	if UDPEnabled() {
		t.Fatal("candidate UDP must remain unavailable without a live fixture")
	}
}

func TestCFBContextsPreserveArbitraryWriteBoundaries(t *testing.T) {
	key := DeriveKey("password")
	iv := []byte("0123456789abcdef")
	plain := []byte("a continuous CFB stream must not reset at write boundaries")

	oneShot, err := NewEncrypter(key[:], iv)
	if err != nil {
		t.Fatal(err)
	}
	wantCiphertext := make([]byte, len(plain))
	oneShot.XORKeyStream(wantCiphertext, plain)

	streaming, err := NewEncrypter(key[:], iv)
	if err != nil {
		t.Fatal(err)
	}
	gotCiphertext := make([]byte, len(plain))
	for _, span := range [][2]int{{0, 1}, {1, 8}, {8, 19}, {19, len(plain)}} {
		streaming.XORKeyStream(gotCiphertext[span[0]:span[1]], plain[span[0]:span[1]])
	}
	if !bytes.Equal(gotCiphertext, wantCiphertext) {
		t.Fatalf("stream ciphertext = %x, want %x", gotCiphertext, wantCiphertext)
	}

	decrypter, err := NewDecrypter(key[:], iv)
	if err != nil {
		t.Fatal(err)
	}
	gotPlain := make([]byte, len(plain))
	for _, span := range [][2]int{{0, 3}, {3, 4}, {4, len(plain)}} {
		decrypter.XORKeyStream(gotPlain[span[0]:span[1]], gotCiphertext[span[0]:span[1]])
	}
	if !bytes.Equal(gotPlain, plain) {
		t.Fatalf("stream plaintext = %q, want %q", gotPlain, plain)
	}
}

func TestCandidateUDPAllAddressFormsAndLegacyOTAVectors(t *testing.T) {
	key := DeriveKey("password")
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	ipv6Request := append([]byte{0, 0, 0, 4, 0x20, 1, 0x0d, 0xb8}, make([]byte, 11)...)
	ipv6Request = append(ipv6Request, 1, 0, 53, 'd', 'a', 't', 'a')
	cases := []struct {
		name    string
		request []byte
		want    string
	}{
		{"ipv4", []byte{0, 0, 0, 1, 192, 0, 2, 1, 31, 144, 'x'}, "000102030405060708090a0b0c0d0e0fd20b8e3bd2dfe2b4"},
		{"ipv6", ipv6Request, "000102030405060708090a0b0c0d0e0fd7eb8f346bc072cc2bd41a74127bd142bab4f415343de0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeCandidateUDPTestOnly(key[:], tc.request, bytes.NewReader(iv))
			if err != nil {
				t.Fatal(err)
			}
			if encoded := hex.EncodeToString(got); encoded != tc.want {
				t.Fatalf("encoded = %s, want %s", encoded, tc.want)
			}
			decoded, err := DecodeCandidateUDPTestOnly(key[:], got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, tc.request) {
				t.Fatalf("decoded = %x, want %x", decoded, tc.request)
			}
		})
	}

	initial, err := LegacyInitialOTATestOnly(key[:], iv, []byte{1, 127, 0, 0, 1, 0, 80})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(initial), "c2b48e39d2c0227d29e272a6108a49bda9"; got != want {
		t.Fatalf("initial OTA = %s, want %s", got, want)
	}
	chunk, err := LegacyChunkOTATestOnly(iv, 7, []byte("chunk"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(chunk), "00059bfd534846906ce4b5476368756e6b"; got != want {
		t.Fatalf("chunk OTA = %s, want %s", got, want)
	}
}

func TestCandidateUDPRejectsFragments(t *testing.T) {
	key := DeriveKey("password")
	_, err := EncodeCandidateUDPTestOnly(key[:], []byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 80}, bytes.NewReader(make([]byte, IVSize)))
	if !errors.Is(err, errFragmentedUDP) {
		t.Fatalf("fragment error = %v", err)
	}
}

func TestRelaySupportsHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverReady := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			serverReady <- conn
		}
	}()
	left, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right := <-serverReady
	defer right.Close()

	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamServer.Close()

	done := make(chan error, 1)
	go func() { done <- Relay(context.Background(), right, streamTestConn{Conn: upstreamClient}) }()

	if _, err := left.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := left.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(upstreamServer, request); err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q", request)
	}
	if _, err := upstreamServer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := upstreamServer.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(left)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q", response)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Relay did not finish")
	}
}

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	n := copy(p, chunk)
	if n == len(chunk) {
		r.chunks = r.chunks[1:]
	} else {
		r.chunks[0] = chunk[n:]
	}
	return n, nil
}

type streamTestConn struct{ net.Conn }

func (streamTestConn) CloseWrite() error { return nil }
