package wifiin

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestUOTHandshakeAndFrameDeterministic(t *testing.T) {
	key := DeriveKey("password")
	var iv [IVSize]byte
	for index := range iv {
		iv[index] = byte(index)
	}
	header, err := newOutboundHeaderWithIV(key[:], "192.0.2.1", 443, "|provider-token|cc.fancast.major|order|user|MAC|1.0.46", UOTOuterType, iv)
	if err != nil {
		t.Fatal(err)
	}
	if header.Packet[0] != UOTOuterType {
		t.Fatalf("outer type = %#x, want %#x", header.Packet[0], UOTOuterType)
	}

	request := []byte{0, 0, 0, 1, 192, 0, 2, 1, 1, 187, 'h', 'e', 'l', 'l', 'o'}
	var wire bytes.Buffer
	writer, err := NewUOTWriter(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSOCKSDatagram(0xbeef, request); err != nil {
		t.Fatal(err)
	}
	want := "000e01c000020101bbbeef68656c6c6f"
	if got := hex.EncodeToString(wire.Bytes()); got != want {
		t.Fatalf("UOT frame = %s, want %s", got, want)
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

func TestUOTReaderHandlesAddressFormsFragmentationAndKeepalive(t *testing.T) {
	cases := []struct {
		name    string
		address []byte
		flowID  uint16
		payload []byte
	}{
		{"ipv4", []byte{1, 192, 0, 2, 1, 0, 53}, 0x1234, []byte("v4")},
		{"domain", append(append([]byte{3, 11}, []byte("example.com")...), 1, 187), 0xbeef, []byte("name")},
		{"ipv6", append(append([]byte{4, 0x20, 1, 0x0d, 0xb8}, make([]byte, 12)...), 0, 53), 7, []byte("v6")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]byte(nil), tc.address...)
			body = binary.BigEndian.AppendUint16(body, tc.flowID)
			body = append(body, tc.payload...)
			frame := []byte{0, 0, 0, 0}
			binary.BigEndian.PutUint16(frame[2:4], uint16(len(body)))
			frame = append(frame, body...)
			reader, err := NewUOTReader(&chunkReader{chunks: [][]byte{frame[:1], frame[1:5], frame[5:]}})
			if err != nil {
				t.Fatal(err)
			}
			output := make([]byte, 1<<16-1)
			n, flowID, err := reader.ReadSOCKSDatagram(output)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]byte{0, 0, 0}, tc.address...)
			want = append(want, tc.payload...)
			if flowID != tc.flowID || !bytes.Equal(output[:n], want) {
				t.Fatalf("decoded = %x flow=%#x, want %x flow=%#x", output[:n], flowID, want, tc.flowID)
			}
		})
	}
}

func TestUOTRejectsFragmentsAndMalformedFrames(t *testing.T) {
	writer, err := NewUOTWriter(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSOCKSDatagram(1, []byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 80}); !errors.Is(err, ErrFragmentedUDP) {
		t.Fatalf("fragment error = %v", err)
	}
	domain := append([]byte{0, 0, 0, 3, 11}, []byte("example.com")...)
	domain = append(domain, 0, 53)
	if err := writer.WriteSOCKSDatagram(1, domain); !errors.Is(err, ErrUnsupportedUDPAddress) {
		t.Fatalf("domain address error = %v", err)
	}
	reader, err := NewUOTReader(bytes.NewReader([]byte{0, 1, 0xff}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.ReadSOCKSDatagram(make([]byte, 32)); !errors.Is(err, ErrInvalidUOTFrame) {
		t.Fatalf("malformed frame error = %v", err)
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
