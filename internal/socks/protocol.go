// Package socks provides the loopback-only SOCKS5 frontend for WIFIIN TCP.
package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	version5    byte = 0x05
	version1929 byte = 0x01

	methodNoAuthentication byte = 0x00
	methodUserPassword     byte = 0x02
	methodNoAcceptable     byte = 0xff

	commandConnect byte = 0x01
	commandBind    byte = 0x02
	commandUDP     byte = 0x03

	addressIPv4   byte = 0x01
	addressDomain byte = 0x03
	addressIPv6   byte = 0x04

	replySucceeded           byte = 0x00
	replyGeneralFailure      byte = 0x01
	replyConnectionForbidden byte = 0x02
	replyNetworkUnreachable  byte = 0x03
	replyHostUnreachable     byte = 0x04
	replyConnectionRefused   byte = 0x05
	replyTTLExpired          byte = 0x06
	replyCommandUnsupported  byte = 0x07
	replyAddressUnsupported  byte = 0x08
)

var (
	errBadGreeting            = errors.New("socks: malformed method negotiation")
	errBadAuth                = errors.New("socks: malformed RFC1929 authentication")
	errBadRequest             = errors.New("socks: malformed request")
	errBadAddress             = errors.New("socks: malformed target address")
	errAddressTypeUnsupported = errors.New("socks: unsupported target address type")
)

type target struct {
	Host string
	Port uint16
}

func negotiate(r io.Reader, w io.Writer) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("%w: %v", errBadGreeting, err)
	}
	if header[0] != version5 || header[1] == 0 {
		return errBadGreeting
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return fmt.Errorf("%w: %v", errBadGreeting, err)
	}
	for _, method := range methods {
		if method == methodUserPassword {
			return writeAll(w, []byte{version5, methodUserPassword})
		}
	}
	if err := writeAll(w, []byte{version5, methodNoAcceptable}); err != nil {
		return err
	}
	return errBadGreeting
}

func readUserPassword(r io.Reader) (username, password string, err error) {
	var versionAndLength [2]byte
	if _, err = io.ReadFull(r, versionAndLength[:]); err != nil {
		return "", "", fmt.Errorf("%w: %v", errBadAuth, err)
	}
	if versionAndLength[0] != version1929 || versionAndLength[1] == 0 {
		return "", "", errBadAuth
	}
	usernameBytes := make([]byte, int(versionAndLength[1]))
	if _, err = io.ReadFull(r, usernameBytes); err != nil {
		return "", "", fmt.Errorf("%w: %v", errBadAuth, err)
	}
	var passwordLength [1]byte
	if _, err = io.ReadFull(r, passwordLength[:]); err != nil {
		return "", "", fmt.Errorf("%w: %v", errBadAuth, err)
	}
	if passwordLength[0] == 0 {
		return "", "", errBadAuth
	}
	passwordBytes := make([]byte, int(passwordLength[0]))
	if _, err = io.ReadFull(r, passwordBytes); err != nil {
		return "", "", fmt.Errorf("%w: %v", errBadAuth, err)
	}
	return string(usernameBytes), string(passwordBytes), nil
}

func writeAuthStatus(w io.Writer, success bool) error {
	status := byte(0x01)
	if success {
		status = 0
	}
	return writeAll(w, []byte{version1929, status})
}

func readRequest(r io.Reader) (command byte, destination target, err error) {
	var header [4]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return 0, target{}, fmt.Errorf("%w: %v", errBadRequest, err)
	}
	if header[0] != version5 || header[2] != 0 {
		return 0, target{}, errBadRequest
	}
	command = header[1]
	destination.Host, destination.Port, err = readTargetAddress(r, header[3])
	return command, destination, err
}

func readTargetAddress(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case addressIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, fmt.Errorf("%w: %v", errBadAddress, err)
		}
		host = netip.AddrFrom4(raw).String()
	case addressIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", 0, fmt.Errorf("%w: %v", errBadAddress, err)
		}
		host = netip.AddrFrom16(raw).String()
	case addressDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, fmt.Errorf("%w: %v", errBadAddress, err)
		}
		if n[0] == 0 {
			return "", 0, errBadAddress
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, fmt.Errorf("%w: %v", errBadAddress, err)
		}
		for _, b := range name {
			if b < 0x21 || b > 0x7e {
				return "", 0, errBadAddress
			}
		}
		host = string(name)
	default:
		return "", 0, errAddressTypeUnsupported
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return "", 0, fmt.Errorf("%w: %v", errBadAddress, err)
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	return host, port, nil
}
func writeReply(w io.Writer, code byte, bound target) error {
	// Empty/error bound addresses use the standard IPv4 0.0.0.0:0 form.
	if bound.Host == "" {
		return writeAll(w, []byte{version5, code, 0, addressIPv4, 0, 0, 0, 0, 0, 0})
	}
	if ip, err := netip.ParseAddr(bound.Host); err == nil {
		if ip.Is4() {
			out := make([]byte, 10)
			out[0], out[1], out[2], out[3] = version5, code, 0, addressIPv4
			copy(out[4:8], ip.AsSlice())
			binary.BigEndian.PutUint16(out[8:], bound.Port)
			return writeAll(w, out)
		}
		if ip.Is6() {
			out := make([]byte, 22)
			out[0], out[1], out[2], out[3] = version5, code, 0, addressIPv6
			copy(out[4:20], ip.AsSlice())
			binary.BigEndian.PutUint16(out[20:], bound.Port)
			return writeAll(w, out)
		}
	}
	if len(bound.Host) > 255 {
		return errBadAddress
	}
	out := make([]byte, 4+1+len(bound.Host)+2)
	out[0], out[1], out[2], out[3] = version5, code, 0, addressDomain
	out[4] = byte(len(bound.Host))
	copy(out[5:], bound.Host)
	binary.BigEndian.PutUint16(out[5+len(bound.Host):], bound.Port)
	return writeAll(w, out)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
