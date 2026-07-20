package socks

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	"github.com/kfadapter/kfadapter/internal/wifiin"
)

const maxUDPDatagramSize = 1<<16 - 1

type udpAssociation struct {
	conn     *net.UDPConn
	clientIP netip.Addr
	flowID   uint16
	endpoint atomic.Pointer[net.UDPAddr]
}

func newUDPAssociation(client net.Conn, requested target) (*udpAssociation, error) {
	remote, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok || remote == nil {
		return nil, errors.New("socks: UDP association requires a TCP client address")
	}
	clientIP, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return nil, errBadAddress
	}
	clientIP = clientIP.Unmap()
	requestedIP, err := netip.ParseAddr(requested.Host)
	if err != nil {
		return nil, errAddressTypeUnsupported
	}
	requestedIP = requestedIP.Unmap()
	if !requestedIP.IsUnspecified() && requestedIP != clientIP {
		return nil, errBadAddress
	}

	local, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok || local == nil {
		return nil, errors.New("socks: UDP association requires a TCP listener address")
	}
	network := "udp6"
	if local.IP.To4() != nil {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: append(net.IP(nil), local.IP...), Zone: local.Zone})
	if err != nil {
		return nil, fmt.Errorf("socks: bind UDP association: %w", err)
	}
	bound, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || bound.Port < 1 || bound.Port > 65535 {
		_ = udp.Close()
		return nil, errors.New("socks: invalid UDP association address")
	}
	association := &udpAssociation{conn: udp, clientIP: clientIP, flowID: uint16(bound.Port)}
	if requested.Port != 0 {
		association.endpoint.Store(&net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: int(requested.Port), Zone: remote.Zone})
	}
	return association, nil
}

func (a *udpAssociation) acceptSource(address *net.UDPAddr) bool {
	if address == nil || address.Port < 1 || address.Port > 65535 {
		return false
	}
	ip, ok := netip.AddrFromSlice(address.IP)
	if !ok || ip.Unmap() != a.clientIP {
		return false
	}
	if endpoint := a.endpoint.Load(); endpoint != nil {
		return address.Port == endpoint.Port
	}
	copyAddress := &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
	return a.endpoint.CompareAndSwap(nil, copyAddress)
}

func (s *Server) relayUDPAssociation(ctx context.Context, control net.Conn, upstream net.Conn, handshake *wifiin.HandshakeReader, header *wifiin.OutboundHeader, key []byte, association *udpAssociation) error {
	lazyInbound, err := wifiin.NewLazyInboundReader(handshake, key, upstream, s.handshakeTimeout)
	if err != nil {
		return fmt.Errorf("socks: configure delayed WIFIIN UOT IV: %w", err)
	}
	plaintextWriter := &outboundCFBWriter{
		writer:  &cipher.StreamWriter{S: header.Stream, W: upstream},
		inbound: lazyInbound,
		conn:    upstream,
	}
	uotWriter, err := wifiin.NewUOTWriter(plaintextWriter)
	if err != nil {
		return err
	}
	uotReader, err := wifiin.NewUOTReader(lazyInbound)
	if err != nil {
		return err
	}

	results := make(chan error, 3)
	go func() { results <- watchUDPControl(control) }()
	go func() { results <- association.clientToUOT(uotWriter) }()
	go func() { results <- association.uotToClient(uotReader) }()

	err = <-results
	_ = association.conn.Close()
	_ = upstream.Close()
	_ = control.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

func watchUDPControl(control net.Conn) error {
	var discard [256]byte
	for {
		_, err := control.Read(discard[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (a *udpAssociation) clientToUOT(writer *wifiin.UOTWriter) error {
	packet := make([]byte, maxUDPDatagramSize)
	for {
		n, _, flags, source, err := a.conn.ReadMsgUDP(packet, nil)
		if err != nil {
			return fmt.Errorf("socks: read client UDP datagram: %w", err)
		}
		if flags&syscall.MSG_TRUNC != 0 || !a.acceptSource(source) {
			continue
		}
		if err := writer.WriteSOCKSDatagram(a.flowID, packet[:n]); err != nil {
			if errors.Is(err, wifiin.ErrInvalidUDPDatagram) || errors.Is(err, wifiin.ErrFragmentedUDP) || errors.Is(err, wifiin.ErrUnsupportedUDPAddress) {
				continue
			}
			return err
		}
	}
}

func (a *udpAssociation) uotToClient(reader *wifiin.UOTReader) error {
	packet := make([]byte, maxUDPDatagramSize)
	for {
		n, flowID, err := reader.ReadSOCKSDatagram(packet)
		if err != nil {
			return fmt.Errorf("socks: read WIFIIN UOT datagram: %w", err)
		}
		if flowID != a.flowID {
			continue
		}
		endpoint := a.endpoint.Load()
		if endpoint == nil {
			continue
		}
		if _, err := a.conn.WriteToUDP(packet[:n], endpoint); err != nil {
			return fmt.Errorf("socks: write client UDP datagram: %w", err)
		}
	}
}
