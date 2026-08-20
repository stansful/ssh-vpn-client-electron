package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// The dataplane never speaks the transport's own protocol. Both transports
// already publish a loopback SOCKS5 inbound - the Node process does for SSH
// (src/core/network/socks5-proxy.ts), Xray does for its own outbound - so one
// SOCKS5 client reaches either of them and neither transport needs a second
// implementation of itself in Go.
//
// The endpoint is on loopback, which the TUN adapter does not own, so these
// connections cannot re-enter the dataplane.

const (
	socksVersion        = 0x05
	socksNoAuth         = 0x00
	socksCmdConnect     = 0x01
	socksCmdAssociate   = 0x03
	socksAddrIPv4       = 0x01
	socksAddrIPv6       = 0x04
	socksReplySucceeded = 0x00

	// A UDP association lives as long as its control connection. Datagram
	// sockets have no close handshake, so the TCP side is what tells the proxy
	// the association is over.
	socksHandshakeTimeout = 10 * time.Second
)

var errSocksUDPUnsupported = errors.New("proxy refused UDP ASSOCIATE")

// Socks5Client dials one loopback SOCKS5 inbound.
type Socks5Client struct {
	// Endpoint is the proxy's address, always on loopback.
	Endpoint netip.AddrPort
	// Dial reaches the proxy. It is injected so the dataplane can use a plain
	// loopback dialer while direct egress uses an interface-bound one.
	Dial func(ctx context.Context, network string, address string) (net.Conn, error)
}

func (c *Socks5Client) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

// DialTCP opens a tunnelled TCP connection to destination.
func (c *Socks5Client) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	conn, err := c.dial(ctx, "tcp", c.Endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if _, err := c.handshake(ctx, conn, socksCmdConnect, destination); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// AssociateUDP opens a UDP association and returns a session whose lifetime is
// bound to the returned control connection.
func (c *Socks5Client) AssociateUDP(ctx context.Context) (*Socks5UDPSession, error) {
	control, err := c.dial(ctx, "tcp", c.Endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	// RFC 1928: a client that does not know its own source address in advance
	// sends all zeroes, and the proxy must accept datagrams from any source it
	// has already authenticated.
	bound, err := c.handshake(ctx, control, socksCmdAssociate, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		control.Close()
		return nil, err
	}
	if !bound.IsValid() || bound.Port() == 0 {
		control.Close()
		return nil, errSocksUDPUnsupported
	}
	// A proxy is allowed to answer with the unspecified address, meaning "the
	// address you reached me on".
	if bound.Addr().IsUnspecified() {
		bound = netip.AddrPortFrom(c.Endpoint.Addr(), bound.Port())
	}
	if !bound.Addr().IsLoopback() {
		// A relay off loopback would be reached through the capture routes and
		// come straight back into this stack.
		control.Close()
		return nil, fmt.Errorf("proxy advertised a non-loopback UDP relay at %s", bound)
	}

	// Bound to loopback, not to every interface: the relay is a loopback
	// proxy, and a socket on 0.0.0.0 would let anything on the LAN that guesses
	// the ephemeral port inject datagrams into a tunnelled flow.
	packet, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("open udp socket: %w", err)
	}
	session := &Socks5UDPSession{control: control, packet: packet, relay: net.UDPAddrFromAddrPort(bound)}
	// The control connection carries no data after the reply, but its close is
	// the signal that ends the association, so it is watched rather than
	// forgotten.
	go session.watchControl()
	return session, nil
}

func (c *Socks5Client) handshake(ctx context.Context, conn net.Conn, command byte, destination netip.AddrPort) (netip.AddrPort, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(socksHandshakeTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.AddrPort{}, err
	}
	// Clearing the deadline is the caller's gain: a CONNECT tunnel must not
	// inherit the handshake timeout as an idle timeout.
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte{socksVersion, 1, socksNoAuth}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("read greeting: %w", err)
	}
	if greeting[0] != socksVersion || greeting[1] != socksNoAuth {
		return netip.AddrPort{}, fmt.Errorf("proxy rejected no-auth (version %#x, method %#x)", greeting[0], greeting[1])
	}

	request := append([]byte{socksVersion, command, 0x00}, encodeSocksAddress(destination)...)
	if _, err := conn.Write(request); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send request: %w", err)
	}

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("read reply: %w", err)
	}
	if header[0] != socksVersion {
		return netip.AddrPort{}, fmt.Errorf("unexpected proxy reply version %#x", header[0])
	}
	if header[1] != socksReplySucceeded {
		return netip.AddrPort{}, fmt.Errorf("proxy refused request (reply %#x)", header[1])
	}
	return readSocksAddress(conn, header[3])
}

func encodeSocksAddress(address netip.AddrPort) []byte {
	addr := address.Addr().Unmap()
	if addr.Is4() {
		octets := addr.As4()
		encoded := append([]byte{socksAddrIPv4}, octets[:]...)
		return binary.BigEndian.AppendUint16(encoded, address.Port())
	}
	octets := addr.As16()
	encoded := append([]byte{socksAddrIPv6}, octets[:]...)
	return binary.BigEndian.AppendUint16(encoded, address.Port())
}

func readSocksAddress(reader io.Reader, addressType byte) (netip.AddrPort, error) {
	var raw []byte
	switch addressType {
	case socksAddrIPv4:
		raw = make([]byte, 4+2)
	case socksAddrIPv6:
		raw = make([]byte, 16+2)
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return netip.AddrPort{}, err
		}
		raw = make([]byte, int(length[0])+2)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return netip.AddrPort{}, err
		}
		// A named bound address cannot be used as a datagram relay target and
		// is never sent for CONNECT by any proxy this client talks to.
		return netip.AddrPort{}, errors.New("proxy returned a named bound address")
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported proxy address type %#x", addressType)
	}
	if _, err := io.ReadFull(reader, raw); err != nil {
		return netip.AddrPort{}, err
	}
	addr, ok := netip.AddrFromSlice(raw[:len(raw)-2])
	if !ok {
		return netip.AddrPort{}, errors.New("proxy returned an unparsable bound address")
	}
	return netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(raw[len(raw)-2:])), nil
}

// Socks5UDPSession carries datagrams for one association.
type Socks5UDPSession struct {
	control net.Conn
	packet  *net.UDPConn
	relay   *net.UDPAddr
}

// WriteTo sends one datagram to destination through the association.
func (s *Socks5UDPSession) WriteTo(payload []byte, destination netip.AddrPort) error {
	header := append([]byte{0x00, 0x00, 0x00}, encodeSocksAddress(destination)...)
	_, err := s.packet.WriteToUDP(append(header, payload...), s.relay)
	return err
}

// ReadFrom returns the next datagram and the address it came from. The
// returned slice points into buffer and is valid until the next call.
func (s *Socks5UDPSession) ReadFrom(buffer []byte) ([]byte, netip.AddrPort, error) {
	for {
		read, from, err := s.packet.ReadFromUDP(buffer)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		// Only the relay may answer. The socket is connectionless, so without
		// this check anything that reaches the port can inject into the flow.
		if from == nil || !from.IP.Equal(s.relay.IP) || from.Port != s.relay.Port {
			continue
		}
		payload, source, ok := decodeSocksUDPDatagram(buffer[:read])
		if !ok {
			// A fragmented or malformed datagram is dropped rather than
			// surfaced: UDP is lossy by contract and the peer will retry.
			continue
		}
		return payload, source, nil
	}
}

// SetReadDeadline bounds a blocked ReadFrom.
func (s *Socks5UDPSession) SetReadDeadline(deadline time.Time) error {
	return s.packet.SetReadDeadline(deadline)
}

// Close ends the association.
func (s *Socks5UDPSession) Close() error {
	err := s.packet.Close()
	if controlErr := s.control.Close(); err == nil {
		err = controlErr
	}
	return err
}

func (s *Socks5UDPSession) watchControl() {
	// Any read on the control connection returns only when the proxy closes
	// it, which is exactly when the association stops being usable.
	var discard [1]byte
	_, _ = s.control.Read(discard[:])
	s.packet.Close()
}

func decodeSocksUDPDatagram(datagram []byte) ([]byte, netip.AddrPort, bool) {
	if len(datagram) < 4 || datagram[2] != 0x00 {
		return nil, netip.AddrPort{}, false // reserved bytes wrong, or a fragment
	}
	var addressLength int
	switch datagram[3] {
	case socksAddrIPv4:
		addressLength = 4
	case socksAddrIPv6:
		addressLength = 16
	default:
		return nil, netip.AddrPort{}, false
	}
	if len(datagram) < 4+addressLength+2 {
		return nil, netip.AddrPort{}, false
	}
	addr, ok := netip.AddrFromSlice(datagram[4 : 4+addressLength])
	if !ok {
		return nil, netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(datagram[4+addressLength : 4+addressLength+2])
	return datagram[4+addressLength+2:], netip.AddrPortFrom(addr.Unmap(), port), true
}
