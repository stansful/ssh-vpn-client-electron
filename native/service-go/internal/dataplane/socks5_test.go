package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// startFakeSocks5 accepts one connection, performs the handshake, and reports
// what the client asked for. It is deliberately strict about the wire format,
// because a proxy that is merely lenient would hide an encoding mistake here
// until it met Xray.
func startFakeSocks5(t *testing.T, reply func(command byte, destination netip.AddrPort) (byte, netip.AddrPort)) (netip.AddrPort, <-chan socksRequest) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	requests := make(chan socksRequest, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		greeting := make([]byte, 2)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		methods := make([]byte, greeting[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{socksVersion, socksNoAuth}); err != nil {
			return
		}

		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		var raw []byte
		switch header[3] {
		case socksAddrIPv4:
			raw = make([]byte, 6)
		case socksAddrIPv6:
			raw = make([]byte, 18)
		case socksAddrDomain:
			length := make([]byte, 1)
			if _, err := io.ReadFull(conn, length); err != nil {
				return
			}
			raw = make([]byte, int(length[0])+2)
		default:
			return
		}
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		request := socksRequest{Version: header[0], Command: header[1], AddressType: header[3]}
		port := binary.BigEndian.Uint16(raw[len(raw)-2:])
		if header[3] == socksAddrDomain {
			request.Name = string(raw[:len(raw)-2])
			request.Destination = netip.AddrPortFrom(netip.Addr{}, port)
		} else {
			address, _ := netip.AddrFromSlice(raw[:len(raw)-2])
			request.Destination = netip.AddrPortFrom(address.Unmap(), port)
		}
		requests <- request

		status, bound := reply(header[1], request.Destination)
		response := append([]byte{socksVersion, status, 0x00}, encodeSocksAddress(bound)...)
		if _, err := conn.Write(response); err != nil {
			return
		}
		// Hold the connection open so a UDP association stays alive for the
		// duration of the test.
		io.Copy(io.Discard, conn)
	}()

	return netip.MustParseAddrPort(listener.Addr().String()), requests
}

type socksRequest struct {
	Version     byte
	Command     byte
	AddressType byte
	// Destination is the requested address, or only its port when the
	// request named a host.
	Destination netip.AddrPort
	Name        string
}

func TestDialTCPSendsAConnectRequest(t *testing.T) {
	endpoint, requests := startFakeSocks5(t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return socksReplySucceeded, netip.MustParseAddrPort("0.0.0.0:0")
	})
	client := &Socks5Client{Endpoint: endpoint}

	destination := netip.MustParseAddrPort("149.154.167.51:443")
	conn, err := client.DialTCP(context.Background(), destination, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case request := <-requests:
		if request.Version != socksVersion || request.Command != socksCmdConnect {
			t.Fatalf("expected a SOCKS5 CONNECT, got %+v", request)
		}
		if request.AddressType != socksAddrIPv4 || request.Destination != destination {
			t.Fatalf("expected %s by address, got %+v", destination, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the proxy never saw a request")
	}

	// The handshake deadline must not survive as an idle timeout on the tunnel.
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
}

func TestDialTCPAsksTheProxyForTheNameWhenOneIsGiven(t *testing.T) {
	// The address came from the local resolver, which may have been poisoned
	// for a blocked site. With the name the far end resolves it itself.
	endpoint, requests := startFakeSocks5(t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return socksReplySucceeded, netip.MustParseAddrPort("0.0.0.0:0")
	})
	client := &Socks5Client{Endpoint: endpoint}
	conn, err := client.DialTCP(context.Background(), netip.MustParseAddrPort("10.10.34.35:443"), "blocked.example.org")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	select {
	case request := <-requests:
		if request.Command != socksCmdConnect || request.AddressType != socksAddrDomain {
			t.Fatalf("expected a CONNECT by name, got %+v", request)
		}
		if request.Name != "blocked.example.org" || request.Destination.Port() != 443 {
			t.Fatalf("expected blocked.example.org:443, got %q:%d", request.Name, request.Destination.Port())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the proxy never saw a request")
	}
}

func TestEncodeSocksDomainRefusesWhatIsNotAHostName(t *testing.T) {
	for _, name := range []string{"", "203.0.113.7", "2001:db8::7", strings.Repeat("a", 256)} {
		if _, ok := encodeSocksDomain(name, 443); ok {
			t.Fatalf("expected %q to be sent as an address", name)
		}
	}
	encoded, ok := encodeSocksDomain("example.org", 8443)
	want := append([]byte{socksAddrDomain, byte(len("example.org"))}, "example.org"...)
	want = append(want, 0x20, 0xfb)
	if !ok || !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %x, want %x", encoded, want)
	}
}

func TestDialTCPReportsARefusedRequest(t *testing.T) {
	endpoint, _ := startFakeSocks5(t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return 0x05, netip.MustParseAddrPort("0.0.0.0:0") // connection refused
	})
	client := &Socks5Client{Endpoint: endpoint}
	if _, err := client.DialTCP(context.Background(), netip.MustParseAddrPort("1.1.1.1:443"), ""); err == nil {
		t.Fatalf("expected a refused request to fail")
	}
}

func TestAssociateUDPRejectsAProxyWithoutARelayPort(t *testing.T) {
	// The SSH transport's proxy answers CONNECT only. Detecting that here is
	// what lets the caller fall back to dropping datagrams instead of silently
	// sending them nowhere.
	endpoint, _ := startFakeSocks5(t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return socksReplySucceeded, netip.MustParseAddrPort("0.0.0.0:0")
	})
	client := &Socks5Client{Endpoint: endpoint}
	if _, err := client.AssociateUDP(context.Background()); err == nil {
		t.Fatalf("expected an association without a relay port to fail")
	}
}

func TestUDPDatagramRoundTrip(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer relay.Close()
	relayPort := uint16(relay.LocalAddr().(*net.UDPAddr).Port)

	endpoint, requests := startFakeSocks5(t, func(command byte, _ netip.AddrPort) (byte, netip.AddrPort) {
		if command != socksCmdAssociate {
			return 0x07, netip.AddrPort{}
		}
		return socksReplySucceeded, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relayPort)
	})

	client := &Socks5Client{Endpoint: endpoint}
	session, err := client.AssociateUDP(context.Background())
	if err != nil {
		t.Fatalf("associate: %v", err)
	}
	defer session.Close()
	<-requests

	destination := netip.MustParseAddrPort("8.8.8.8:53")
	if err := session.WriteTo([]byte("query"), destination); err != nil {
		t.Fatalf("write: %v", err)
	}

	incoming := make([]byte, 1024)
	if err := relay.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	read, from, err := relay.ReadFromUDP(incoming)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	payload, wrapped, ok := decodeSocksUDPDatagram(incoming[:read])
	if !ok {
		t.Fatalf("relay received a datagram it could not decode")
	}
	if string(payload) != "query" || wrapped != destination {
		t.Fatalf("expected the payload addressed to %s, got %q to %s", destination, payload, wrapped)
	}

	// Answer through the relay and confirm the header is stripped again.
	answer := append([]byte{0x00, 0x00, 0x00}, encodeSocksAddress(destination)...)
	if _, err := relay.WriteToUDP(append(answer, []byte("reply")...), from); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	if err := session.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 1024)
	received, source, err := session.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("session read: %v", err)
	}
	if string(received) != "reply" || source != destination {
		t.Fatalf("expected \"reply\" from %s, got %q from %s", destination, received, source)
	}
}

func TestDecodeSocksUDPDatagramRejectsFragments(t *testing.T) {
	fragment := append([]byte{0x00, 0x00, 0x01, socksAddrIPv4, 1, 2, 3, 4, 0x00, 0x35}, []byte("x")...)
	if _, _, ok := decodeSocksUDPDatagram(fragment); ok {
		t.Fatalf("expected a fragmented datagram to be rejected")
	}
}

func TestUDPSessionDropsADatagramTheRelayCannotTake(t *testing.T) {
	// Xray's relay reads into 8 KiB; on Windows a larger datagram ends its
	// receive loop for every association. It is refused here instead, and
	// the association carries on.
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer relay.Close()
	relayPort := uint16(relay.LocalAddr().(*net.UDPAddr).Port)
	endpoint, requests := startFakeSocks5(t, func(byte, netip.AddrPort) (byte, netip.AddrPort) {
		return socksReplySucceeded, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relayPort)
	})
	session, err := (&Socks5Client{Endpoint: endpoint}).AssociateUDP(context.Background())
	if err != nil {
		t.Fatalf("associate: %v", err)
	}
	defer session.Close()
	<-requests

	destination := netip.MustParseAddrPort("[2001:db8::7]:19305")
	if err := session.WriteTo(make([]byte, 9000), destination); !errors.Is(err, errSocksUDPTooLarge) {
		t.Fatalf("expected an oversized datagram to be refused, got %v", err)
	}
	// The largest datagram that fits still goes.
	fits := make([]byte, socksUDPMaxDatagram-len(encodeSocksAddress(destination))-3)
	if err := session.WriteTo(fits, destination); err != nil {
		t.Fatalf("a datagram that fits was refused: %v", err)
	}
	if err := relay.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	incoming := make([]byte, 64*1024)
	read, _, err := relay.ReadFromUDP(incoming)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if read != socksUDPMaxDatagram {
		t.Fatalf("the relay received %d bytes, expected the %d-byte datagram that fits", read, socksUDPMaxDatagram)
	}
}
