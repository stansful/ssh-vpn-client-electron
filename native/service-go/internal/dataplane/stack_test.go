package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"

	"shadowssh/service/internal/routing"
)

// These tests stand an application in front of the dataplane the way the
// adapter does: a second userspace stack whose packets are piped into the
// dataplane's adapter, so handleTCP and handleUDP run exactly as they do on
// the machine, with the sniffing in between.

// pipeAdapter carries packets between the client stack and the dataplane.
type pipeAdapter struct {
	toDataplane chan []byte
	toClient    chan []byte
	closeOnce   sync.Once
	closed      chan struct{}
}

func newPipeAdapter() *pipeAdapter {
	return &pipeAdapter{
		toDataplane: make(chan []byte, 1024),
		toClient:    make(chan []byte, 1024),
		closed:      make(chan struct{}),
	}
}

func (a *pipeAdapter) ReceivePacket() ([]byte, error) {
	select {
	case packet := <-a.toDataplane:
		return packet, nil
	case <-a.closed:
		return nil, errors.New("adapter closed")
	}
}

func (a *pipeAdapter) SendPacket(packet []byte) error {
	select {
	case a.toClient <- append([]byte(nil), packet...):
		return nil
	case <-a.closed:
		return errors.New("adapter closed")
	}
}

func (a *pipeAdapter) Close() error {
	a.closeOnce.Do(func() { close(a.closed) })
	return nil
}

// clientStack is the "application side": a dual-stack host with one address
// per family whose packets all go to the adapter.
type clientStack struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	cancel   context.CancelFunc
}

func newClientStack(t *testing.T, adapter *pipeAdapter) *clientStack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	endpoint := channel.New(512, DefaultMTU, "")
	if err := s.CreateNIC(1, endpoint); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	for _, address := range []tcpip.ProtocolAddress{
		{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), PrefixLen: 24},
		},
		{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16(netip.MustParseAddr("fd00::2").As16()), PrefixLen: 64},
		},
	} {
		if err := s.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
			t.Fatalf("client address: %v", err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			packet := endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			select {
			case adapter.toDataplane <- data:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case packet := <-adapter.toClient:
				protocol, ok := ipVersion(packet)
				if !ok {
					continue
				}
				buffered := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
				endpoint.InjectInbound(protocol, buffered)
				buffered.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	return &clientStack{stack: s, endpoint: endpoint, cancel: cancel}
}

func (c *clientStack) dialTCP(t *testing.T, destination netip.AddrPort) net.Conn {
	t.Helper()
	conn, err := c.tryDialTCP(destination, 5*time.Second)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	return conn
}

// tryDialTCP is a connect() whose failure is the point of the test.
func (c *clientStack) tryDialTCP(destination netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	address, protocol := clientAddress(destination)
	return gonet.DialContextTCP(ctx, c.stack, address, protocol)
}

func clientAddress(destination netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	if destination.Addr().Is4() {
		return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(destination.Addr().As4()), Port: destination.Port()}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom16(destination.Addr().As16()), Port: destination.Port()}, ipv6.ProtocolNumber
}

func (c *clientStack) dialUDP(t *testing.T, destination netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	address, protocol := clientAddress(destination)
	conn, err := gonet.DialUDP(c.stack, nil, &address, protocol)
	if err != nil {
		t.Fatalf("client udp dial: %v", err)
	}
	return conn
}

func (c *clientStack) close() {
	c.cancel()
	c.endpoint.Close()
	c.stack.Close()
}

// recordingDialers stand in for the transport and the physical interface.
type recordingDialers struct {
	mu           sync.Mutex
	tunnelled    []netip.AddrPort
	direct       []netip.AddrPort
	associations int
	tunnelEnd    chan net.Conn
	directEnd    chan net.Conn
	udpDirect    chan *recordingPacketConn
}

func newRecordingDialers() *recordingDialers {
	return &recordingDialers{
		tunnelEnd: make(chan net.Conn, 16),
		directEnd: make(chan net.Conn, 16),
		udpDirect: make(chan *recordingPacketConn, 16),
	}
}

func (r *recordingDialers) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	r.mu.Lock()
	r.tunnelled = append(r.tunnelled, destination)
	r.mu.Unlock()
	ours, theirs := net.Pipe()
	r.tunnelEnd <- theirs
	return ours, nil
}

func (r *recordingDialers) AssociateUDP(ctx context.Context) (*Socks5UDPSession, error) {
	r.mu.Lock()
	r.associations++
	r.mu.Unlock()
	return nil, errors.New("no udp in this test")
}

type testDirectDialer struct{ r *recordingDialers }

func (d testDirectDialer) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	d.r.mu.Lock()
	d.r.direct = append(d.r.direct, destination)
	d.r.mu.Unlock()
	ours, theirs := net.Pipe()
	d.r.directEnd <- theirs
	return ours, nil
}

func (d testDirectDialer) ListenUDP(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error) {
	conn := &recordingPacketConn{written: make(chan []byte, 16), closed: make(chan struct{})}
	d.r.udpDirect <- conn
	return conn, nil
}

// recordingPacketConn records what the dataplane sends out directly.
type recordingPacketConn struct {
	written   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *recordingPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *recordingPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.written <- append([]byte(nil), payload...)
	return len(payload), nil
}

func (c *recordingPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func startTestDataplane(t *testing.T, cfg Config) (*clientStack, *recordingDialers, *DomainCache) {
	t.Helper()
	client, dialers, domains, _ := startTestDataplaneWithProbe(t, cfg, nil)
	return client, dialers, domains
}

func startTestDataplaneWithProbe(t *testing.T, cfg Config, probe func(context.Context) IPv6Reach) (*clientStack, *recordingDialers, *DomainCache, *Dataplane) {
	t.Helper()
	adapter := newPipeAdapter()
	dialers := newRecordingDialers()
	domains := NewDomainCache(0)
	dataplane, err := Start(Options{
		Adapter:         adapter,
		Tunnel:          dialers,
		Direct:          testDirectDialer{dialers},
		Policy:          NewPolicy(cfg),
		Domains:         domains,
		TunnelIPv6Probe: probe,
		Log:             func(level, message string) { t.Logf("%s: %s", level, message) },
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	client := newClientStack(t, adapter)
	t.Cleanup(func() {
		client.close()
		_ = dataplane.Close()
	})
	return client, dialers, domains, dataplane
}

func readWithin(t *testing.T, conn net.Conn, want int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	data := make([]byte, 0, want)
	chunk := make([]byte, 64*1024)
	for len(data) < want {
		read, err := conn.Read(chunk)
		if read > 0 {
			data = append(data, chunk[:read]...)
		}
		if err != nil {
			t.Fatalf("read: %v after %d of %d bytes", err, len(data), want)
		}
	}
	return data
}

func selectedRules() Config {
	return Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{{ID: "d", Type: routing.RuleDomain, Value: "example.org", Enabled: true}},
	}
}

func TestDataplaneRoutesTCPBySniffedServerName(t *testing.T) {
	client, dialers, domains := startTestDataplane(t, selectedRules())
	destination := netip.MustParseAddrPort("203.0.113.7:443")

	// A selected site, opened with no DNS answer seen: the ClientHello names it.
	conn := client.dialTCP(t, destination)
	hello := clientHelloFor(t, "www.example.org", tls.VersionTLS13)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	var remote net.Conn
	select {
	case remote = <-dialers.tunnelEnd:
	case <-dialers.directEnd:
		t.Fatal("selected site was dialled directly")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	if got := readWithin(t, remote, len(hello)); !bytes.Equal(got, hello) {
		t.Fatal("the hello did not arrive intact ahead of the relay")
	}
	// The relay carries both directions after the sniffed head.
	if _, err := remote.Write([]byte("server says hi")); err != nil {
		t.Fatal(err)
	}
	if got := readWithin(t, conn, len("server says hi")); string(got) != "server says hi" {
		t.Fatalf("client read %q", got)
	}
	if _, err := conn.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if got := readWithin(t, remote, 4); string(got) != "more" {
		t.Fatalf("remote read %q", got)
	}
	if names := domains.Lookup(destination.Addr()); len(names) != 1 || names[0] != "www.example.org" {
		t.Fatalf("sniffed name was not remembered: %v", names)
	}
	conn.Close()
	remote.Close()

	// An unselected site on another address goes out directly, hello and all.
	other := netip.MustParseAddrPort("203.0.113.8:443")
	conn = client.dialTCP(t, other)
	otherHello := clientHelloFor(t, "other.test", tls.VersionTLS13)
	if _, err := conn.Write(otherHello); err != nil {
		t.Fatal(err)
	}
	select {
	case remote = <-dialers.directEnd:
	case <-dialers.tunnelEnd:
		t.Fatal("unselected site was tunnelled")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	if got := readWithin(t, remote, len(otherHello)); !bytes.Equal(got, otherHello) {
		t.Fatal("the direct hello did not arrive intact")
	}
	conn.Close()
	remote.Close()
}

func TestDataplaneDoesNotHoldFlowsThatNeedNoName(t *testing.T) {
	client, dialers, _ := startTestDataplane(t, selectedRules())

	// A server-first protocol sends nothing: the flow is dialled after the
	// sniff window, not left waiting.
	started := time.Now()
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.9:22"))
	var remote net.Conn
	select {
	case remote = <-dialers.directEnd:
	case <-time.After(3 * time.Second):
		t.Fatal("silent flow was never dialled")
	}
	if waited := time.Since(started); waited < sniffTimeout/2 || waited > 2*time.Second {
		t.Fatalf("silent flow waited %v", waited)
	}
	// The expired sniff deadline must not have damaged the flow: both
	// directions still carry data afterwards.
	if _, err := remote.Write([]byte("SSH-2.0-server\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := readWithin(t, conn, len("SSH-2.0-server\r\n")); string(got) != "SSH-2.0-server\r\n" {
		t.Fatalf("client read %q", got)
	}
	if _, err := conn.Write([]byte("SSH-2.0-client\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := readWithin(t, remote, len("SSH-2.0-client\r\n")); string(got) != "SSH-2.0-client\r\n" {
		t.Fatalf("remote read %q", got)
	}
	remote.Close()
	conn.Close()

	// A client that speaks a protocol without a name is not held at all.
	started = time.Now()
	conn = client.dialTCP(t, netip.MustParseAddrPort("203.0.113.9:6667"))
	if _, err := conn.Write([]byte("NICK someone\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case remote := <-dialers.directEnd:
		if got := readWithin(t, remote, len("NICK someone\r\n")); string(got) != "NICK someone\r\n" {
			t.Fatalf("head lost: %q", got)
		}
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("flow was never dialled")
	}
	if waited := time.Since(started); waited > sniffTimeout {
		t.Fatalf("non-TLS flow waited %v", waited)
	}
	conn.Close()
}

func TestDataplaneRefusesQUICOfASniffedSelectedSite(t *testing.T) {
	client, dialers, domains := startTestDataplane(t, selectedRules())
	destination := netip.MustParseAddrPort("203.0.113.7:443")

	// The QUIC Initial names a selected site: on a transport without UDP the
	// datagram is refused, so the client falls back to TCP.
	hello := tlsHandshakeMessage(t, clientHelloFor(t, "www.example.org", tls.VersionTLS13))
	initial := sealInitial(t, quicVersion1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 0, cryptoFrame(0, hello), 1200)
	conn := client.dialUDP(t, destination)
	if _, err := conn.Write(initial); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialers.udpDirect:
		t.Fatal("a selected site's QUIC went out directly")
	case <-time.After(sniffTimeout * 3):
	}
	if names := domains.Lookup(destination.Addr()); len(names) != 1 || names[0] != "www.example.org" {
		t.Fatalf("sniffed QUIC name was not remembered: %v", names)
	}
	conn.Close()

	// An unselected site's QUIC goes out directly, first datagram included.
	other := netip.MustParseAddrPort("203.0.113.8:443")
	otherHello := tlsHandshakeMessage(t, clientHelloFor(t, "other.test", tls.VersionTLS13))
	otherInitial := sealInitial(t, quicVersion1, []byte{9, 9, 9, 9}, 0, cryptoFrame(0, otherHello), 1200)
	conn = client.dialUDP(t, other)
	if _, err := conn.Write(otherInitial); err != nil {
		t.Fatal(err)
	}
	select {
	case remote := <-dialers.udpDirect:
		select {
		case datagram := <-remote.written:
			if !bytes.Equal(datagram, otherInitial) {
				t.Fatal("the first datagram was not forwarded intact")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the first datagram was not forwarded")
		}
		// Later datagrams flow as before.
		if _, err := conn.Write([]byte("second")); err != nil {
			t.Fatal(err)
		}
		select {
		case datagram := <-remote.written:
			if string(datagram) != "second" {
				t.Fatalf("second datagram %q", datagram)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the second datagram was not forwarded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unselected QUIC was not dialled directly")
	}
	conn.Close()
}

func TestDataplaneSkipsSniffingWhenNamesCannotMatter(t *testing.T) {
	client, dialers, _ := startTestDataplane(t, Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{{ID: "p", Type: routing.RuleProcessName, Value: "app.exe", Enabled: true}},
	})
	started := time.Now()
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.9:22"))
	select {
	case remote := <-dialers.directEnd:
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("flow was never dialled")
	}
	if waited := time.Since(started); waited > sniffTimeout {
		t.Fatalf("a rule set without names held the flow for %v", waited)
	}
	conn.Close()
}

func TestDataplaneDoesNotHoldFlowsAlreadySelectedByAddress(t *testing.T) {
	client, dialers, _ := startTestDataplane(t, Config{
		Mode: routing.ModeSelectedRules,
		Rules: []routing.Rule{
			{ID: "d", Type: routing.RuleDomain, Value: "example.org", Enabled: true},
			{ID: "ip", Type: routing.RuleIP, Value: "203.0.113.0/24", Enabled: true},
		},
	})
	// Selected by its address: tunnelled at once, no wait for a hello.
	started := time.Now()
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.9:22"))
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-dialers.directEnd:
		t.Fatal("address-selected flow went direct")
	case <-time.After(3 * time.Second):
		t.Fatal("flow was never dialled")
	}
	if waited := time.Since(started); waited > sniffTimeout {
		t.Fatalf("address-selected flow waited %v", waited)
	}
	conn.Close()
}

func TestDataplaneJudgesEachFlowOnASharedAddressByItsOwnHello(t *testing.T) {
	client, dialers, domains := startTestDataplane(t, selectedRules())
	cdn := netip.MustParseAddrPort("203.0.113.7:443")
	open := func(serverName string) string {
		t.Helper()
		conn := client.dialTCP(t, cdn)
		defer conn.Close()
		if _, err := conn.Write(clientHelloFor(t, serverName, tls.VersionTLS13)); err != nil {
			t.Fatal(err)
		}
		select {
		case remote := <-dialers.tunnelEnd:
			remote.Close()
			return "tunnel"
		case remote := <-dialers.directEnd:
			remote.Close()
			return "direct"
		case <-time.After(3 * time.Second):
			t.Fatal("no dial")
			return ""
		}
	}
	// An unselected site first, then a selected one, on the same CDN address:
	// the second flow must be judged by its own hello, not by the name the
	// address was learned under a moment earlier.
	if egress := open("other.test"); egress != "direct" {
		t.Fatalf("unselected site: %s", egress)
	}
	if egress := open("www.example.org"); egress != "tunnel" {
		t.Fatalf("selected site after an unselected one on the same address: %s", egress)
	}
	if egress := open("other.test"); egress != "direct" {
		t.Fatalf("unselected site after a selected one on the same address: %s", egress)
	}
	// The address now remembers both, newest first.
	names := domains.Lookup(cdn.Addr())
	if len(names) != 2 || names[0] != "other.test" || names[1] != "www.example.org" {
		t.Fatalf("remembered names: %v", names)
	}
	// And the selected site is still selected after the unselected one was
	// seen last on the address.
	if egress := open("www.example.org"); egress != "tunnel" {
		t.Fatalf("selected site seen after an unselected one on the same address: %s", egress)
	}
	// A flow to that address with no hello of its own is tunnelled: one of
	// the names it is known under is selected, and the safe error is over-
	// inclusion, not a leak.
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.7:22"))
	defer conn.Close()
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-dialers.directEnd:
		t.Fatal("nameless flow to an address with a selected name went direct")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
}

func TestSniffTCPBoundsTheWorkForATricklingPeer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Single-byte TLS records, one byte per write, forever.
	go func() {
		for i := 0; i < 10_000; i++ {
			if _, err := client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}); err != nil {
				return
			}
		}
	}()
	started := time.Now()
	head, name := sniffTCP(server)
	if name != "" {
		t.Fatalf("got a name %q from garbage", name)
	}
	if len(head) == 0 {
		t.Fatal("nothing read")
	}
	if elapsed := time.Since(started); elapsed > 2*sniffTimeout {
		t.Fatalf("a trickling peer held the flow for %v", elapsed)
	}
}

// The report these pin: a dual-stack PC, a transport whose server has no IPv6,
// and every selected site with an IPv6 address failing outright. The server
// refused each IPv6 address, but the application had already been told the
// connection was up, so the browser never tried IPv4 and retried the dead
// address several times a second.

func TestDataplaneRefusesIPv6ThatWouldBeTunnelledWhileTheTunnelHasNone(t *testing.T) {
	client, dialers, _ := startTestDataplane(t, Config{Mode: routing.ModeProxyAll})

	// Refused before the handshake: that is what moves Happy Eyeballs on to
	// the site's IPv4 address.
	_, err := client.tryDialTCP(netip.MustParseAddrPort("[2001:db8::7]:443"), 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected the IPv6 connect to be refused, got %v", err)
	}
	// And IPv4 is tunnelled as before.
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.7:443"))
	defer conn.Close()
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("the IPv4 flow was never tunnelled")
	}
	dialers.mu.Lock()
	defer dialers.mu.Unlock()
	if len(dialers.tunnelled) != 1 || !dialers.tunnelled[0].Addr().Is4() {
		t.Fatalf("expected only the IPv4 flow to reach the transport, got %v", dialers.tunnelled)
	}
}

func TestDataplaneRefusesIPv6ANameCouldStillSelect(t *testing.T) {
	// The failing flows in the report were selected by the curated list, so
	// they were held for their hello - accepted before the name was known. A
	// browser's flow with nothing known about its address is refused up
	// front: by the time its name is known, refusing no longer helps.
	client, dialers, _ := startTestDataplane(t, Config{
		Mode:         routing.ModeSelectedRules,
		ProxyDomains: []string{"example.org"},
	})
	_, err := client.tryDialTCP(netip.MustParseAddrPort("[2001:db8::7]:443"), 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected the IPv6 connect to be refused, got %v", err)
	}
	select {
	case <-dialers.tunnelEnd:
		t.Fatal("a refused flow was dialled")
	case <-dialers.directEnd:
		t.Fatal("a refused flow was dialled")
	default:
	}
}

func TestDataplaneRefusesIPv6WhoseLearnedNameIsSelected(t *testing.T) {
	client, _, domains := startTestDataplane(t, Config{
		Mode:         routing.ModeSelectedRules,
		ProxyDomains: []string{"example.org"},
	})
	destination := netip.MustParseAddrPort("[2001:db8::7]:443")
	domains.Record([]dnsRecord{{Address: destination.Addr(), Names: []string{"www.example.org"}, TTL: time.Minute}})
	_, err := client.tryDialTCP(destination, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected the IPv6 connect to be refused, got %v", err)
	}
}

func TestDataplaneLetsUnselectedIPv6OutUnderNameRules(t *testing.T) {
	// Name rules hold almost every flow for its hello, but refusing all of
	// those broke what had worked: ssh to an IPv6-only host, DNS over TCP, an
	// unselected site whose DNS answer was seen.
	client, dialers, domains := startTestDataplane(t, Config{
		Mode:         routing.ModeSelectedRules,
		ProxyDomains: []string{"example.org"},
	})
	known := netip.MustParseAddrPort("[2001:db8::9]:443")
	domains.Record([]dnsRecord{{Address: known.Addr(), Names: []string{"ipv6only.example.net"}, TTL: time.Minute}})
	for _, destination := range []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::9]:22"),
		netip.MustParseAddrPort("[2001:db8::53]:53"),
		known,
	} {
		conn, err := client.tryDialTCP(destination, 3*time.Second)
		if err != nil {
			t.Fatalf("%s: an unselected IPv6 flow was refused: %v", destination, err)
		}
		select {
		case remote := <-dialers.directEnd:
			remote.Close()
		case <-dialers.tunnelEnd:
			t.Fatalf("%s: an unselected flow was tunnelled", destination)
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the flow was never dialled", destination)
		}
		conn.Close()
	}
}

func TestDataplaneLeavesIPv6ThatCannotBeTunnelledAlone(t *testing.T) {
	// Only a process rule: an unattributed flow is going out directly whatever
	// it carries, so its IPv6 works as it did before the tunnel came up.
	client, dialers, _ := startTestDataplane(t, Config{
		Mode:  routing.ModeSelectedRules,
		Rules: []routing.Rule{{ID: "p", Type: routing.RuleProcessName, Value: "app.exe", Enabled: true}},
	})
	conn := client.dialTCP(t, netip.MustParseAddrPort("[2001:db8::7]:443"))
	defer conn.Close()
	select {
	case remote := <-dialers.directEnd:
		remote.Close()
	case <-dialers.tunnelEnd:
		t.Fatal("an unselected flow was tunnelled")
	case <-time.After(3 * time.Second):
		t.Fatal("the direct IPv6 flow was never dialled")
	}
}

func TestDataplaneTunnelsIPv6OnceTheTunnelReachesIt(t *testing.T) {
	previous := ipv6ProbeRetry
	ipv6ProbeRetry = 10 * time.Millisecond
	t.Cleanup(func() { ipv6ProbeRetry = previous })
	client, dialers, _, dataplane := startTestDataplaneWithProbe(t, Config{Mode: routing.ModeProxyAll},
		func(context.Context) IPv6Reach { return IPv6Reachable })
	deadline := time.Now().Add(3 * time.Second)
	for !dataplane.TunnelReachesIPv6() {
		if time.Now().After(deadline) {
			t.Fatal("the probe's answer was never taken")
		}
		time.Sleep(10 * time.Millisecond)
	}
	destination := netip.MustParseAddrPort("[2001:db8::7]:443")
	conn := client.dialTCP(t, destination)
	defer conn.Close()
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("the IPv6 flow was never tunnelled")
	}
	dialers.mu.Lock()
	defer dialers.mu.Unlock()
	if len(dialers.tunnelled) != 1 || dialers.tunnelled[0] != destination {
		t.Fatalf("expected the IPv6 flow to be tunnelled by its address, got %v", dialers.tunnelled)
	}
}

func TestDataplaneDropsTunnelledIPv6DatagramsWhileTheTunnelHasNone(t *testing.T) {
	// Xray carries UDP, but not to IPv6 from a server without it. QUIC that
	// gets no answer falls back to TCP, which is then refused onto IPv4.
	client, dialers, _ := startTestDataplane(t, Config{Mode: routing.ModeProxyAll, UDPSupported: true})
	conn := client.dialUDP(t, netip.MustParseAddrPort("[2001:db8::7]:443"))
	defer conn.Close()
	if _, err := conn.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialers.udpDirect:
		t.Fatal("a selected IPv6 datagram went out directly")
	case <-time.After(sniffTimeout * 3):
	}
	dialers.mu.Lock()
	defer dialers.mu.Unlock()
	if dialers.associations != 0 {
		t.Fatalf("an IPv6 datagram was handed to a tunnel that cannot carry it")
	}
}
