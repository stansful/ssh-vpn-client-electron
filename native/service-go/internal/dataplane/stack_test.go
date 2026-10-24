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
	mu        sync.Mutex
	tunnelled []netip.AddrPort
	// tunnelNames are the names the tunnel was asked for, one per tunnelled
	// dial, "" for a dial by address.
	tunnelNames  []string
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

func (r *recordingDialers) DialTCP(ctx context.Context, destination netip.AddrPort, name string) (net.Conn, error) {
	r.mu.Lock()
	r.tunnelled = append(r.tunnelled, destination)
	r.tunnelNames = append(r.tunnelNames, name)
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
	// The tunnel was asked for the name the hello carried, so the far end
	// resolves it rather than following the local resolver's answer.
	dialers.mu.Lock()
	if len(dialers.tunnelNames) != 1 || dialers.tunnelNames[0] != "www.example.org" || dialers.tunnelled[0] != destination {
		t.Fatalf("expected a dial by name for %s, got %v %v", destination, dialers.tunnelNames, dialers.tunnelled)
	}
	dialers.mu.Unlock()
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
	// Nothing named it, so it is dialled by its address.
	dialers.mu.Lock()
	if len(dialers.tunnelNames) != 1 || dialers.tunnelNames[0] != "" {
		t.Fatalf("expected a dial by address, got names %q", dialers.tunnelNames)
	}
	dialers.mu.Unlock()
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

// openTLS opens a flow to destination that sends a ClientHello for
// serverName, and reports which way it was dialled.
func openTLS(t *testing.T, client *clientStack, dialers *recordingDialers, destination netip.AddrPort, serverName string) string {
	t.Helper()
	conn := client.dialTCP(t, destination)
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

func TestFullTunnelSendsDirectListSitesDirect(t *testing.T) {
	// Full tunnel used to ignore the "Russian services" list on TUN while the
	// PAC honoured it. The flow's own name is what places it on the list.
	client, dialers, _ := startTestDataplane(t, Config{
		Mode:          routing.ModeProxyAll,
		DirectDomains: []string{".ru", "yandex.example"},
		ProxyDomains:  []string{"blocked.example"},
	})
	destination := netip.MustParseAddrPort("203.0.113.7:443")
	if egress := openTLS(t, client, dialers, destination, "www.gosuslugi.ru"); egress != "direct" {
		t.Fatalf("a direct-list site went %s", egress)
	}
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.8:443"), "music.yandex.example"); egress != "direct" {
		t.Fatalf("a direct-list site went %s", egress)
	}
	// A blocked site is dialled by its name, so a poisoned local answer is not
	// followed; any other name - possibly borrowed, as REALITY and fake-TLS
	// clients do - keeps the address the application chose.
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.9:443"), "www.blocked.example"); egress != "tunnel" {
		t.Fatalf("a blocked site went %s", egress)
	}
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.11:443"), "www.example.org"); egress != "tunnel" {
		t.Fatalf("another site went %s", egress)
	}
	dialers.mu.Lock()
	if len(dialers.tunnelNames) != 2 || dialers.tunnelNames[0] != "www.blocked.example" || dialers.tunnelNames[1] != "" {
		t.Fatalf("expected only the blocked site to be dialled by name, got %q", dialers.tunnelNames)
	}
	dialers.mu.Unlock()

	// A flow that names nothing is still tunnelled, by address, once the
	// sniff window has passed.
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.10:22"))
	defer conn.Close()
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-dialers.directEnd:
		t.Fatal("a nameless flow left full tunnel")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	dialers.mu.Lock()
	defer dialers.mu.Unlock()
	if last := dialers.tunnelNames[len(dialers.tunnelNames)-1]; last != "" {
		t.Fatalf("a nameless flow was dialled by name %q", last)
	}
}

func TestFullTunnelWithoutADirectListDoesNotHoldFlows(t *testing.T) {
	client, dialers, _ := startTestDataplane(t, Config{Mode: routing.ModeProxyAll})
	started := time.Now()
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.10:22"))
	defer conn.Close()
	select {
	case remote := <-dialers.tunnelEnd:
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	if waited := time.Since(started); waited > sniffTimeout {
		t.Fatalf("full tunnel without a direct list held a flow for %v", waited)
	}
}

func TestDataplaneSendsPrivateDestinationsDirect(t *testing.T) {
	// A private range that is not on-link is taken by the capture routes;
	// full tunnel must not carry it to the remote server.
	client, dialers, _ := startTestDataplane(t, Config{Mode: routing.ModeProxyAll})
	conn := client.dialTCP(t, netip.MustParseAddrPort("10.20.30.40:445"))
	defer conn.Close()
	select {
	case remote := <-dialers.directEnd:
		remote.Close()
	case <-dialers.tunnelEnd:
		t.Fatal("a private destination was tunnelled")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
}

func TestADomainRuleTunnelsAHostBehindTheServerOnANonWebPort(t *testing.T) {
	// https://pve.home.example:8006, its private address resolved where the
	// dataplane could not see it: the hello names the host the domain rule
	// claims, ahead of the local network, in either mode.
	for _, mode := range []routing.Mode{routing.ModeSelectedRules, routing.ModeProxyAll} {
		client, dialers, _ := startTestDataplane(t, Config{
			Mode:  mode,
			Rules: []routing.Rule{{ID: "d1", Type: routing.RuleDomain, Value: "home.example", Enabled: true}},
		})
		if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("10.8.0.5:8006"), "pve.home.example"); egress != "tunnel" {
			t.Fatalf("%s: a host behind the server on 8006 went %s", mode, egress)
		}
		// A server-speaks-first LAN flow is not held for a name it never sends.
		// (Another address: the name just read now describes 10.8.0.5, and
		// selects every later flow to it.)
		started := time.Now()
		conn := client.dialTCP(t, netip.MustParseAddrPort("10.8.0.6:3306"))
		select {
		case remote := <-dialers.directEnd:
			remote.Close()
		case <-dialers.tunnelEnd:
			t.Fatalf("%s: a nameless LAN flow was tunnelled", mode)
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: no dial", mode)
		}
		if waited := time.Since(started); waited > sniffTimeout {
			t.Fatalf("%s: a server-speaks-first LAN flow was held for %v", mode, waited)
		}
		conn.Close()
	}
}

func TestFullTunnelSendsASingleLabelSiteDirect(t *testing.T) {
	// http://printer/, resolved by a DNS suffix search to an address outside
	// the private ranges: the system-proxy paths send a single-label name
	// direct, and so must TUN, which only learns the name from the request.
	client, dialers, domains := startTestDataplane(t, Config{Mode: routing.ModeProxyAll})
	destination := netip.MustParseAddrPort("192.0.2.20:80")
	conn := client.dialTCP(t, destination)
	defer conn.Close()
	request := []byte("GET / HTTP/1.1\r\nHost: printer\r\n\r\n")
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case remote := <-dialers.directEnd:
		if got := readWithin(t, remote, len(request)); !bytes.Equal(got, request) {
			t.Fatalf("the request was not forwarded intact: %q", got)
		}
		remote.Close()
	case <-dialers.tunnelEnd:
		t.Fatal("a single-label site was tunnelled")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	// The name describes that flow only; later flows to the address are not
	// judged by it.
	if names := domains.Lookup(destination.Addr()); len(names) != 0 {
		t.Fatalf("a single-label name was remembered for the address: %v", names)
	}
	// A dotted name on the same kind of address stays in the tunnel.
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("192.0.2.21:443"), "www.example.org"); egress != "tunnel" {
		t.Fatalf("a public site went %s", egress)
	}
}

func TestBlockedSitesAreDialledByNameWhateverTunnelsThem(t *testing.T) {
	// A poisoned local answer sends the browser to a stub address. Full
	// tunnel without the direct list, and a process rule's own flows, used to
	// skip reading the name and followed the stub through the tunnel.
	client, dialers, _ := startTestDataplane(t, Config{Mode: routing.ModeProxyAll, ProxyDomains: []string{"blocked.example"}})
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.9:443"), "www.blocked.example"); egress != "tunnel" {
		t.Fatalf("full tunnel: a blocked site went %s", egress)
	}
	dialers.mu.Lock()
	if len(dialers.tunnelNames) != 1 || dialers.tunnelNames[0] != "www.blocked.example" {
		t.Fatalf("full tunnel: expected a dial by name, got %q", dialers.tunnelNames)
	}
	dialers.mu.Unlock()

	chrome := &countingAttributor{name: "chrome.exe"}
	client, dialers = startAttributedDataplane(t, Config{
		Mode:         routing.ModeSelectedRules,
		Rules:        []routing.Rule{processRule("p", "chrome.exe")},
		ProxyDomains: []string{"blocked.example"},
	}, chrome)
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.9:443"), "www.blocked.example"); egress != "tunnel" {
		t.Fatalf("process rule: a blocked site went %s", egress)
	}
	if egress := openTLS(t, client, dialers, netip.MustParseAddrPort("203.0.113.10:443"), "www.example.org"); egress != "tunnel" {
		t.Fatalf("process rule: another site went %s", egress)
	}
	dialers.mu.Lock()
	defer dialers.mu.Unlock()
	if len(dialers.tunnelNames) != 2 || dialers.tunnelNames[0] != "www.blocked.example" || dialers.tunnelNames[1] != "" {
		t.Fatalf("process rule: expected only the blocked site to be dialled by name, got %q", dialers.tunnelNames)
	}
}

func TestRequestsToAnHTTPProxyAreDialledToTheProxy(t *testing.T) {
	// An application with its own plain-HTTP proxy at a public address names
	// the site it wants inside the request. That name may route the flow, but
	// dialled by it the flow would reach the site on the proxy's port and
	// never the proxy.
	split := Config{Mode: routing.ModeSelectedRules, ProxyDomains: []string{"youtube.com"}}
	full := Config{Mode: routing.ModeProxyAll, ProxyDomains: []string{"youtube.com"}}
	for _, test := range []struct {
		label       string
		cfg         Config
		destination string
		request     string
		dialName    string
	}{
		{"connect", split, "203.0.113.5:3128", "CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n", ""},
		{"absolute-form", split, "203.0.113.5:8080", "GET http://www.youtube.com/x HTTP/1.1\r\n\r\n", ""},
		{"absolute-form with a host", split, "203.0.113.5:8080", "GET http://www.youtube.com/x HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n", ""},
		{"full tunnel connect", full, "203.0.113.5:80", "CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n", ""},
		// A request to the site itself is still dialled by the name it carries.
		{"origin-form", split, "203.0.113.6:80", "GET /x HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n", "www.youtube.com"},
		{"full tunnel origin-form", full, "203.0.113.6:80", "GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n", "www.youtube.com"},
	} {
		t.Run(test.label, func(t *testing.T) {
			client, dialers, _ := startTestDataplane(t, test.cfg)
			destination := netip.MustParseAddrPort(test.destination)
			conn := client.dialTCP(t, destination)
			defer conn.Close()
			request := []byte(test.request)
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
			select {
			case remote := <-dialers.tunnelEnd:
				if got := readWithin(t, remote, len(request)); !bytes.Equal(got, request) {
					t.Fatalf("the request was not forwarded intact: %q", got)
				}
				remote.Close()
			case <-dialers.directEnd:
				t.Fatal("a request for a listed site went direct")
			case <-time.After(3 * time.Second):
				t.Fatal("no dial")
			}
			dialers.mu.Lock()
			defer dialers.mu.Unlock()
			if len(dialers.tunnelled) != 1 || dialers.tunnelled[0] != destination {
				t.Fatalf("tunnelled to %v, want %v", dialers.tunnelled, destination)
			}
			if dialers.tunnelNames[0] != test.dialName {
				t.Fatalf("dialled by name %q, want %q", dialers.tunnelNames[0], test.dialName)
			}
		})
	}
}

// countingAttributor names one owner for every socket and counts the lookups.
type countingAttributor struct {
	mu      sync.Mutex
	name    string
	pid     uint32
	lookups int
}

func (a *countingAttributor) Process(Protocol, netip.AddrPort) SocketOwner {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lookups++
	return SocketOwner{Name: a.name, PID: a.pid}
}

func (a *countingAttributor) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lookups
}

func startAttributedDataplane(t *testing.T, cfg Config, attribution Attributor) (*clientStack, *recordingDialers) {
	t.Helper()
	adapter := newPipeAdapter()
	dialers := newRecordingDialers()
	plane, err := Start(Options{
		Adapter:     adapter,
		Attribution: attribution,
		Tunnel:      dialers,
		Direct:      testDirectDialer{dialers},
		Policy:      NewPolicy(cfg),
		Log:         func(level, message string) { t.Logf("%s: %s", level, message) },
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	client := newClientStack(t, adapter)
	t.Cleanup(func() {
		client.close()
		_ = plane.Close()
	})
	return client, dialers
}

func TestTheTransportsOwnProcessIsNeverTunnelled(t *testing.T) {
	// Xray behind a CDN dials a server address the host routes do not cover.
	// In full tunnel that dial was captured and proxied into Xray's own inbound.
	transport := []ProcessIdentity{{PID: 4242, Name: "xray.exe"}}
	xray := &countingAttributor{name: "xray.exe", pid: 4242}
	client, dialers := startAttributedDataplane(t, Config{
		Mode:            routing.ModeProxyAll,
		DirectProcesses: transport,
	}, xray)
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.77:443"))
	defer conn.Close()
	select {
	case remote := <-dialers.directEnd:
		remote.Close()
	case <-dialers.tunnelEnd:
		t.Fatal("the transport's own dial was tunnelled")
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	if xray.count() != 1 {
		t.Fatalf("expected one owner lookup, got %d", xray.count())
	}

	// Any other process is tunnelled as before, another program called
	// xray.exe included.
	for _, other := range []*countingAttributor{
		{name: "chrome.exe", pid: 1001},
		{name: "xray.exe", pid: 777},
	} {
		client, dialers = startAttributedDataplane(t, Config{
			Mode:            routing.ModeProxyAll,
			DirectProcesses: transport,
		}, other)
		conn = client.dialTCP(t, netip.MustParseAddrPort("203.0.113.77:443"))
		defer conn.Close()
		select {
		case remote := <-dialers.tunnelEnd:
			remote.Close()
		case <-dialers.directEnd:
			t.Fatalf("a flow of %s (%d) went direct", other.name, other.pid)
		case <-time.After(3 * time.Second):
			t.Fatal("no dial")
		}
	}
}

func TestOwnerIsNotLookedUpForAFlowItCannotChange(t *testing.T) {
	// Only the transport's process is listed, and this flow goes direct
	// anyway: reading the owner tables would only cost time.
	attribution := &countingAttributor{name: "xray.exe", pid: 4242}
	client, dialers := startAttributedDataplane(t, Config{
		Mode:            routing.ModeSelectedRules,
		Rules:           []routing.Rule{{ID: "ip", Type: routing.RuleIP, Value: "198.51.100.0/24", Enabled: true}},
		DirectProcesses: []ProcessIdentity{{PID: 4242, Name: "xray.exe"}},
	}, attribution)
	conn := client.dialTCP(t, netip.MustParseAddrPort("203.0.113.77:22"))
	defer conn.Close()
	select {
	case remote := <-dialers.directEnd:
		remote.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	if attribution.count() != 0 {
		t.Fatalf("the owner was looked up %d times for a flow it could not change", attribution.count())
	}
}
