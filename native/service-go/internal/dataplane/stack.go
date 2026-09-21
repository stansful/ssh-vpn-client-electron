package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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
	"github.com/sagernet/gvisor/pkg/waiter"
)

// A TUN adapter delivers IP packets, not connections, so something has to
// terminate TCP and UDP before a policy decision can be made per flow. That is
// what this file does: it runs gVisor's userspace network stack over the
// adapter, and hands every accepted flow to the policy, then to the transport
// or to the physical interface.
//
// Hand-rolling TCP instead is not a reasonable alternative, and the stack used
// here is the same one sing-box and Xray use for the same purpose.

const (
	// DefaultMTU matches what the adapter is configured with. 1420 leaves room
	// for the transport's own framing inside a 1500-byte path.
	DefaultMTU = 1420
	// nicID is the single NIC the adapter is attached to.
	nicID = tcpip.NICID(1)
	// tcpReceiveWindow and tcpMaxInFlight bound the forwarder's pending
	// handshakes. The defaults are what a desktop client needs; a server would
	// want more.
	tcpReceiveWindow = 0 // zero selects the stack default, which is auto-tuned
	tcpMaxInFlight   = 2048
	// udpSessionIdleTimeout closes a datagram flow that has gone quiet. UDP has
	// no close, so an idle bound is the only way a flow is ever reclaimed.
	udpSessionIdleTimeout = 90 * time.Second
	// dnsTimeout bounds one forwarded DNS exchange.
	dnsTimeout = 5 * time.Second
	// dialTimeout bounds one upstream connection attempt.
	dialTimeout = 15 * time.Second
	// sniffTimeout bounds how long a flow whose name is not yet known is held
	// back for a look at its first bytes (see sniff.go). A client that speaks
	// first - every TLS and HTTP client - has sent them within a round trip
	// of the loopback handshake, so the wait is only ever paid in full by a
	// flow whose server speaks first, and only when a rule could depend on
	// the name.
	sniffTimeout = 250 * time.Millisecond
	// sniffMaxReads bounds how many reads one sniff makes. A hello arrives in
	// a handful of segments; a peer trickling single bytes would otherwise
	// have the parser re-run once per byte for the whole window.
	sniffMaxReads = 32
	// sniffedNameTTL is how long a name read from a flow's first bytes keeps
	// describing the address it was sent to, so that a later flow to the same
	// address without a hello of its own - a QUIC attempt above all - is
	// judged by the same rule.
	sniffedNameTTL = 10 * time.Minute
	// relayBufferBytes is the copy buffer for one direction of one TCP flow.
	relayBufferBytes = 32 * 1024
	// udpDatagramMaxBytes bounds one datagram read.
	udpDatagramMaxBytes = 64 * 1024
)

// Adapter is the packet source and sink. internal/tun.Adapter satisfies it.
type Adapter interface {
	ReceivePacket() ([]byte, error)
	SendPacket(packet []byte) error
	Close() error
}

// Attributor resolves the process that owns a local socket. An empty answer
// means "unknown", which the policy treats as "no process rule matched"
// rather than as an error: an unattributable flow must still be routed.
type Attributor interface {
	Owner(protocol Protocol, local netip.AddrPort) string
}

// TunnelDialer reaches the active transport.
type TunnelDialer interface {
	DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error)
	AssociateUDP(ctx context.Context) (*Socks5UDPSession, error)
}

// DirectDialer reaches the network through the physical interface. It must
// pin the egress interface explicitly: the TUN adapter owns the default route
// while the dataplane is up, so an unpinned socket would loop straight back
// into this stack.
type DirectDialer interface {
	DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error)
	// ListenUDP takes the destination so the socket can be opened in the right
	// address family and pinned to the interface that reaches it.
	ListenUDP(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error)
}

// Options configures a dataplane.
type Options struct {
	Adapter     Adapter
	Attribution Attributor
	Tunnel      TunnelDialer
	Direct      DirectDialer
	Policy      *Policy
	Domains     *DomainCache
	MTU         uint32
	// Log receives one line per notable event. Levels are "info" and
	// "warning", matching the service's diagnostics vocabulary.
	Log func(level string, message string)
}

// Dataplane owns the userspace stack and every flow running through it.
type Dataplane struct {
	options  Options
	stack    *stack.Stack
	endpoint *channel.Endpoint
	policy   atomic.Pointer[Policy]
	cancel   context.CancelFunc
	done     sync.WaitGroup
	closeOne sync.Once
	closeErr error
}

// Start brings the stack up and begins forwarding. The returned Dataplane runs
// until Close.
//
// On success the Dataplane owns the adapter and closes it in Close; on failure
// the adapter is untouched and the caller still owns it.
func Start(options Options) (*Dataplane, error) {
	if options.Adapter == nil {
		return nil, errors.New("dataplane requires an adapter")
	}
	if options.Policy == nil {
		return nil, errors.New("dataplane requires a policy")
	}
	if options.Tunnel == nil || options.Direct == nil {
		return nil, errors.New("dataplane requires both a tunnel and a direct dialer")
	}
	if options.Domains == nil {
		options.Domains = NewDomainCache(0)
	}
	if options.MTU == 0 {
		options.MTU = DefaultMTU
	}
	if options.Log == nil {
		options.Log = func(string, string) {}
	}

	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// The stack terminates flows addressed to every possible destination, so
	// the NIC has to accept packets that are not addressed to it (promiscuous)
	// and originate replies from addresses it does not own (spoofing).
	endpoint := channel.New(defaultQueueDepth, options.MTU, "")
	// gVisor's stack starts protocol goroutines and timers on construction, so
	// every failure below has to tear it back down rather than return.
	abandon := func(format string, err tcpip.Error) (*Dataplane, error) {
		endpoint.Close()
		networkStack.Close()
		return nil, fmt.Errorf(format, err)
	}
	if err := networkStack.CreateNIC(nicID, endpoint); err != nil {
		return abandon("create nic: %v", err)
	}
	if err := networkStack.SetPromiscuousMode(nicID, true); err != nil {
		return abandon("enable promiscuous mode: %v", err)
	}
	if err := networkStack.SetSpoofing(nicID, true); err != nil {
		return abandon("enable spoofing: %v", err)
	}
	networkStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	dataplane := &Dataplane{options: options, stack: networkStack, endpoint: endpoint}
	dataplane.policy.Store(options.Policy)

	networkStack.SetTransportProtocolHandler(tcp.ProtocolNumber,
		tcp.NewForwarder(networkStack, tcpReceiveWindow, tcpMaxInFlight, dataplane.handleTCP).HandlePacket)
	networkStack.SetTransportProtocolHandler(udp.ProtocolNumber,
		udp.NewForwarder(networkStack, dataplane.handleUDP).HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	dataplane.cancel = cancel
	dataplane.done.Add(2)
	go dataplane.pumpInbound(ctx)
	go dataplane.pumpOutbound(ctx)
	return dataplane, nil
}

// defaultQueueDepth is the channel endpoint's outbound queue. Packets are
// drained by a dedicated goroutine, so this only has to absorb a burst.
const defaultQueueDepth = 512

// UpdatePolicy swaps the routing revision without interrupting live flows.
// Flows already routed keep their decision, which matches the system-proxy
// path: a rule change there also only affects connections opened afterwards.
func (d *Dataplane) UpdatePolicy(policy *Policy) {
	if policy != nil {
		d.policy.Store(policy)
	}
}

// Close stops forwarding, closes the adapter and releases the stack.
//
// The adapter is closed first and deliberately: the inbound pump is parked
// inside a blocking read, and cancelling the context alone would leave it
// there. Closing the adapter is what makes that read return.
func (d *Dataplane) Close() error {
	d.closeOne.Do(func() {
		d.cancel()
		d.closeErr = d.options.Adapter.Close()
		d.endpoint.Close()
		d.done.Wait()
		d.stack.Close()
	})
	return d.closeErr
}

// pumpInbound moves packets from the adapter into the stack.
func (d *Dataplane) pumpInbound(ctx context.Context) {
	defer d.done.Done()
	for ctx.Err() == nil {
		packet, err := d.options.Adapter.ReceivePacket()
		if err != nil {
			if ctx.Err() == nil {
				d.options.Log("warning", "TUN read stopped: "+err.Error())
			}
			return
		}
		protocolNumber, ok := ipVersion(packet)
		if !ok {
			continue
		}
		// The adapter reuses one buffer between reads, so the stack - which
		// keeps the payload well past this iteration - gets its own copy.
		payload := make([]byte, len(packet))
		copy(payload, packet)
		buffered := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
		d.endpoint.InjectInbound(protocolNumber, buffered)
		buffered.DecRef()
	}
}

// pumpOutbound moves packets the stack produced back to the adapter.
func (d *Dataplane) pumpOutbound(ctx context.Context) {
	defer d.done.Done()
	for {
		packet := d.endpoint.ReadContext(ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		if err := d.options.Adapter.SendPacket(view.AsSlice()); err != nil && ctx.Err() == nil {
			d.options.Log("warning", "TUN write failed: "+err.Error())
		}
		view.Release()
		packet.DecRef()
	}
}

func ipVersion(packet []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber, true
	case 6:
		return header.IPv6ProtocolNumber, true
	default:
		return 0, false
	}
}

// flowOf turns a forwarder request identity into the descriptor the policy
// reads. gVisor names the fields from the stack's point of view: the packet's
// destination is Local, and its source - the application's own socket - is
// Remote.
func (d *Dataplane) flowOf(protocol Protocol, id stack.TransportEndpointID) Flow {
	destination := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
	source := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	flow := Flow{Protocol: protocol, Destination: destination}
	if d.options.Attribution != nil {
		flow.ProcessName = d.options.Attribution.Owner(protocol, source)
	}
	flow.Domains = d.options.Domains.Lookup(destination.Addr())
	return flow
}

func addrOf(address tcpip.Address) netip.Addr {
	slice := address.AsSlice()
	addr, ok := netip.AddrFromSlice(slice)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func (d *Dataplane) handleTCP(request *tcp.ForwarderRequest) {
	id := request.ID()
	flow := d.flowOf(ProtocolTCP, id)
	policy := d.policy.Load()
	decision := policy.Decide(flow)
	if decision.Verdict == VerdictDrop {
		// A reset tells the application immediately instead of leaving it to
		// time out, which is what a user reads as "the app is broken".
		request.Complete(true)
		return
	}

	var queue waiter.Queue
	endpoint, endpointErr := request.CreateEndpoint(&queue)
	if endpointErr != nil {
		request.Complete(true)
		return
	}
	request.Complete(false)
	local := gonet.NewTCPConn(&queue, endpoint)

	go func() {
		defer local.Close()

		// The name the flow was opened for decides between a domain rule and
		// nothing, and DNS learning does not see it for a client that resolved
		// before the tunnel came up or resolves over DoH. Its first bytes do.
		var head []byte
		if d.shouldSniff(policy, flow) {
			var name string
			head, name = sniffTCP(local)
			if name != "" {
				flow.Domains = []string{name}
				decision = policy.Decide(flow)
				d.rememberSniffedName(flow.Destination, name)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()

		remote, err := d.dialTCP(ctx, decision.Verdict, flow.Destination)
		if err != nil {
			d.options.Log("warning", fmt.Sprintf(
				"TUN tcp %s -> %s (%s/%s) failed: %s",
				describeProcess(flow.ProcessName), flow.Destination, decision.Verdict, decision.Reason, err))
			return
		}
		defer remote.Close()
		if len(head) > 0 {
			if _, err := remote.Write(head); err != nil {
				return
			}
		}
		relay(local, remote)
	}()
}

// sniffTCP reads the opening bytes of a flow until they name the destination,
// prove they never will, or sniffTimeout passes. Whatever was read is returned
// so the caller forwards it ahead of the relay; the flow is never altered.
func sniffTCP(local net.Conn) (head []byte, name string) {
	if err := local.SetReadDeadline(time.Now().Add(sniffTimeout)); err != nil {
		return nil, ""
	}
	defer func() {
		_ = local.SetReadDeadline(time.Time{})
	}()
	chunk := make([]byte, 4096)
	for reads := 0; ; reads++ {
		read, err := local.Read(chunk)
		if read > 0 {
			head = append(head, chunk[:read]...)
			name, needMore := guardedSniffClientName(head)
			if name != "" || !needMore || len(head) >= sniffMaxBytes || reads >= sniffMaxReads {
				return head, name
			}
		}
		if err != nil {
			// A deadline, a peer that closed, or a broken flow: the bytes so
			// far are forwarded and the flow is routed on what is known.
			return head, ""
		}
	}
}

// shouldSniff says whether a flow's first bytes are worth reading for a
// name: only when a rule could turn on it, and only when nothing else has
// settled the flow already. A process rule or an address rule selects the
// flow whatever it is named - the direct list never pre-empts a rule - and
// the transport's own endpoint is settled before any rule.
//
// Names the address was learned under do not settle it. One CDN address
// serves many sites, and only the flow's own hello says which of them this
// one is for; judging it by whatever name the address happened to be learned
// under last would route a selected site directly, or an unselected one
// through the tunnel. The learned names stay as the fallback for a flow that
// carries no hello.
func (d *Dataplane) shouldSniff(policy *Policy, flow Flow) bool {
	if !policy.NamesMatter() {
		return false
	}
	nameless := flow
	nameless.Domains = nil
	settled := policy.Decide(nameless)
	return settled.Verdict == VerdictDirect && settled.Reason != "protected-ssh-connection"
}

// rememberSniffedName teaches the domain cache what a flow revealed, so a
// later flow to the same address that carries no hello - a QUIC attempt,
// or a plain socket - is judged by the same name.
func (d *Dataplane) rememberSniffedName(destination netip.AddrPort, name string) {
	d.options.Domains.Record([]dnsRecord{{Address: destination.Addr(), Names: []string{name}, TTL: sniffedNameTTL}})
}

// sniffUDP reads the opening datagrams of a flow for the name in a QUIC
// ClientHello. Every datagram read is returned so the caller forwards them
// ahead of the relay; a flow that is not QUIC is answered on its first
// datagram without waiting.
func sniffUDP(local net.Conn) (head [][]byte, name string) {
	deadline := time.Now().Add(sniffTimeout)
	defer func() {
		_ = local.SetReadDeadline(time.Time{})
	}()
	sink := newCryptoReassembler()
	buffer := make([]byte, udpDatagramMaxBytes)
	for len(head) < quicMaxInitialDatagrams {
		if err := local.SetReadDeadline(deadline); err != nil {
			return head, ""
		}
		read, err := local.Read(buffer)
		if err != nil {
			return head, ""
		}
		datagram := append([]byte(nil), buffer[:read]...)
		head = append(head, datagram)
		name, isQUIC, needMore := guardedSniffQUICServerName(sink, datagram)
		if name != "" || !isQUIC || !needMore {
			return head, name
		}
	}
	return head, ""
}

// The parsers are fuzzed and bounds-checked, but they read bytes an
// arbitrary application chose, inside the process that owns the machine's
// routes. A panic here would take the helper down with the capture routes
// still installed; a name that could not be read is merely a flow routed as
// it would have been before there was any sniffing.
func guardedSniffClientName(data []byte) (name string, needMore bool) {
	defer func() {
		if recover() != nil {
			name, needMore = "", false
		}
	}()
	return sniffClientName(data)
}

func guardedSniffQUICServerName(sink *cryptoReassembler, datagram []byte) (name string, isQUIC bool, needMore bool) {
	defer func() {
		if recover() != nil {
			name, isQUIC, needMore = "", false, false
		}
	}()
	return sniffQUICServerName(sink, datagram)
}

func (d *Dataplane) dialTCP(ctx context.Context, verdict Verdict, destination netip.AddrPort) (net.Conn, error) {
	if verdict == VerdictProxy {
		return d.options.Tunnel.DialTCP(ctx, destination)
	}
	return d.options.Direct.DialTCP(ctx, destination)
}

// relay copies both directions and returns once both have finished. Each
// direction half-closes its destination on EOF, so a peer that stops sending
// does not cut off the data still coming the other way.
func relay(local net.Conn, remote net.Conn) {
	done := make(chan struct{}, 2)
	copyOnce := func(destination net.Conn, source net.Conn) {
		buffer := make([]byte, relayBufferBytes)
		_, _ = io.CopyBuffer(destination, source, buffer)
		// Half-closing lets the peer see EOF while the other direction drains.
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOnce(remote, local)
	go copyOnce(local, remote)
	<-done
	<-done
}

// handleUDP runs on the goroutine that feeds packets into the stack - unlike
// the TCP forwarder, gVisor calls the UDP handler synchronously. Nothing here
// may block: the socket-table lookup the policy needs would stall the adapter
// ring for every application on the machine, so the endpoint is created here
// and every decision is made on a goroutine of its own.
func (d *Dataplane) handleUDP(request *udp.ForwarderRequest) bool {
	// The forwarder hands over a clone that nothing in the library releases.
	// Missing this returns nothing to the packet pool for the life of the
	// process.
	defer request.Packet().DecRef()

	id := request.ID()
	var queue waiter.Queue
	endpoint, endpointErr := request.CreateEndpoint(&queue)
	if endpointErr != nil {
		return true
	}
	local := gonet.NewUDPConn(&queue, endpoint)

	go func() {
		defer local.Close()
		flow := d.flowOf(ProtocolUDP, id)

		// DNS is answered before the policy runs. With the default route
		// captured, refusing a selected application's DNS - which the UDP drop
		// rule would do on the SSH transport - would break it far more
		// thoroughly than routing ever fixed. Queries go out the physical
		// interface exactly as they did before the tunnel came up, and their
		// answers teach the domain cache which address belongs to which name.
		if flow.Destination.Port() == 53 {
			d.serveDNS(local, flow)
			return
		}

		policy := d.policy.Load()
		decision := policy.Decide(flow)
		// A QUIC client's first datagram names the site it is opening (see
		// quic.go). Reading it here is what lets a domain rule refuse the
		// datagram flow of a site whose address no DNS answer has explained,
		// so the client falls back to the TCP flow that is tunnelled.
		var head [][]byte
		if d.shouldSniff(policy, flow) {
			var name string
			head, name = sniffUDP(local)
			if name != "" {
				flow.Domains = []string{name}
				decision = policy.Decide(flow)
				d.rememberSniffedName(flow.Destination, name)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		switch decision.Verdict {
		case VerdictDrop:
			// The endpoint is held open and drained rather than closed, so the
			// application's retransmits are swallowed here instead of
			// re-entering this handler - and, on the packet pump, re-running
			// attribution - for every datagram. A QUIC client that gets no
			// answer falls back to TCP, which is tunnelled.
			d.discardUDP(local)
		case VerdictProxy:
			d.relayUDPThroughTunnel(ctx, local, flow, head)
		default:
			d.relayUDPDirect(ctx, local, flow, head)
		}
	}()
	return true
}

// discardUDP reads and drops until the application gives up.
func (d *Dataplane) discardUDP(local net.Conn) {
	buffer := make([]byte, udpDatagramMaxBytes)
	for {
		if err := local.SetReadDeadline(time.Now().Add(udpSessionIdleTimeout)); err != nil {
			return
		}
		if _, err := local.Read(buffer); err != nil {
			return
		}
	}
}

func (d *Dataplane) relayUDPThroughTunnel(ctx context.Context, local net.Conn, flow Flow, head [][]byte) {
	session, err := d.options.Tunnel.AssociateUDP(ctx)
	if err != nil {
		d.options.Log("warning", fmt.Sprintf("TUN udp %s -> %s tunnel failed: %s",
			describeProcess(flow.ProcessName), flow.Destination, err))
		return
	}
	defer session.Close()
	for _, datagram := range head {
		if err := session.WriteTo(datagram, flow.Destination); err != nil {
			return
		}
	}

	go func() {
		buffer := make([]byte, udpDatagramMaxBytes)
		for {
			// Both deadlines are pushed out on activity in either direction: a
			// flow that is only receiving - a voice stream, a download - is
			// still alive, and tearing it down after 90 s of silence in the
			// send direction alone would be a bug the user experiences as the
			// call dropping.
			if err := extendUDPDeadlines(local, session); err != nil {
				return
			}
			payload, _, err := session.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := local.Write(payload); err != nil {
				return
			}
		}
	}()

	buffer := make([]byte, udpDatagramMaxBytes)
	for {
		if err := extendUDPDeadlines(local, session); err != nil {
			return
		}
		read, err := local.Read(buffer)
		if err != nil {
			return
		}
		if err := session.WriteTo(buffer[:read], flow.Destination); err != nil {
			return
		}
	}
}

type deadlineSetter interface {
	SetReadDeadline(deadline time.Time) error
}

func extendUDPDeadlines(sides ...deadlineSetter) error {
	deadline := time.Now().Add(udpSessionIdleTimeout)
	for _, side := range sides {
		if err := side.SetReadDeadline(deadline); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dataplane) relayUDPDirect(ctx context.Context, local net.Conn, flow Flow, head [][]byte) {
	remote, err := d.options.Direct.ListenUDP(ctx, flow.Destination)
	if err != nil {
		return
	}
	defer remote.Close()
	destination := net.UDPAddrFromAddrPort(flow.Destination)
	for _, datagram := range head {
		if _, err := remote.WriteTo(datagram, destination); err != nil {
			return
		}
	}

	go func() {
		buffer := make([]byte, udpDatagramMaxBytes)
		for {
			if err := extendUDPDeadlines(local, remote); err != nil {
				return
			}
			read, _, err := remote.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := local.Write(buffer[:read]); err != nil {
				return
			}
		}
	}()

	buffer := make([]byte, udpDatagramMaxBytes)
	for {
		if err := extendUDPDeadlines(local, remote); err != nil {
			return
		}
		read, err := local.Read(buffer)
		if err != nil {
			return
		}
		if _, err := remote.WriteTo(buffer[:read], destination); err != nil {
			return
		}
	}
}

func (d *Dataplane) serveDNS(local net.Conn, flow Flow) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	remote, err := d.options.Direct.ListenUDP(ctx, flow.Destination)
	if err != nil {
		return
	}
	defer remote.Close()
	destination := net.UDPAddrFromAddrPort(flow.Destination)

	buffer := make([]byte, udpDatagramMaxBytes)
	answer := make([]byte, udpDatagramMaxBytes)
	for {
		// A resolver client reuses one socket for several queries, so the
		// exchange loops until the client goes quiet rather than serving a
		// single question.
		if err := local.SetReadDeadline(time.Now().Add(udpSessionIdleTimeout)); err != nil {
			return
		}
		read, err := local.Read(buffer)
		if err != nil {
			return
		}
		if _, err := remote.WriteTo(buffer[:read], destination); err != nil {
			return
		}
		if err := remote.SetReadDeadline(time.Now().Add(dnsTimeout)); err != nil {
			return
		}
		answered, _, err := remote.ReadFrom(answer)
		if err != nil {
			return
		}
		d.options.Domains.Record(parseDNSAnswers(answer[:answered]))
		if _, err := local.Write(answer[:answered]); err != nil {
			return
		}
	}
}

func describeProcess(name string) string {
	if name == "" {
		return "(unattributed)"
	}
	return name
}
