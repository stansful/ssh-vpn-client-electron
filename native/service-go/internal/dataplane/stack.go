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
	decision := d.policy.Load().Decide(flow)
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
		relay(local, remote)
	}()
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

		decision := d.policy.Load().Decide(flow)
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
			d.relayUDPThroughTunnel(ctx, local, flow)
		default:
			d.relayUDPDirect(ctx, local, flow)
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

func (d *Dataplane) relayUDPThroughTunnel(ctx context.Context, local net.Conn, flow Flow) {
	session, err := d.options.Tunnel.AssociateUDP(ctx)
	if err != nil {
		d.options.Log("warning", fmt.Sprintf("TUN udp %s -> %s tunnel failed: %s",
			describeProcess(flow.ProcessName), flow.Destination, err))
		return
	}
	defer session.Close()

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

func (d *Dataplane) relayUDPDirect(ctx context.Context, local net.Conn, flow Flow) {
	remote, err := d.options.Direct.ListenUDP(ctx, flow.Destination)
	if err != nil {
		return
	}
	defer remote.Close()
	destination := net.UDPAddrFromAddrPort(flow.Destination)

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
