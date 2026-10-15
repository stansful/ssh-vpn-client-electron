package dataplane

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// The capture routes take IPv6 whenever this machine has an IPv6 route, but
// the server at the other end of the transport may have none. A browser on a
// dual-stack PC prefers IPv6, so every selected site that also has an IPv6
// address then fails - and fails in the one way Happy Eyeballs cannot repair:
// the stack completes the handshake before the flow is dialled, so the
// application sees its IPv6 connection succeed and then close, and retries
// the same address instead of moving on to IPv4.
//
// What the far end can reach is therefore asked of the far end itself, and
// while the answer is not a clear yes the dataplane refuses, before the
// handshake, the IPv6 flows it would have to tunnel. A refused connect is what
// makes an application try its next address, so the site is reached over IPv4
// instead.

// IPv6Reach is one answer of the IPv6 probe.
type IPv6Reach int

const (
	// IPv6Unknown means the tunnel itself did not answer - it was down or
	// still settling - so nothing was learned about IPv6.
	IPv6Unknown IPv6Reach = iota
	// IPv6Unreachable means IPv4 answered through the tunnel and IPv6 did not.
	IPv6Unreachable
	// IPv6Reachable means every IPv6 target answered through the tunnel.
	IPv6Reachable
)

// ipv6ProbeTimeout bounds one probe. It covers the transport's own connect
// and a TLS round trip from the far end.
const ipv6ProbeTimeout = 10 * time.Second

// The probe schedule. Variables only so tests need not wait for it.
var (
	// ipv6ProbeRetry is the wait after a probe that learned nothing, and
	// before the one that confirms a first "reachable".
	ipv6ProbeRetry = 30 * time.Second
	// ipv6ProbeRecheck is the wait after a settled answer. A server's IPv6
	// rarely changes within a session, and a different server rebuilds the
	// dataplane anyway, since its address is part of what the dataplane was
	// built for. Each probe that finds no IPv6 is two failed tunnel opens in
	// the transport's own log, so it is not repeated often.
	ipv6ProbeRecheck = time.Hour
)

// The probe targets are anycast resolvers that answer TLS on 443 from any
// network. The IPv6 ones are what is being asked about; the IPv4 ones tell a
// server without IPv6 apart from a tunnel that is not working at all.
var (
	ipv6ProbeTargets = []netip.AddrPort{
		netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:443"),
	}
	ipv4ControlTargets = []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:443"),
		netip.MustParseAddrPort("8.8.8.8:443"),
	}
)

// ProbeTunnelIPv6 asks whether the transport's far end reaches the IPv6
// internet. A wrong "reachable" brings the original failure back while a
// wrong "unreachable" only costs a fallback to IPv4, so reachable needs every
// IPv6 target to answer - a server that reaches one operator's network some
// other way (a WARP route for Google, say) is not taken to have IPv6.
func ProbeTunnelIPv6(ctx context.Context, tunnel TunnelDialer) IPv6Reach {
	ctx, cancel := context.WithTimeout(ctx, ipv6ProbeTimeout)
	defer cancel()
	type answer struct {
		ipv6     bool
		answered bool
	}
	targets := len(ipv6ProbeTargets) + len(ipv4ControlTargets)
	// Buffered, so the attempts still running when this returns finish on
	// their own instead of holding up whoever is waiting for the probe.
	answers := make(chan answer, targets)
	for _, target := range ipv6ProbeTargets {
		go func() { answers <- answer{ipv6: true, answered: answersThroughTunnel(ctx, tunnel, target)} }()
	}
	for _, target := range ipv4ControlTargets {
		go func() { answers <- answer{ipv6: false, answered: answersThroughTunnel(ctx, tunnel, target)} }()
	}
	ipv6Answered, ipv4Answered := 0, false
	for range targets {
		select {
		case <-ctx.Done():
			return IPv6Unknown
		case result := <-answers:
			switch {
			case result.ipv6 && result.answered:
				ipv6Answered++
			case !result.ipv6 && result.answered:
				ipv4Answered = true
			}
		}
	}
	switch {
	case ipv6Answered == len(ipv6ProbeTargets):
		return IPv6Reachable
	case ipv4Answered:
		return IPv6Unreachable
	default:
		return IPv6Unknown
	}
}

// answersThroughTunnel opens a TLS handshake with destination through the
// transport and reports whether anything came back. A successful CONNECT is
// not enough: Xray's SOCKS inbound reports success before its outbound has
// connected, so on Xray an address the server cannot reach shows up only as a
// connection that closes without a byte.
//
// The hello carries no server name. With one, a server that sniffs TLS and
// routes by name - common on Xray servers - would connect to the name instead
// of the address and answer for an address it cannot reach. The handshake's
// outcome is beside the point and nothing is sent once it ends, which is why
// the certificate is not verified.
func answersThroughTunnel(ctx context.Context, tunnel TunnelDialer, destination netip.AddrPort) bool {
	conn, err := tunnel.DialTCP(ctx, destination)
	if err != nil {
		return false
	}
	defer conn.Close()
	counted := &readCountingConn{Conn: conn}
	client := tls.Client(counted, &tls.Config{InsecureSkipVerify: true})
	_ = client.HandshakeContext(ctx)
	return counted.read.Load() > 0
}

type readCountingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *readCountingConn) Read(buffer []byte) (int, error) {
	read, err := c.Conn.Read(buffer)
	c.read.Add(int64(read))
	return read, err
}

// TunnelReachesIPv6 reports whether the IPv6 probe last settled on
// "reachable". Until it has, it is false.
func (d *Dataplane) TunnelReachesIPv6() bool {
	return d.tunnelIPv6.Load()
}

// watchTunnelIPv6 keeps TunnelReachesIPv6 current for as long as the
// dataplane runs, and says so in the log whenever the answer changes.
func (d *Dataplane) watchTunnelIPv6(ctx context.Context) {
	defer d.done.Done()
	logged := false
	unconfirmed := false
	for {
		answer := d.options.TunnelIPv6Probe(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := ipv6ProbeRecheck
		switch {
		case answer == IPv6Unknown:
			// Nothing learned: keep the last answer, and ask again soon.
			wait = ipv6ProbeRetry
		case answer == IPv6Reachable && !d.tunnelIPv6.Load() && !unconfirmed:
			// A "reachable" is asked once more before IPv6 is tunnelled: a
			// probe that slipped out some other way than through the tunnel
			// would otherwise bring the original failure back for an hour,
			// while waiting costs only a fallback to IPv4 meanwhile.
			unconfirmed = true
			wait = ipv6ProbeRetry
		case answer == IPv6Reachable:
			unconfirmed = false
			if !d.tunnelIPv6.Swap(true) || !logged {
				d.logTunnelIPv6(true)
			}
			logged = true
		default:
			unconfirmed = false
			if d.tunnelIPv6.Swap(false) || !logged {
				d.logTunnelIPv6(false)
			}
			logged = true
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *Dataplane) logTunnelIPv6(reachable bool) {
	if reachable {
		d.options.Log("info", "The tunnel reaches IPv6: IPv6 connections are tunnelled.")
		return
	}
	d.options.Log("warning",
		"The tunnel's server does not reach IPv6 (checked through the tunnel against 2606:4700:4700::1111 and "+
			"2001:4860:4860::8888, while IPv4 answered): IPv6 connections that would be tunnelled are refused, so "+
			"applications use IPv4 instead. Failed tunnel opens to those two addresses are this check.")
}

// refusesForIPv6 says whether a TCP flow has to be refused before the
// handshake because it is IPv6, the tunnel has not been found to carry IPv6,
// and the flow would - or quite possibly would - be tunnelled.
//
// A flow already selected is refused. A flow held for its name is refused
// only where its name is what will decide it and nothing about the address is
// known yet: on 443 or 80, where browsers race address families, with no name
// learned from DNS. Once a name has been learned and the flow is still not
// selected, every name the address is known by is unselected, and it is let
// through to go out directly as before. That leaves one way back into the old
// failure - a selected site sharing an address with unselected names whose
// own DNS answer was never seen - which is narrow. Refusing more widely broke
// what had worked: ssh to an IPv6-only host, DNS over TCP, and the Happy
// Eyeballs delay on every unselected dual-stack site.
func (d *Dataplane) refusesForIPv6(flow Flow, decision Decision, heldForName bool) bool {
	if !flow.Destination.Addr().Is6() || d.tunnelIPv6.Load() {
		return false
	}
	if decision.Verdict == VerdictProxy {
		return true
	}
	port := flow.Destination.Port()
	return heldForName && len(flow.Domains) == 0 && (port == 443 || port == 80)
}
