// Package winfirewall keeps traffic that ignores the routing table inside the
// tunnel adapter while the TUN dataplane runs.
//
// The capture routes win on prefix length, and that is enough for every socket
// that lets Windows choose the route. It is not enough for a socket bound to
// the network card's own address: Windows sends from a bound address over that
// interface's routes only (the strong host model), so such a socket leaves
// through the card's default route whatever the adapter's /1 routes say, and
// the dataplane never sees it. Calls bind exactly that way - WebRTC opens one
// socket per interface, in browsers and in Telegram, Signal or Zoom alike - and
// ICE then prefers the card over the adapter, whose type it does not know and
// rates as more expensive. So a call's audio and video left the machine
// directly while its page was tunnelled, which on a network that throttles
// calls is a call without sound or picture.
//
// The fix is the one VPN clients apply: while the adapter is up, traffic that
// would leave by another interface to an address the routing table sends into
// the tunnel is refused - UDP both ways, and outgoing TCP for the ICE-TCP and
// TURN-TCP fallbacks - so the application falls back to its socket on the
// adapter, and its traffic is routed like everything else. Whatever the routing
// table itself sends elsewhere (the LAN, another VPN's networks, a persistent
// route) is left alone, and so are system services, the transport and this
// helper. The filters live in a dynamic WFP session, which Windows deletes the
// moment the helper's handle closes - including when the process dies - so a
// crash cannot leave the machine cut off.
package winfirewall

import (
	"net/netip"
	"slices"
)

// Family is the IP version a filter applies to.
type Family int

const (
	FamilyIPv4 Family = 4
	FamilyIPv6 Family = 6
)

// Direction is which ALE layer a filter sits at.
type Direction int

const (
	// Outbound is ALE_AUTH_CONNECT: an outgoing connection, or the first
	// datagram a socket sends to each remote endpoint.
	Outbound Direction = iota
	// Inbound is ALE_AUTH_RECV_ACCEPT: an incoming connection, or the first
	// datagram a socket receives from each remote endpoint. Without it a peer
	// could open the flow on the card - an ICE check to a public address - and
	// the replies would ride on it unexamined.
	Inbound
)

// Action is what a filter does with the traffic it matches.
type Action int

const (
	ActionPermit Action = iota
	ActionBlock
)

// ConditionKind is what a filter matches on. A filter has one kind of
// condition, and the values of a multi-valued one are alternatives.
type ConditionKind int

const (
	// ConditionHelper matches traffic of this helper process: its
	// interface-pinned direct dials and DNS forwarding leave by the network
	// card on purpose.
	ConditionHelper ConditionKind = iota
	// ConditionServices matches processes running as SYSTEM, LocalService or
	// NetworkService: Windows' own services and the VPN daemons of other
	// clients (Teredo, IKE, tailscaled, AnyConnect), which pin to an interface
	// deliberately. The applications whose calls leaked run as the user.
	ConditionServices
	// ConditionLoopback matches loopback traffic.
	ConditionLoopback
	// ConditionTunnel matches traffic leaving by the tunnel adapter.
	ConditionTunnel
	// ConditionRemotePrefixes matches traffic to any of Prefixes.
	ConditionRemotePrefixes
	// ConditionRemotePorts matches traffic to any of Ports.
	ConditionRemotePorts
	// ConditionUDP matches UDP.
	ConditionUDP
	// ConditionTCP matches TCP.
	ConditionTCP
	// ConditionTCPReauthorized matches TCP that WFP is re-authorizing: a
	// connection that already existed when the filters changed. The guard is
	// about new connections; one opened before the tunnel came up - an RDP
	// session, a download - is left to finish rather than cut.
	ConditionTCPReauthorized
	// ConditionLocalPrefixes matches traffic to a local address in any of
	// Prefixes: multicast and broadcast a socket receives, an IPTV stream from
	// an operator's public source among them.
	ConditionLocalPrefixes
)

// Condition is one filter's match.
type Condition struct {
	Kind     ConditionKind
	Prefixes []netip.Prefix
	Ports    []uint16
}

// Filter is one WFP filter, independent of how Windows spells it.
type Filter struct {
	Name      string
	Family    Family
	Direction Direction
	Action    Action
	Weight    uint8
	Condition Condition
}

// Weights inside the guard's own sublayer: the permits are looked at before
// the blocks. Other sublayers - Windows Firewall among them - are evaluated as
// well, and a block there still wins, so a permit here never opens anything
// that was closed before; it only exempts traffic from this guard.
const (
	weightProcess  = 15
	weightLoopback = 14
	weightTunnel   = 13
	weightLocal    = 12
	weightBlock    = 0
)

// remoteServicePorts are services a machine needs from whatever network it is
// on, and that it addresses from interface-bound sockets: DNS (the Windows DNS
// client queries each interface's own servers), DHCPv4 and DHCPv6. On the
// inbound side the remote port is the sender's, which is the server's for the
// answers.
var remoteServicePorts = []uint16{53, 67, 547}

// Address space that is never the public internet: private and shared ranges,
// link-local, multicast and broadcast. Traffic to these stays on the local
// network, where the tunnel has nothing to say about it.
var (
	localPrefixes4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	localPrefixes6 = []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// Local addresses a socket receives on that are not its own: multicast and
// broadcast.
var (
	groupPrefixes4 = []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}
	groupPrefixes6 = []netip.Prefix{netip.MustParsePrefix("ff00::/8")}
)

const (
	// maxRoutedPerFamily bounds the routed exemptions of one family. A route
	// list another VPN or a "direct" list installs can run to thousands of
	// entries. Past the bound the plan is marked TooManyRoutes and not
	// installed: a partial list would refuse, for every application,
	// destinations the routing table sends elsewhere.
	maxRoutedPerFamily = 8192
	// prefixesPerFilter splits a long exemption list over several filters.
	prefixesPerFilter = 256
)

// Plan is the guard for one dataplane.
type Plan struct {
	// TunnelLUID is the adapter's interface LUID.
	TunnelLUID uint64
	// IPv6 says whether IPv6 is captured. An uncaptured family goes out
	// directly by design, and guarding it would only break it.
	IPv6 bool
	// Reachable are the remote prefixes traffic may still reach by another
	// interface: local address space, the transport's own servers - a QUIC or
	// mKCP transport (Hysteria 2, say) talks to its server over UDP, from
	// outside the tunnel - and whatever the routing table sends there.
	Reachable []netip.Prefix
	// TooManyRoutes means the routing table sends more networks elsewhere
	// than the guard can exempt; such a plan must not be installed.
	TooManyRoutes bool
}

// NewPlan builds the guard for an adapter. servers are the transport's own
// addresses, and routed the destinations the routing table sends by another
// interface ahead of the capture routes - the networks the machine is on,
// persistent routes, another VPN's split routes.
func NewPlan(tunnelLUID uint64, ipv6 bool, servers []netip.Addr, routed []netip.Prefix) Plan {
	// The fixed exemptions - local space and the transport's servers - are
	// never subject to the bound: losing one would cut the tunnel or the LAN.
	fixed := append(slices.Clone(localPrefixes4), localPrefixes6...)
	for _, server := range servers {
		server = server.Unmap()
		if server.IsValid() {
			fixed = append(fixed, netip.PrefixFrom(server, server.BitLen()))
		}
	}
	var routedOnly []netip.Prefix
	for _, prefix := range routed {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			continue
		}
		if prefix.Bits() < 2 {
			// Zero- and one-bit prefixes are the default route and the
			// capture routes themselves - or another VPN's - and would exempt
			// the internet.
			continue
		}
		routedOnly = append(routedOnly, prefix.Masked())
	}
	plan := Plan{TunnelLUID: tunnelLUID, IPv6: ipv6}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		all := collapse(append(ofFamily(fixed, family), ofFamily(routedOnly, family)...))
		fixedOfFamily := collapse(ofFamily(fixed, family))
		if len(all)-len(fixedOfFamily) > maxRoutedPerFamily {
			plan.TooManyRoutes = true
		}
		plan.Reachable = append(plan.Reachable, all...)
	}
	return plan
}

// Filters renders the whole plan.
func (p Plan) Filters() []Filter {
	return append(p.StaticFilters(), p.ReachableFilters()...)
}

func (p Plan) families() []Family {
	if p.IPv6 {
		return []Family{FamilyIPv4, FamilyIPv6}
	}
	return []Family{FamilyIPv4}
}

// StaticFilters are the filters that do not depend on the routing table.
func (p Plan) StaticFilters() []Filter {
	var filters []Filter
	for _, family := range p.families() {
		for _, direction := range []Direction{Outbound, Inbound} {
			label := label(family, direction)
			filters = append(filters,
				Filter{Name: "Permit this helper" + label, Family: family, Direction: direction, Action: ActionPermit,
					Weight: weightProcess, Condition: Condition{Kind: ConditionHelper}},
				Filter{Name: "Permit system services" + label, Family: family, Direction: direction, Action: ActionPermit,
					Weight: weightProcess, Condition: Condition{Kind: ConditionServices}},
				Filter{Name: "Permit loopback" + label, Family: family, Direction: direction, Action: ActionPermit,
					Weight: weightLoopback, Condition: Condition{Kind: ConditionLoopback}},
				Filter{Name: "Permit the tunnel adapter" + label, Family: family, Direction: direction, Action: ActionPermit,
					Weight: weightTunnel, Condition: Condition{Kind: ConditionTunnel}},
				Filter{Name: "Permit DNS and DHCP" + label, Family: family, Direction: direction, Action: ActionPermit,
					Weight: weightLocal, Condition: Condition{Kind: ConditionRemotePorts, Ports: slices.Clone(remoteServicePorts)}},
				Filter{Name: "Block UDP outside the tunnel adapter" + label, Family: family, Direction: direction,
					Action: ActionBlock, Weight: weightBlock, Condition: Condition{Kind: ConditionUDP}},
			)
			if direction == Inbound {
				groups := groupPrefixes4
				if family == FamilyIPv6 {
					groups = groupPrefixes6
				}
				filters = append(filters, Filter{Name: "Permit multicast and broadcast reception" + label, Family: family,
					Direction: direction, Action: ActionPermit, Weight: weightLocal,
					Condition: Condition{Kind: ConditionLocalPrefixes, Prefixes: slices.Clone(groups)}})
				continue
			}
			// Outgoing TCP only: a card-bound TCP socket is how ICE-TCP and
			// TURN-TCP leave once UDP is refused. Incoming TCP to the card is
			// a server the user runs, which is theirs to expose.
			filters = append(filters,
				Filter{Name: "Permit existing TCP connections" + label, Family: family, Direction: direction,
					Action: ActionPermit, Weight: weightLocal, Condition: Condition{Kind: ConditionTCPReauthorized}},
				Filter{Name: "Block TCP outside the tunnel adapter" + label, Family: family, Direction: direction,
					Action: ActionBlock, Weight: weightBlock, Condition: Condition{Kind: ConditionTCP}},
			)
		}
	}
	return filters
}

// ReachableFilters are the exemptions that follow the routing table, and
// are replaced when it changes.
func (p Plan) ReachableFilters() []Filter {
	var filters []Filter
	for _, family := range p.families() {
		reachable := ofFamily(p.Reachable, family)
		for _, direction := range []Direction{Outbound, Inbound} {
			for start := 0; start < len(reachable); start += prefixesPerFilter {
				chunk := reachable[start:min(start+prefixesPerFilter, len(reachable))]
				filters = append(filters, Filter{Name: "Permit local and routed networks" + label(family, direction),
					Family: family, Direction: direction, Action: ActionPermit, Weight: weightLocal,
					Condition: Condition{Kind: ConditionRemotePrefixes, Prefixes: slices.Clone(chunk)}})
			}
		}
	}
	return filters
}

func label(family Family, direction Direction) string {
	text := " (IPv4, "
	if family == FamilyIPv6 {
		text = " (IPv6, "
	}
	if direction == Inbound {
		return text + "inbound)"
	}
	return text + "outbound)"
}

func ofFamily(prefixes []netip.Prefix, family Family) []netip.Prefix {
	var selected []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == (family == FamilyIPv4) {
			selected = append(selected, prefix)
		}
	}
	return selected
}

// collapse sorts prefixes and drops those another one already covers.
func collapse(prefixes []netip.Prefix) (kept []netip.Prefix) {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	for _, prefix := range sorted {
		// In this order a covering prefix comes first, and everything between
		// it and a prefix it covers is covered too and was dropped, so the
		// last one kept is the only one to check.
		if len(kept) > 0 {
			last := kept[len(kept)-1]
			if last.Bits() <= prefix.Bits() && last.Contains(prefix.Addr()) {
				continue
			}
		}
		kept = append(kept, prefix)
	}
	return kept
}
