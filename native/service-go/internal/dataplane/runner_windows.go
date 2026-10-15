//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/tun"
	"shadowssh/service/internal/winfirewall"
	"shadowssh/service/internal/winnet"
	"shadowssh/service/internal/winroute"
)

// This file is the only place the layers meet: the adapter that provides
// packets, the routing table that sends them there, the userspace stack that
// terminates them, and the transport that carries the ones a rule selected.
//
// Bring-up order is not arbitrary. Everything that must survive the capture is
// discovered first, while the routing table still describes the machine's real
// path to the internet; only then are the capture routes installed. Teardown
// runs the same list backwards.

const (
	// The adapter's own addresses. They are never seen on the wire - the stack
	// answers for every destination - so they only have to be private and
	// stable. The IPv4 block is inside 10.0.0.0/8 and the IPv6 one is a ULA.
	defaultTunnelAddress4 = "10.253.7.2"
	defaultTunnelMask4    = "255.255.255.0"
	defaultTunnelAddress6 = "fd7a:c0de:5417::2"
	defaultTunnelPrefix6  = 64
	// The probe addresses are used only for routing-table lookups, never
	// contacted, to learn which interfaces the machine would use for the
	// internet before the capture routes are added.
	routeProbeAddress4 = "1.1.1.1"
	routeProbeAddress6 = "2606:4700:4700::1111"
)

// ErrNotElevated is returned when the process cannot create an adapter.
var ErrNotElevated = errors.New("the TUN dataplane requires the application to be started as administrator")

// WindowsOptions configures a Windows dataplane.
type WindowsOptions struct {
	// AdapterName is what the adapter is called in network settings.
	AdapterName string
	// JournalPath is where routing changes are recorded so a crash can be
	// undone by the next run.
	JournalPath string
	// Policy is the initial routing revision.
	Policy *Policy
	// TunnelEndpoint is the transport's loopback SOCKS5 inbound.
	TunnelEndpoint netip.AddrPort
	// ProtectedAddresses are the transport's own servers. They keep their
	// physical route so the tunnel does not carry itself.
	ProtectedAddresses []netip.Addr
	// EnforceIPv6 captures IPv6 as well as IPv4. It is refused when a
	// protected address is IPv6, because this build cannot compute an IPv6
	// next hop and would strand the transport.
	EnforceIPv6 bool
	Log         func(level string, message string)
}

// Runner owns a live Windows dataplane.
type Runner struct {
	options WindowsOptions
	routes  *winroute.Manager
	plane   *Dataplane
	// guard keeps interface-bound traffic in the adapter; nil when it could
	// not be installed.
	guard *winfirewall.Guard
	// stopRoutesWatch ends the goroutine that keeps the guard's exemptions in
	// step with the routing table, and routesWatchDone closes when it has.
	stopRoutesWatch context.CancelFunc
	routesWatchDone chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

// StartWindows brings up the dataplane.
func StartWindows(ctx context.Context, options WindowsOptions) (*Runner, error) {
	log := options.Log
	if log == nil {
		log = func(string, string) {}
		options.Log = log
	}
	if !winnet.IsElevated() {
		return nil, ErrNotElevated
	}
	if options.Policy == nil {
		return nil, errors.New("dataplane requires a policy")
	}
	if !options.TunnelEndpoint.IsValid() || options.TunnelEndpoint.Port() == 0 {
		return nil, errors.New("dataplane requires the transport's loopback proxy endpoint")
	}

	routes := winroute.NewManager(options.JournalPath, nil, log)
	// Anything a previous run left behind is undone before new state is
	// created, so a crash cannot compound across restarts.
	if err := routes.Recover(ctx); err != nil {
		log("warning", "Could not undo routing changes from a previous run: "+err.Error())
	}

	if len(options.ProtectedAddresses) == 0 {
		// Without at least one address to exclude, the capture routes would
		// swallow the transport's own established connection: gVisor answers
		// only SYNs, so its mid-stream segments would be reset and the tunnel
		// would die while the adapter kept black-holing every selected flow.
		return nil, errors.New("dataplane requires at least one transport server address to exclude")
	}

	// Discover the physical paths first: after the capture routes exist, the
	// honest answer to "how do I reach the internet" is "through the adapter".
	internetEgress, err := winnet.LookupEgress(netip.MustParseAddr(routeProbeAddress4))
	if err != nil {
		return nil, fmt.Errorf("locate the physical interface: %w", err)
	}
	// A missing IPv6 path is normal on an IPv4-only network and is not an
	// error; it only means IPv6 must stay uncaptured, because a captured
	// family whose direct egress cannot be pinned would loop back into this
	// stack.
	internetIndex6, egress6Err := winnet.BestInterfaceIndex(netip.MustParseAddr(routeProbeAddress6))
	if egress6Err != nil {
		internetIndex6 = 0
	}
	// A route left over from a previous run can name an interface that has
	// since been removed - the adapter this dataplane created and closed. Every
	// direct flow would then be pinned to an interface that does not exist, and
	// the transport's own server would be given a host route through it.
	if present, known := interfaceExists(internetEgress.InterfaceIndex); known && !present {
		return nil, fmt.Errorf(
			"the physical route to the internet names interface %d, which no longer exists; routing from a previous run was not fully removed",
			internetEgress.InterfaceIndex)
	} else if !known {
		// Not being able to enumerate interfaces is not evidence of anything.
		// Refusing here would turn a diagnostic aid into an outage.
		log("warning", "Could not verify the physical interface before capturing traffic; continuing.")
	}

	protectedRoutes, enforceIPv6, err := protectedRoutePlan(options.ProtectedAddresses, options.EnforceIPv6, log)
	if err != nil {
		return nil, err
	}
	if enforceIPv6 && internetIndex6 == 0 {
		log("warning", "IPv6 capture is disabled: this machine has no usable IPv6 route to pin direct traffic to.")
		enforceIPv6 = false
	}

	adapter, err := tun.Open(tun.Config{Name: options.AdapterName, TunnelType: "Shadow SSH"})
	if err != nil {
		return nil, fmt.Errorf("create the tunnel adapter: %w", err)
	}

	interfaceIndex, err := winnet.InterfaceIndex(adapter.LUID())
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("resolve the tunnel interface index: %w", err)
	}
	if interfaceIndex == internetEgress.InterfaceIndex {
		// Windows reuses interface indices. If the index the routing table
		// called "the way to the internet" is the one it just handed this
		// adapter, that lookup described a leftover adapter and every direct
		// flow would be pinned straight back into this stack.
		adapter.Close()
		return nil, fmt.Errorf(
			"the tunnel adapter was given interface %d, which the routing table already names as the physical path to the internet; routing from a previous run was not fully removed",
			interfaceIndex)
	}

	plan := winroute.Plan{
		TunnelInterfaceIndex: interfaceIndex,
		TunnelAddress4:       netip.MustParseAddr(defaultTunnelAddress4),
		TunnelMask4:          netip.MustParseAddr(defaultTunnelMask4),
		TunnelAddress6:       netip.MustParseAddr(defaultTunnelAddress6),
		TunnelPrefixLength6:  defaultTunnelPrefix6,
		EnforceIPv4:          true,
		EnforceIPv6:          enforceIPv6,
		ProtectedRoutes:      protectedRoutes,
	}
	if err := routes.Apply(ctx, plan); err != nil {
		adapter.Close()
		return nil, fmt.Errorf("apply tunnel routing: %w", err)
	}

	tunnel := &Socks5Client{Endpoint: options.TunnelEndpoint}
	var probeIPv6 func(ctx context.Context) IPv6Reach
	if enforceIPv6 {
		// Only a captured family needs to know whether the tunnel carries it.
		probeIPv6 = func(ctx context.Context) IPv6Reach { return ProbeTunnelIPv6(ctx, tunnel) }
	}
	plane, err := Start(Options{
		Adapter:         adapter,
		Attribution:     NewOwnerTable(windowsOwnerSnapshot),
		Tunnel:          tunnel,
		Direct:          directDialer{winnet.NewInterfaceDialer(internetEgress.InterfaceIndex, internetIndex6)},
		Policy:          options.Policy,
		Domains:         NewDomainCache(0),
		TunnelIPv6Probe: probeIPv6,
		Log:             log,
	})
	if err != nil {
		if restoreErr := routes.Restore(ctx); restoreErr != nil {
			log("warning", "Routing rollback after a failed start reported: "+restoreErr.Error())
		}
		adapter.Close()
		return nil, err
	}

	// The routes capture every socket that lets Windows choose; the guard
	// covers the ones that do not (see internal/winfirewall). Without it the
	// tunnel still works for nearly everything, so failing to install it is a
	// warning, not a reason to give up the dataplane.
	runner := &Runner{options: options, routes: routes, plane: plane}
	guardPlan := buildGuardPlan(adapter.LUID(), interfaceIndex, enforceIPv6, options.ProtectedAddresses, log)
	guard, guardErr := winfirewall.Start(guardPlan)
	if guardErr != nil {
		log("warning", "Traffic from sockets bound to the network card is not kept in the tunnel - calls (Google Meet, "+
			"Zoom, Telegram) may send audio and video directly: "+guardErr.Error())
	} else {
		log("info", "UDP, and new outgoing TCP, from sockets bound to another interface is refused for destinations "+
			"the routing table sends into the tunnel, so calls fall back to the adapter. Applications that bind to "+
			"the network card on purpose cannot reach the internet through it while the tunnel is up; system "+
			"services and other VPN services are not affected.")
		runner.guard = guard
		watchCtx, stop := context.WithCancel(context.Background())
		runner.stopRoutesWatch = stop
		runner.routesWatchDone = make(chan struct{})
		go runner.watchRoutes(watchCtx, guardPlan, adapter.LUID(), interfaceIndex, enforceIPv6)
	}

	log("info", fmt.Sprintf(
		"TUN dataplane is up on interface %d (IPv6 capture %s, traffic guard %s, transport proxy %s).",
		interfaceIndex, enabledLabel(enforceIPv6), enabledLabel(runner.guard != nil), options.TunnelEndpoint))
	return runner, nil
}

// routesWatchInterval is how often the routing table is re-read for the
// guard's exemptions. A route another VPN or the network adds meanwhile is
// refused for at most this long.
const routesWatchInterval = 10 * time.Second

// buildGuardPlan reads the routing table into a plan. A table that cannot be
// read leaves the networks the interfaces are on as the only routed
// exemptions.
func buildGuardPlan(tunnelLUID uint64, tunnelIndex uint32, enforceIPv6 bool, servers []netip.Addr, log func(string, string)) winfirewall.Plan {
	routed, err := routedPrefixes(tunnelLUID, tunnelIndex)
	if err != nil {
		log("warning", "Could not read the routing table for the traffic guard; exempting only the networks this "+
			"machine is on: "+err.Error())
	}
	return winfirewall.NewPlan(tunnelLUID, enforceIPv6, servers, routed)
}

// watchRoutes keeps the guard's exemptions in step with the routing table: a
// VPN connected, a network joined or a route added after the tunnel came up
// must keep reaching what the table sends elsewhere. If the table outgrows
// what the guard can exempt, the guard is removed rather than left to refuse
// destinations the table routes elsewhere.
func (r *Runner) watchRoutes(ctx context.Context, current winfirewall.Plan, tunnelLUID uint64, tunnelIndex uint32, enforceIPv6 bool) {
	defer close(r.routesWatchDone)
	ticker := time.NewTicker(routesWatchInterval)
	defer ticker.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		routed, err := routedPrefixes(tunnelLUID, tunnelIndex)
		if err != nil {
			// A table that cannot be read says nothing about what changed;
			// the exemptions in place stay.
			continue
		}
		next := winfirewall.NewPlan(tunnelLUID, enforceIPv6, r.options.ProtectedAddresses, routed)
		if slices.Equal(next.Reachable, current.Reachable) {
			continue
		}
		if next.TooManyRoutes {
			r.options.Log("warning", "The routing table now sends more networks elsewhere than the traffic guard can "+
				"exempt, so the guard is removed: calls may again send audio and video directly.")
			_ = r.guard.Close()
			return
		}
		if err := r.guard.UpdateReachable(next); err != nil {
			if !failing {
				r.options.Log("warning", "Could not update the traffic guard for a routing change: "+err.Error())
			}
			failing = true
			continue
		}
		failing = false
		current = next
	}
}

// UpdatePolicy swaps the routing revision without restarting the dataplane.
func (r *Runner) UpdatePolicy(policy *Policy) {
	r.plane.UpdatePolicy(policy)
}

// Close tears the dataplane down. The traffic guard goes first, while the routes
// still send everything to the adapter: the other way round, there would be a
// moment in which interface-bound UDP is refused and nothing else carries it.
// Routing is restored before the adapter goes away, so there is no moment in
// which the machine has capture routes pointing at an interface that no longer
// exists.
func (r *Runner) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		if r.stopRoutesWatch != nil {
			r.stopRoutesWatch()
			<-r.routesWatchDone
		}
		if r.guard != nil {
			if err := r.guard.Close(); err != nil {
				r.closeErr = err
				r.options.Log("warning", "Removing the traffic guard reported: "+err.Error())
			}
		}
		if err := r.routes.Restore(ctx); err != nil {
			if r.closeErr == nil {
				r.closeErr = err
			}
			r.options.Log("warning", "Routing restore reported: "+err.Error())
		}
		if err := r.plane.Close(); err != nil && r.closeErr == nil {
			r.closeErr = err
		}
	})
	return r.closeErr
}

// routedPrefixes are the destinations the routing table sends by another
// interface ahead of the capture routes: the networks this machine is on, a
// LAN numbered from public space, persistent routes, another VPN's split
// routes. The guard leaves them alone - it is there for sockets that ignore the
// routing table, not to overrule it. It is read after the capture routes are
// in, and again by watchRoutes.
func routedPrefixes(tunnelLUID uint64, tunnelIndex uint32) ([]netip.Prefix, error) {
	routes, err := winnet.Routes()
	if err != nil {
		return onLinkPrefixes(tunnelIndex), err
	}
	var prefixes []netip.Prefix
	for _, route := range routes {
		if route.InterfaceLUID != tunnelLUID {
			prefixes = append(prefixes, route.Destination)
		}
	}
	// The interfaces' own prefixes as well: an address can be on-link without
	// a route of its own length having been listed.
	return append(prefixes, onLinkPrefixes(tunnelIndex)...), nil
}

// onLinkPrefixes are the networks this machine's other interfaces are on.
func onLinkPrefixes(tunnelIndex uint32) []netip.Prefix {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var prefixes []netip.Prefix
	for _, candidate := range interfaces {
		if candidate.Index == int(tunnelIndex) || candidate.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := candidate.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(network.IP)
			if !ok {
				continue
			}
			ones, size := network.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && size == 128 {
				// An IPv4 address with its mask in the 16-byte form.
				ones -= 96
			}
			prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
		}
	}
	return prefixes
}

// protectedRoutePlan works out how each of the transport's servers stays
// reachable, and whether IPv6 can be captured at all.
func protectedRoutePlan(addresses []netip.Addr, enforceIPv6 bool, log func(string, string)) ([]winroute.ProtectedRoute, bool, error) {
	var routes []winroute.ProtectedRoute
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if !address.Is4() {
			// Without an IPv6 next hop this address cannot be excluded, so
			// IPv6 is left uncaptured rather than captured with a hole the
			// transport falls into.
			if enforceIPv6 {
				log("warning", fmt.Sprintf(
					"IPv6 capture is disabled because the transport server %s is IPv6 and cannot be excluded by this build.", address))
			}
			enforceIPv6 = false
			continue
		}
		egress, err := winnet.LookupEgress(address)
		if err != nil {
			return nil, false, fmt.Errorf("locate the physical route to %s: %w", address, err)
		}
		routes = append(routes, winroute.ProtectedRoute{
			Address:        address,
			InterfaceIndex: egress.InterfaceIndex,
			NextHop:        egress.NextHop,
		})
	}
	return routes, enforceIPv6, nil
}

// directDialer adapts an interface-pinned dialer to the dataplane's interface.
type directDialer struct {
	dialer winnet.InterfaceDialer
}

func (d directDialer) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	return d.dialer.DialTCP(ctx, destination)
}

func (d directDialer) ListenUDP(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error) {
	return d.dialer.ListenUDP(ctx, destination)
}

// windowsOwnerSnapshot reads the machine's TCP and UDP owner tables.
func windowsOwnerSnapshot() ([]OwnerRow, error) {
	connections, err := platform.ListConnections()
	if err != nil {
		return nil, err
	}
	rows := make([]OwnerRow, 0, len(connections))
	for _, connection := range connections {
		protocol, ok := ProtocolFromTableName(connection.Protocol)
		if !ok {
			continue
		}
		address, err := netip.ParseAddr(connection.LocalAddress)
		if err != nil {
			continue
		}
		rows = append(rows, OwnerRow{
			Protocol:    protocol,
			Local:       netip.AddrPortFrom(address.WithZone("").Unmap(), uint16(connection.LocalPort)),
			ProcessName: connection.ProcessName,
		})
	}
	return rows, nil
}

// interfaceExists reports whether an interface index is present, and whether
// the answer is trustworthy at all. Enumeration itself can fail, and "I could
// not look" must not be confused with "it is gone".
func interfaceExists(index uint32) (present bool, known bool) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		return false, false
	}
	for _, candidate := range interfaces {
		if candidate.Index == int(index) {
			return true, true
		}
	}
	return false, true
}

func enabledLabel(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
