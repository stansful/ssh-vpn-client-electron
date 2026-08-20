//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/tun"
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
	options   WindowsOptions
	routes    *winroute.Manager
	plane     *Dataplane
	closeOnce sync.Once
	closeErr  error
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

	plane, err := Start(Options{
		Adapter:     adapter,
		Attribution: NewOwnerTable(windowsOwnerSnapshot),
		Tunnel:      &Socks5Client{Endpoint: options.TunnelEndpoint},
		Direct:      directDialer{winnet.NewInterfaceDialer(internetEgress.InterfaceIndex, internetIndex6)},
		Policy:      options.Policy,
		Domains:     NewDomainCache(0),
		Log:         log,
	})
	if err != nil {
		if restoreErr := routes.Restore(ctx); restoreErr != nil {
			log("warning", "Routing rollback after a failed start reported: "+restoreErr.Error())
		}
		adapter.Close()
		return nil, err
	}

	log("info", fmt.Sprintf(
		"TUN dataplane is up on interface %d (IPv6 capture %s, transport proxy %s).",
		interfaceIndex, enabledLabel(enforceIPv6), options.TunnelEndpoint))
	return &Runner{options: options, routes: routes, plane: plane}, nil
}

// UpdatePolicy swaps the routing revision without restarting the dataplane.
func (r *Runner) UpdatePolicy(policy *Policy) {
	r.plane.UpdatePolicy(policy)
}

// Close tears the dataplane down. Routing is restored before the adapter goes
// away, so there is no moment in which the machine has capture routes pointing
// at an interface that no longer exists.
func (r *Runner) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		if err := r.routes.Restore(ctx); err != nil {
			r.closeErr = err
			r.options.Log("warning", "Routing restore reported: "+err.Error())
		}
		if err := r.plane.Close(); err != nil && r.closeErr == nil {
			r.closeErr = err
		}
	})
	return r.closeErr
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

func enabledLabel(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
