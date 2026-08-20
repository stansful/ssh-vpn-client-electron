// Package winroute owns the routing-table changes that put the TUN adapter in
// front of everything else, and the journal that undoes them after a crash.
//
// Two rules shape the design.
//
// The first is that nothing existing is modified. Capturing traffic is done by
// adding 0.0.0.0/1 and 128.0.0.0/1 (and their IPv6 equivalents) on the
// adapter, which beat the machine's default route on prefix length alone. The
// default route is never touched, so recovery is only ever a matter of
// deleting routes this process added - there is no saved state that can be
// lost, and no window in which the machine has no default route at all.
//
// The second is that the transport must stay reachable. Its server gets a host
// route through the gateway it was already using, added before the capture
// routes, so the tunnel does not try to carry itself.
package winroute

import (
	"fmt"
	"net/netip"
	"strconv"
)

// Operation is one reversible change, expressed as the argv that applies it
// and the argv that undoes it. Keeping both together is what makes the journal
// possible: a crashed process leaves behind a list of undo commands that any
// later run can execute without understanding what they were for.
type Operation struct {
	// Description is what appears in diagnostics.
	Description string   `json:"description"`
	Apply       []string `json:"-"`
	Undo        []string `json:"undo"`
}

// Plan describes the routing state the dataplane needs.
type Plan struct {
	// TunnelInterfaceIndex is the adapter's interface index.
	TunnelInterfaceIndex uint32
	// TunnelAddress4 and TunnelPrefix4 configure the adapter's IPv4 address.
	TunnelAddress4 netip.Addr
	TunnelMask4    netip.Addr
	// TunnelAddress6 and TunnelPrefixLength6 configure IPv6. Left zero when
	// IPv6 is not captured.
	TunnelAddress6      netip.Addr
	TunnelPrefixLength6 int
	// EnforceIPv4 and EnforceIPv6 select which families are captured. IPv6
	// stays uncaptured when the transport's own server could not be given a
	// host route, because capturing it would strand the tunnel.
	EnforceIPv4 bool
	EnforceIPv6 bool
	// ProtectedRoutes keeps the transport's own server reachable through the
	// physical path it was already using.
	ProtectedRoutes []ProtectedRoute
}

// ProtectedRoute pins one address to the physical interface.
type ProtectedRoute struct {
	Address        netip.Addr
	InterfaceIndex uint32
	// NextHop is empty when the address is on-link, in which case no host
	// route is needed at all: the on-link route is already more specific than
	// the capture routes.
	NextHop netip.Addr
}

// Operations renders the plan in application order. Protected routes come
// first so there is no instant in which the capture routes are live and the
// transport's own server is not excluded.
func (p Plan) Operations() ([]Operation, error) {
	if p.TunnelInterfaceIndex == 0 {
		return nil, fmt.Errorf("tunnel interface index is required")
	}
	index := strconv.FormatUint(uint64(p.TunnelInterfaceIndex), 10)

	var operations []Operation
	for _, protected := range p.ProtectedRoutes {
		operation, ok := protected.operation()
		if ok {
			operations = append(operations, operation)
		}
	}

	if p.EnforceIPv4 {
		if !p.TunnelAddress4.Is4() || !p.TunnelMask4.Is4() {
			return nil, fmt.Errorf("IPv4 capture requires an IPv4 address and mask")
		}
		operations = append(operations,
			Operation{
				Description: "assign " + p.TunnelAddress4.String() + " to the tunnel adapter",
				Apply: []string{"netsh", "interface", "ipv4", "set", "address",
					"name=" + index, "source=static",
					"address=" + p.TunnelAddress4.String(), "mask=" + p.TunnelMask4.String(),
					"gateway=none", "store=active"},
				Undo: []string{"netsh", "interface", "ipv4", "set", "address",
					"name=" + index, "source=dhcp", "store=active"},
			},
			interfaceMetricOperation("ipv4", index),
		)
		for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			operations = append(operations, captureRouteOperation("ipv4", prefix, index))
		}
	}

	if p.EnforceIPv6 {
		if !p.TunnelAddress6.Is6() || p.TunnelPrefixLength6 <= 0 || p.TunnelPrefixLength6 > 128 {
			return nil, fmt.Errorf("IPv6 capture requires an IPv6 address and prefix length")
		}
		address := p.TunnelAddress6.String() + "/" + strconv.Itoa(p.TunnelPrefixLength6)
		operations = append(operations,
			Operation{
				Description: "assign " + address + " to the tunnel adapter",
				Apply: []string{"netsh", "interface", "ipv6", "set", "address",
					"interface=" + index, "address=" + address, "store=active"},
				Undo: []string{"netsh", "interface", "ipv6", "delete", "address",
					"interface=" + index, "address=" + p.TunnelAddress6.String(), "store=active"},
			},
			interfaceMetricOperation("ipv6", index),
		)
		for _, prefix := range []string{"::/1", "8000::/1"} {
			operations = append(operations, captureRouteOperation("ipv6", prefix, index))
		}
	}

	if len(operations) == 0 {
		return nil, fmt.Errorf("plan captures neither address family")
	}
	return operations, nil
}

// captureRouteOperation adds an on-link route on the adapter. No next hop is
// given: a TUN adapter has no link layer to resolve one on, and an on-link
// route through the interface is what every other client installs here.
func captureRouteOperation(family string, prefix string, index string) Operation {
	return Operation{
		Description: "capture " + prefix + " on the tunnel adapter",
		Apply: []string{"netsh", "interface", family, "add", "route",
			"prefix=" + prefix, "interface=" + index, "metric=1", "store=active"},
		Undo: []string{"netsh", "interface", family, "delete", "route",
			"prefix=" + prefix, "interface=" + index, "store=active"},
	}
}

// interfaceMetricOperation pins the adapter to the lowest interface metric.
// Prefix length already decides against the machine's default route, but a low
// interface metric also makes Windows prefer the adapter when it is choosing a
// source address, which is what keeps applications from binding to the
// physical address and bypassing the capture.
func interfaceMetricOperation(family string, index string) Operation {
	return Operation{
		Description: "set the tunnel adapter " + family + " interface metric",
		Apply: []string{"netsh", "interface", family, "set", "interface",
			"interface=" + index, "metric=1", "store=active"},
		Undo: []string{"netsh", "interface", family, "set", "interface",
			"interface=" + index, "metric=automatic", "store=active"},
	}
}

func (r ProtectedRoute) operation() (Operation, bool) {
	// An on-link server needs no host route: its subnet route is already more
	// specific than /1, so the capture cannot take it.
	if !r.NextHop.IsValid() || r.InterfaceIndex == 0 || !r.Address.IsValid() {
		return Operation{}, false
	}
	address := r.Address.Unmap()
	family := "ipv4"
	prefix := address.String() + "/32"
	if !address.Is4() {
		family = "ipv6"
		prefix = address.String() + "/128"
	}
	index := strconv.FormatUint(uint64(r.InterfaceIndex), 10)
	return Operation{
		Description: "keep " + address.String() + " on the physical interface",
		Apply: []string{"netsh", "interface", family, "add", "route",
			"prefix=" + prefix, "interface=" + index, "nexthop=" + r.NextHop.String(),
			"metric=1", "store=active"},
		Undo: []string{"netsh", "interface", family, "delete", "route",
			"prefix=" + prefix, "interface=" + index, "nexthop=" + r.NextHop.String(), "store=active"},
	}, true
}
