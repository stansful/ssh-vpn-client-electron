// Package winnet holds the small Windows networking primitives the TUN
// dataplane needs and nothing else: whether this process can create an
// adapter at all, which physical interface a destination would have used
// before the tunnel captured the default route, and sockets pinned to that
// interface so the dataplane's own direct egress cannot loop back into itself.
//
// The stubs in the non-Windows build keep the rest of the service compiling
// and unit-testable on any machine.
package winnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ErrUnsupportedPlatform is returned by every entry point on an OS without an
// implementation.
var ErrUnsupportedPlatform = errors.New("windows networking primitives are unavailable on this OS")

// Egress describes the physical path to a destination as it was before the
// dataplane changed the routing table.
type Egress struct {
	// InterfaceIndex is the IPv4 interface index to pin sockets to.
	InterfaceIndex uint32
	// NextHop is the gateway to reach the destination, or the zero value when
	// the destination is on-link.
	NextHop netip.Addr
}

// InterfaceDialer opens sockets pinned to one interface.
//
// Pinning is not an optimisation. While the dataplane is up the TUN adapter
// owns 0.0.0.0/1 and 128.0.0.0/1, so an ordinary socket opened by this process
// would be routed into the adapter, arrive back in the userspace stack, and be
// forwarded to itself. IP_UNICAST_IF overrides route lookup for the socket and
// is the only way out.
type InterfaceDialer interface {
	DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error)
	ListenUDP(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error)
}
