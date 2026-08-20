//go:build windows

package platform

import (
	"context"

	"shadowssh/service/internal/tun"
	"shadowssh/service/internal/winnet"
)

type windowsDriver struct{}

func NewDriver() Driver {
	return windowsDriver{}
}

func (windowsDriver) Capabilities() Capabilities {
	// The portable build runs `asInvoker`, so the adapter and the routing
	// table are out of reach unless the user started it as administrator.
	// Reporting the capability honestly is what lets the app choose the
	// system-proxy path up front instead of failing at connect time.
	dataplaneReady := winnet.IsElevated() && tun.Available() == nil
	return Capabilities{
		Target:                       CurrentTarget(),
		IPC:                          "named-pipe-or-stdio",
		NamedPipeACL:                 true,
		ServiceControlManager:        true,
		WFPInterception:              false,
		TUNDevice:                    dataplaneReady,
		RouteManipulation:            dataplaneReady,
		ProcessConnectionAttribution: true,
		// The dataplane answers DNS itself once it owns the default route, and
		// learns which name produced which address from the answers.
		DNSVisibility:        dataplaneReady,
		IPv6RouteEnforcement: dataplaneReady,
		// Whether datagrams can actually be carried depends on the transport,
		// not on this process; the flag reports that the dataplane can forward
		// them when the transport accepts them.
		UDPForwarding: dataplaneReady,
		SSHCoreLinked: false,
	}
}

func (windowsDriver) ApplyRouting(context.Context, RoutingConfig) error {
	return ErrRoutingDriverNotInstalled
}

func (windowsDriver) ClearRouting(context.Context) error {
	return nil
}

func (windowsDriver) ListProcessConnections(context.Context) ([]ProcessConnection, error) {
	return listWindowsProcessConnections()
}

// ListConnections is the driver-free entry point the TUN dataplane uses for
// per-flow attribution, so it does not have to construct a driver - and cannot
// import one - on its hot path.
func ListConnections() ([]ProcessConnection, error) {
	return listWindowsProcessConnections()
}
