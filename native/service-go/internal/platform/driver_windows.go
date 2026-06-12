//go:build windows

package platform

import "context"

type windowsDriver struct{}

func NewDriver() Driver {
	return windowsDriver{}
}

func (windowsDriver) Capabilities() Capabilities {
	return Capabilities{
		Target:                       CurrentTarget(),
		IPC:                          "named-pipe-or-stdio",
		NamedPipeACL:                 true,
		ServiceControlManager:        true,
		WFPInterception:              false,
		TUNDevice:                    false,
		RouteManipulation:            false,
		ProcessConnectionAttribution: true,
		DNSVisibility:                false,
		IPv6RouteEnforcement:         false,
		UDPForwarding:                false,
		SSHCoreLinked:                false,
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
