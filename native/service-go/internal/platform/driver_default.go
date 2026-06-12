//go:build !windows

package platform

import "context"

type unsupportedDriver struct{}

func NewDriver() Driver {
	return unsupportedDriver{}
}

func (unsupportedDriver) Capabilities() Capabilities {
	return Capabilities{
		Target:         CurrentTarget(),
		IPC:            "unix-socket-or-stdio",
		UnixSocketMode: true,
		SSHCoreLinked:  false,
	}
}

func (unsupportedDriver) ApplyRouting(context.Context, RoutingConfig) error {
	return ErrUnsupportedPlatform
}

func (unsupportedDriver) ClearRouting(context.Context) error {
	return nil
}

func (unsupportedDriver) ListProcessConnections(context.Context) ([]ProcessConnection, error) {
	return nil, ErrUnsupportedPlatform
}
