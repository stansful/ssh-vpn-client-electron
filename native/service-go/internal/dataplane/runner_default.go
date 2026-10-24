//go:build !windows

package dataplane

import (
	"context"
	"errors"
	"net/netip"
)

// ErrNotElevated keeps the symbol available to code that reports why the
// dataplane is unavailable, on every OS.
var ErrNotElevated = errors.New("the TUN dataplane requires the application to be started as administrator")

// ErrNotSupported is returned off Windows, where no adapter is bundled.
var ErrNotSupported = errors.New("the TUN dataplane is only implemented on Windows")

// WindowsOptions is declared on every OS so callers compile everywhere.
type WindowsOptions struct {
	AdapterName        string
	JournalPath        string
	Policy             *Policy
	TunnelEndpoint     netip.AddrPort
	ProtectedAddresses []netip.Addr
	EnforceIPv6        bool
	Log                func(level string, message string)
	OnFatal            func(runner *Runner, cause error)
}

// Runner is the unavailable stub. It is not zero-sized, so two runners are
// told apart by address here as they are on Windows.
type Runner struct{ _ byte }

// StartWindows always fails off Windows.
func StartWindows(context.Context, WindowsOptions) (*Runner, error) { return nil, ErrNotSupported }

// UpdatePolicy is a no-op on the stub.
func (*Runner) UpdatePolicy(*Policy) {}

// Close is a no-op on the stub.
func (*Runner) Close(context.Context) error { return nil }
