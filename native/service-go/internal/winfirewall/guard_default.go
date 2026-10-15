//go:build !windows || !(amd64 || arm64)

package winfirewall

import "errors"

// ErrNotSupported is returned where the guard cannot be installed.
var ErrNotSupported = errors.New("the UDP guard is only implemented on 64-bit Windows")

// Guard is an installed plan.
type Guard struct{}

// Start is not supported on this platform.
func Start(Plan) (*Guard, error) {
	return nil, ErrNotSupported
}

// UpdateReachable is not supported on this platform.
func (*Guard) UpdateReachable(Plan) error {
	return ErrNotSupported
}

// Close does nothing.
func (*Guard) Close() error {
	return nil
}
