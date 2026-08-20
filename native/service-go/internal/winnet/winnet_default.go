//go:build !windows

package winnet

import (
	"context"
	"net"
	"net/netip"
)

// IsElevated reports false everywhere but Windows, where the question is
// meaningful.
func IsElevated() bool { return false }

// LookupEgress is unavailable off Windows.
func LookupEgress(netip.Addr) (Egress, error) { return Egress{}, ErrUnsupportedPlatform }

// InterfaceAlias is unavailable off Windows.
func InterfaceAlias(uint64) (string, error) { return "", ErrUnsupportedPlatform }

// InterfaceIndex is unavailable off Windows.
func InterfaceIndex(uint64) (uint32, error) { return 0, ErrUnsupportedPlatform }

// BestInterfaceIndex is unavailable off Windows.
func BestInterfaceIndex(netip.Addr) (uint32, error) { return 0, ErrUnsupportedPlatform }

// NewInterfaceDialer is unavailable off Windows.
func NewInterfaceDialer(uint32, uint32) InterfaceDialer { return unsupportedDialer{} }

type unsupportedDialer struct{}

func (unsupportedDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, ErrUnsupportedPlatform
}

func (unsupportedDialer) ListenUDP(context.Context, netip.AddrPort) (net.PacketConn, error) {
	return nil, ErrUnsupportedPlatform
}
