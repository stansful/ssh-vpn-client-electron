// Package tun owns the virtual network adapter used to capture traffic that the
// Windows user proxy cannot reach: UDP/QUIC, raw sockets, and applications that
// ignore the proxy setting entirely.
//
// Nothing in the service branches on this package yet. It is built and proven
// on its own first; the system-proxy path stays the default until the whole
// dataplane described in native/TUN_DATAPLANE.md is complete.
package tun

import "errors"

// ErrUnsupportedPlatform is returned by the constructor on any OS without a
// bundled adapter implementation.
var ErrUnsupportedPlatform = errors.New("tun adapter is unavailable on this OS")

// MinRingCapacity and MaxRingCapacity bound the adapter's receive ring. WinTun
// requires a power of two inside this range.
const (
	MinRingCapacity = 128 * 1024
	MaxRingCapacity = 64 * 1024 * 1024
	// DefaultRingCapacity trades memory for burst tolerance. 4 MiB absorbs a
	// sustained gigabit burst for a few milliseconds, which is enough for the
	// reader goroutine to keep up without pinning large amounts of memory.
	DefaultRingCapacity = 4 * 1024 * 1024
)

// Available reports whether an adapter could be created on this machine,
// without creating one. Capability reporting needs the answer at handshake
// time: a driver that claims a TUN device it cannot produce turns into an
// obscure failure at connect time instead of a clear one up front.
func Available() error {
	return available()
}

// Config describes the adapter to create.
type Config struct {
	// Name is the adapter name shown in Windows network settings.
	Name string
	// TunnelType is a free-form vendor label WinTun records on the adapter.
	TunnelType string
	// RingCapacity is the receive ring size in bytes. Zero selects
	// DefaultRingCapacity.
	RingCapacity uint32
}

// Adapter is a virtual network interface that reads and writes IP packets.
type Adapter interface {
	// ReceivePacket blocks until a packet is available, the adapter is closed,
	// or the wait is interrupted. The returned slice aliases the adapter ring
	// and is only valid until the next ReceivePacket call.
	ReceivePacket() ([]byte, error)
	// SendPacket writes one IP packet to the adapter.
	SendPacket(packet []byte) error
	// LUID identifies the interface for routing and address configuration.
	LUID() uint64
	// Close ends the session and removes the adapter.
	Close() error
}

// ErrAdapterClosed is returned by ReceivePacket once the adapter is closed, so
// a reader loop can exit without treating shutdown as a failure.
var ErrAdapterClosed = errors.New("tun adapter is closed")

func (c Config) ringCapacity() uint32 {
	if c.RingCapacity == 0 {
		return DefaultRingCapacity
	}
	return c.RingCapacity
}
