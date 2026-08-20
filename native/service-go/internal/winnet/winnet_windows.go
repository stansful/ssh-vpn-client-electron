//go:build windows

package winnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// IP_UNICAST_IF and IPV6_UNICAST_IF share the option number but not the
	// byte order of their argument: the IPv4 option takes the interface index
	// in network byte order, the IPv6 option in host byte order. Getting this
	// wrong does not fail loudly - the socket simply uses the wrong interface -
	// so both conversions are spelled out where they are used.
	optionUnicastIf = 31
	// maxInterfaceAliasChars is the documented bound on an interface alias.
	maxInterfaceAliasChars = 257
)

var (
	iphlpapi                        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute                = iphlpapi.NewProc("GetBestRoute")
	procConvertInterfaceLuidToIndex = iphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceLuidToAlias = iphlpapi.NewProc("ConvertInterfaceLuidToAlias")
)

// mibIPForwardRow is MIB_IPFORWARDROW: fourteen DWORDs, no unions and no
// pointers, which is why GetBestRoute is used here in preference to the
// modern GetBestRoute2 and its nested SOCKADDR_INET unions.
type mibIPForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// IsElevated reports whether this process can create a TUN adapter and edit
// the routing table. The portable executable runs `asInvoker`, so the answer
// is false unless the user started it as administrator; the capability flags
// must follow this answer rather than failing at connect time.
func IsElevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// LookupEgress answers which interface and gateway a destination would use.
//
// It must be called before the dataplane installs its own routes, because
// afterwards the honest answer for every off-link destination is "the TUN
// adapter", which is precisely what the caller is trying to exclude.
func LookupEgress(destination netip.Addr) (Egress, error) {
	destination = destination.Unmap()
	if !destination.Is4() {
		// GetBestRoute is IPv4-only. Rather than hand-roll the union-bearing
		// IPv6 equivalent untested, the caller is told so and leaves IPv6
		// uncaptured, which keeps the transport reachable.
		return Egress{}, fmt.Errorf("egress lookup for %s: only IPv4 destinations are supported", destination)
	}
	var row mibIPForwardRow
	result, _, _ := procGetBestRoute.Call(
		uintptr(networkOrderIPv4(destination)),
		0,
		uintptr(unsafe.Pointer(&row)),
	)
	if result != 0 {
		return Egress{}, fmt.Errorf("GetBestRoute(%s): %w", destination, syscall.Errno(result))
	}
	egress := Egress{InterfaceIndex: row.ForwardIfIndex}
	if row.ForwardNextHop != 0 {
		var octets [4]byte
		// The helper APIs report addresses as network-order DWORDs, so the
		// octets come back by writing the value out little-endian.
		binary.LittleEndian.PutUint32(octets[:], row.ForwardNextHop)
		nextHop := netip.AddrFrom4(octets)
		// An on-link route reports the destination itself or the unspecified
		// address as the next hop; neither is a gateway.
		if !nextHop.IsUnspecified() && nextHop != destination {
			egress.NextHop = nextHop
		}
	}
	return egress, nil
}

// BestInterfaceIndex reports which interface would carry traffic to a
// destination. Unlike LookupEgress it works for both address families, because
// pinning a socket needs only the index and not the next hop.
//
// It must also be called before the capture routes exist, for the same reason
// LookupEgress must.
func BestInterfaceIndex(destination netip.Addr) (uint32, error) {
	destination = destination.Unmap()
	var sockaddr windows.Sockaddr
	if destination.Is4() {
		sockaddr = &windows.SockaddrInet4{Addr: destination.As4()}
	} else {
		sockaddr = &windows.SockaddrInet6{Addr: destination.As16()}
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(sockaddr, &index); err != nil {
		return 0, fmt.Errorf("GetBestInterfaceEx(%s): %w", destination, err)
	}
	return index, nil
}

// InterfaceIndex converts an adapter LUID to the interface index `netsh` and
// `route` accept.
func InterfaceIndex(luid uint64) (uint32, error) {
	var index uint32
	result, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	if result != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex: %w", syscall.Errno(result))
	}
	return index, nil
}

// InterfaceAlias converts an adapter LUID to the friendly name shown in
// network settings.
func InterfaceAlias(luid uint64) (string, error) {
	alias := make([]uint16, maxInterfaceAliasChars)
	result, _, _ := procConvertInterfaceLuidToAlias.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&alias[0])),
		uintptr(len(alias)),
	)
	if result != 0 {
		return "", fmt.Errorf("ConvertInterfaceLuidToAlias: %w", syscall.Errno(result))
	}
	return windows.UTF16ToString(alias), nil
}

// NewInterfaceDialer returns a dialer pinned to one interface per address
// family. A zero index leaves that family unpinned, which is only safe when
// that family is not captured.
func NewInterfaceDialer(indexIPv4 uint32, indexIPv6 uint32) InterfaceDialer {
	return &interfaceDialer{indexIPv4: indexIPv4, indexIPv6: indexIPv6}
}

type interfaceDialer struct {
	indexIPv4 uint32
	indexIPv6 uint32
}

func (d *interfaceDialer) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	network := "tcp4"
	if !destination.Addr().Unmap().Is4() {
		network = "tcp6"
	}
	dialer := net.Dialer{Control: d.control}
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *interfaceDialer) ListenUDP(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error) {
	network, address := "udp4", "0.0.0.0:0"
	if !destination.Addr().Unmap().Is4() {
		network, address = "udp6", "[::]:0"
	}
	config := net.ListenConfig{Control: d.control}
	return config.ListenPacket(ctx, network, address)
}

func (d *interfaceDialer) control(network string, _ string, connection syscall.RawConn) error {
	isIPv6 := network == "tcp6" || network == "udp6" || network == "ip6"
	index := d.indexIPv4
	if isIPv6 {
		index = d.indexIPv6
	}
	if index == 0 {
		return nil
	}
	var optionErr error
	controlErr := connection.Control(func(handle uintptr) {
		if isIPv6 {
			optionErr = windows.SetsockoptInt(windows.Handle(handle), windows.IPPROTO_IPV6, optionUnicastIf, int(index))
			return
		}
		optionErr = windows.SetsockoptInt(windows.Handle(handle), windows.IPPROTO_IP, optionUnicastIf, int(swapUint32(index)))
	})
	if controlErr != nil {
		return controlErr
	}
	if optionErr != nil {
		return fmt.Errorf("pin socket to interface %d: %w", index, optionErr)
	}
	return nil
}

// networkOrderIPv4 renders an address the way the IPv4 helper APIs expect it:
// as a DWORD holding the octets in memory order, which on a little-endian
// machine reads back byte-swapped.
func networkOrderIPv4(address netip.Addr) uint32 {
	octets := address.As4()
	return binary.LittleEndian.Uint32(octets[:])
}

func swapUint32(value uint32) uint32 {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return binary.BigEndian.Uint32(raw[:])
}
