//go:build windows && (amd64 || arm64)

package winnet

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The routing table comes from GetIpForwardTable2, whose rows hold
// SOCKADDR_INET unions. They are spelled as a family and raw bytes, as
// wireguard-windows' winipcfg does (MIT, Copyright (C) 2019 WireGuard LLC),
// and checked at compile time against the 64-bit layout - amd64 and arm64,
// the only targets built - so a field that moves fails the build instead of
// being read as a different route.

var (
	procGetIpForwardTable2 = iphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable       = iphlpapi.NewProc("FreeMibTable")
)

// rawSockaddrInet is SOCKADDR_INET: a family and the rest of a sockaddr_in or
// sockaddr_in6.
type rawSockaddrInet struct {
	family uint16
	data   [26]byte
}

// ipAddressPrefix is IP_ADDRESS_PREFIX.
type ipAddressPrefix struct {
	prefix       rawSockaddrInet
	prefixLength uint8
	_            [3]byte
}

// mibIPForwardRow2 is MIB_IPFORWARD_ROW2.
type mibIPForwardRow2 struct {
	interfaceLUID        uint64
	interfaceIndex       uint32
	destinationPrefix    ipAddressPrefix
	nextHop              rawSockaddrInet
	sitePrefixLength     uint8
	validLifetime        uint32
	preferredLifetime    uint32
	metric               uint32
	protocol             uint32
	loopback             uint8
	autoconfigureAddress uint8
	publish              uint8
	immortal             uint8
	age                  uint32
	origin               uint32
}

// mibIPForwardTable2 is MIB_IPFORWARD_TABLE2; the rows follow it in memory.
type mibIPForwardTable2 struct {
	numEntries uint32
	table      [1]mibIPForwardRow2
}

var (
	_ [28 - unsafe.Sizeof(rawSockaddrInet{})]byte
	_ [unsafe.Sizeof(rawSockaddrInet{}) - 28]byte
	_ [32 - unsafe.Sizeof(ipAddressPrefix{})]byte
	_ [unsafe.Sizeof(ipAddressPrefix{}) - 32]byte
	_ [28 - unsafe.Offsetof(ipAddressPrefix{}.prefixLength)]byte
	_ [unsafe.Offsetof(ipAddressPrefix{}.prefixLength) - 28]byte
	_ [104 - unsafe.Sizeof(mibIPForwardRow2{})]byte
	_ [unsafe.Sizeof(mibIPForwardRow2{}) - 104]byte
	_ [12 - unsafe.Offsetof(mibIPForwardRow2{}.destinationPrefix)]byte
	_ [unsafe.Offsetof(mibIPForwardRow2{}.destinationPrefix) - 12]byte
	_ [44 - unsafe.Offsetof(mibIPForwardRow2{}.nextHop)]byte
	_ [unsafe.Offsetof(mibIPForwardRow2{}.nextHop) - 44]byte
	_ [84 - unsafe.Offsetof(mibIPForwardRow2{}.metric)]byte
	_ [unsafe.Offsetof(mibIPForwardRow2{}.metric) - 84]byte
	_ [100 - unsafe.Offsetof(mibIPForwardRow2{}.origin)]byte
	_ [unsafe.Offsetof(mibIPForwardRow2{}.origin) - 100]byte
	_ [8 - unsafe.Offsetof(mibIPForwardTable2{}.table)]byte
	_ [unsafe.Offsetof(mibIPForwardTable2{}.table) - 8]byte
)

// Routes reads the IPv4 and IPv6 routing tables.
func Routes() ([]Route, error) {
	var routes []Route
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		var table *mibIPForwardTable2
		result, _, _ := syscall.SyscallN(procGetIpForwardTable2.Addr(), uintptr(family), uintptr(unsafe.Pointer(&table)))
		if result != 0 {
			return nil, fmt.Errorf("GetIpForwardTable2: %w", syscall.Errno(result))
		}
		rows := unsafe.Slice(&table.table[0], table.numEntries)
		for index := range rows {
			if prefix, ok := rows[index].destinationPrefix.netip(); ok {
				routes = append(routes, Route{Destination: prefix, InterfaceLUID: rows[index].interfaceLUID})
			}
		}
		_, _, _ = syscall.SyscallN(procFreeMibTable.Addr(), uintptr(unsafe.Pointer(table)))
	}
	return routes, nil
}

func (p *ipAddressPrefix) netip() (netip.Prefix, bool) {
	var addr netip.Addr
	switch p.prefix.family {
	case windows.AF_INET:
		// sockaddr_in: port, then the address.
		addr = netip.AddrFrom4([4]byte(p.prefix.data[2:6]))
	case windows.AF_INET6:
		// sockaddr_in6: port, flow info, then the address.
		addr = netip.AddrFrom16([16]byte(p.prefix.data[6:22]))
	default:
		return netip.Prefix{}, false
	}
	prefix := netip.PrefixFrom(addr, int(p.prefixLength))
	return prefix, prefix.IsValid()
}
