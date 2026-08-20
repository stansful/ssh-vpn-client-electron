//go:build windows

package platform

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	afInet                   = 2
	afInet6                  = 23
	tcpTableOwnerPIDAll      = 5
	udpTableOwnerPID         = 1
	processQueryLimitedInfo  = 0x1000
	errorInsufficientBuffer  = 122
	extendedTableMaxAttempts = 3
	extendedTableMaxBytes    = 64 * 1024 * 1024
	maxProcessConnections    = 20_000
)

var (
	iphlpapi                       = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32Process                = syscall.NewLazyDLL("kernel32.dll")
	procGetExtendedTCPTable        = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable        = iphlpapi.NewProc("GetExtendedUdpTable")
	procOpenProcess                = kernel32Process.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32Process.NewProc("QueryFullProcessImageNameW")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func listWindowsProcessConnections() ([]ProcessConnection, error) {
	// A process commonly owns many sockets. Resolve its image name once per
	// snapshot instead of issuing OpenProcess/QueryFullProcessImageName for every
	// row in both address families.
	resolver := newProcessNameResolver()
	ipv4, err := listWindowsTCP4Connections(resolver, maxProcessConnections)
	if err != nil {
		return nil, err
	}
	ipv6, err := listWindowsTCP6Connections(resolver, maxProcessConnections-len(ipv4))
	if err != nil {
		return nil, err
	}
	connections := append(ipv4, ipv6...)

	// The TUN dataplane attributes datagram flows too, and a UDP socket never
	// appears in the TCP table. A failure here is not fatal: TCP attribution is
	// still worth having, and the caller reads an absent owner as "unknown"
	// rather than as an error.
	udp4, err := listWindowsUDP4Connections(resolver, maxProcessConnections-len(connections))
	if err == nil {
		connections = append(connections, udp4...)
	}
	udp6, err := listWindowsUDP6Connections(resolver, maxProcessConnections-len(connections))
	if err == nil {
		connections = append(connections, udp6...)
	}
	return connections, nil
}

func listWindowsUDP4Connections(resolver *processNameResolver, limit int) ([]ProcessConnection, error) {
	buffer, err := extendedUDPTableBuffer(afInet)
	if err != nil || len(buffer) < 4 {
		return nil, err
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPID{})
	count = boundedRowCount(count, len(buffer), rowSize, limit)
	connections := make([]ProcessConnection, 0, count)
	for index := uint32(0); index < count; index++ {
		offset := uintptr(4) + uintptr(index)*rowSize
		if offset+rowSize > uintptr(len(buffer)) {
			break
		}
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buffer[offset]))
		pid := int(row.OwningPID)
		connections = append(connections, ProcessConnection{
			PID:          pid,
			ProcessName:  resolver.name(pid),
			LocalAddress: ipv4FromDWORD(row.LocalAddr),
			LocalPort:    portFromDWORD(row.LocalPort),
			Protocol:     "udp4",
		})
	}
	return connections, nil
}

func listWindowsUDP6Connections(resolver *processNameResolver, limit int) ([]ProcessConnection, error) {
	buffer, err := extendedUDPTableBuffer(afInet6)
	if err != nil || len(buffer) < 4 {
		return nil, err
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibUDP6RowOwnerPID{})
	count = boundedRowCount(count, len(buffer), rowSize, limit)
	connections := make([]ProcessConnection, 0, count)
	for index := uint32(0); index < count; index++ {
		offset := uintptr(4) + uintptr(index)*rowSize
		if offset+rowSize > uintptr(len(buffer)) {
			break
		}
		row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(&buffer[offset]))
		pid := int(row.OwningPID)
		connections = append(connections, ProcessConnection{
			PID:          pid,
			ProcessName:  resolver.name(pid),
			LocalAddress: scopedIPv6(row.LocalAddr, row.LocalScopeID),
			LocalPort:    portFromDWORD(row.LocalPort),
			Protocol:     "udp6",
		})
	}
	return connections, nil
}

func listWindowsTCP4Connections(resolver *processNameResolver, limit int) ([]ProcessConnection, error) {
	buffer, err := extendedTCPTableBuffer(afInet)
	if err != nil {
		return nil, err
	}
	if len(buffer) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	count = boundedRowCount(count, len(buffer), rowSize, limit)
	connections := make([]ProcessConnection, 0, count)
	for index := uint32(0); index < count; index++ {
		offset := uintptr(4) + uintptr(index)*rowSize
		if offset+rowSize > uintptr(len(buffer)) {
			break
		}
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buffer[offset]))
		pid := int(row.OwningPID)
		connections = append(connections, ProcessConnection{
			PID:           pid,
			ProcessName:   resolver.name(pid),
			LocalAddress:  ipv4FromDWORD(row.LocalAddr),
			LocalPort:     portFromDWORD(row.LocalPort),
			RemoteAddress: ipv4FromDWORD(row.RemoteAddr),
			RemotePort:    portFromDWORD(row.RemotePort),
			Protocol:      "tcp4",
		})
	}
	return connections, nil
}

func listWindowsTCP6Connections(resolver *processNameResolver, limit int) ([]ProcessConnection, error) {
	buffer, err := extendedTCPTableBuffer(afInet6)
	if err != nil {
		return nil, err
	}
	if len(buffer) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
	count = boundedRowCount(count, len(buffer), rowSize, limit)
	connections := make([]ProcessConnection, 0, count)
	for index := uint32(0); index < count; index++ {
		offset := uintptr(4) + uintptr(index)*rowSize
		if offset+rowSize > uintptr(len(buffer)) {
			break
		}
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buffer[offset]))
		pid := int(row.OwningPID)
		connections = append(connections, ProcessConnection{
			PID:           pid,
			ProcessName:   resolver.name(pid),
			LocalAddress:  scopedIPv6(row.LocalAddr, row.LocalScopeID),
			LocalPort:     portFromDWORD(row.LocalPort),
			RemoteAddress: scopedIPv6(row.RemoteAddr, row.RemoteScopeID),
			RemotePort:    portFromDWORD(row.RemotePort),
			Protocol:      "tcp6",
		})
	}
	return connections, nil
}

func extendedTCPTableBuffer(addressFamily uint32) ([]byte, error) {
	var size uint32
	result, _, _ := procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), uintptr(tcpTableOwnerPIDAll), 0)
	if result != 0 && result != errorInsufficientBuffer {
		return nil, syscall.Errno(result)
	}
	if size == 0 {
		return nil, nil
	}
	if size > extendedTableMaxBytes {
		return nil, fmt.Errorf("Windows TCP table requires %d bytes; limit is %d", size, extendedTableMaxBytes)
	}

	for attempt := 0; attempt < extendedTableMaxAttempts; attempt++ {
		buffer := make([]byte, size)
		result, _, _ = procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(addressFamily),
			uintptr(tcpTableOwnerPIDAll),
			0,
		)
		if result == 0 {
			if size > uint32(len(buffer)) {
				return nil, syscall.Errno(errorInsufficientBuffer)
			}
			return buffer[:size], nil
		}
		if result != errorInsufficientBuffer || size == 0 {
			return nil, syscall.Errno(result)
		}
		if size > extendedTableMaxBytes {
			return nil, fmt.Errorf("Windows TCP table requires %d bytes; limit is %d", size, extendedTableMaxBytes)
		}
	}
	return nil, syscall.Errno(errorInsufficientBuffer)
}

// extendedUDPTableBuffer mirrors extendedTCPTableBuffer. The two tables have
// the same "ask for the size, then ask again with a buffer" protocol and the
// same habit of growing between the two calls.
func extendedUDPTableBuffer(addressFamily uint32) ([]byte, error) {
	var size uint32
	result, _, _ := procGetExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), uintptr(udpTableOwnerPID), 0)
	if result != 0 && result != errorInsufficientBuffer {
		return nil, syscall.Errno(result)
	}
	if size == 0 {
		return nil, nil
	}
	if size > extendedTableMaxBytes {
		return nil, fmt.Errorf("Windows UDP table requires %d bytes; limit is %d", size, extendedTableMaxBytes)
	}

	for attempt := 0; attempt < extendedTableMaxAttempts; attempt++ {
		buffer := make([]byte, size)
		result, _, _ = procGetExtendedUDPTable.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(addressFamily),
			uintptr(udpTableOwnerPID),
			0,
		)
		if result == 0 {
			if size > uint32(len(buffer)) {
				return nil, syscall.Errno(errorInsufficientBuffer)
			}
			return buffer[:size], nil
		}
		if result != errorInsufficientBuffer || size == 0 {
			return nil, syscall.Errno(result)
		}
		if size > extendedTableMaxBytes {
			return nil, fmt.Errorf("Windows UDP table requires %d bytes; limit is %d", size, extendedTableMaxBytes)
		}
	}
	return nil, syscall.Errno(errorInsufficientBuffer)
}

func boundedRowCount(reported uint32, bufferLength int, rowSize uintptr, limit int) uint32 {
	if bufferLength <= 4 || rowSize == 0 || limit <= 0 {
		return 0
	}
	available := uint32(uintptr(bufferLength-4) / rowSize)
	if reported > available {
		reported = available
	}
	if reported > uint32(limit) {
		return uint32(limit)
	}
	return reported
}

type processNameResolver struct {
	cache    map[int]string
	toolhelp map[int]string
	loaded   bool
}

func newProcessNameResolver() *processNameResolver {
	return &processNameResolver{cache: make(map[int]string)}
}

func (r *processNameResolver) name(pid int) string {
	if name, exists := r.cache[pid]; exists {
		return name
	}
	name := processImageName(pid)
	if name == "" {
		// QueryFullProcessImageNameW needs a process handle, and a service
		// running at medium integrity cannot open a higher-integrity process.
		// Without a fallback every elevated application would be unnameable and
		// so unattributable, and its traffic would silently bypass a
		// process.name rule. A toolhelp snapshot lists the image name of every
		// process without opening any of them.
		name = r.toolhelpName(pid)
	}
	r.cache[pid] = name
	return name
}

func (r *processNameResolver) toolhelpName(pid int) string {
	if !r.loaded {
		r.loaded = true
		r.toolhelp = snapshotProcessNames()
	}
	return r.toolhelp[pid]
}

func snapshotProcessNames() map[int]string {
	names := make(map[int]string)
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return names
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		if len(names) >= maxProcessConnections {
			break
		}
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if name != "" {
			names[int(entry.ProcessID)] = filepath.Base(name)
		}
	}
	return names
}

func scopedIPv6(value [16]byte, scopeID uint32) string {
	address := netip.AddrFrom16(value)
	if scopeID != 0 {
		address = address.WithZone(strconv.FormatUint(uint64(scopeID), 10))
	}
	return address.String()
}

func processImageName(pid int) string {
	if pid <= 0 {
		return ""
	}
	handle, _, _ := procOpenProcess.Call(uintptr(processQueryLimitedInfo), 0, uintptr(pid))
	if handle == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buffer))
	ok, _, _ := procQueryFullProcessImageNameW.Call(handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 {
		return ""
	}
	return filepath.Base(syscall.UTF16ToString(buffer[:size]))
}

func ipv4FromDWORD(value uint32) string {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes).String()
}

func portFromDWORD(value uint32) int {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	return int(binary.BigEndian.Uint16(bytes[:2]))
}
