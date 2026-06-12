//go:build windows

package platform

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	afInet                  = 2
	afInet6                 = 23
	tcpTableOwnerPIDAll     = 5
	processQueryLimitedInfo = 0x1000
)

var (
	iphlpapi                       = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32Process                = syscall.NewLazyDLL("kernel32.dll")
	procGetExtendedTCPTable        = iphlpapi.NewProc("GetExtendedTcpTable")
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

func listWindowsProcessConnections() ([]ProcessConnection, error) {
	ipv4, err := listWindowsTCP4Connections()
	if err != nil {
		return nil, err
	}
	ipv6, err := listWindowsTCP6Connections()
	if err != nil {
		return nil, err
	}
	return append(ipv4, ipv6...), nil
}

func listWindowsTCP4Connections() ([]ProcessConnection, error) {
	buffer, err := extendedTCPTableBuffer(afInet)
	if err != nil {
		return nil, err
	}
	if len(buffer) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
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
			ProcessName:   processName(pid),
			LocalAddress:  ipv4FromDWORD(row.LocalAddr),
			LocalPort:     portFromDWORD(row.LocalPort),
			RemoteAddress: ipv4FromDWORD(row.RemoteAddr),
			RemotePort:    portFromDWORD(row.RemotePort),
			Protocol:      "tcp4",
		})
	}
	return connections, nil
}

func listWindowsTCP6Connections() ([]ProcessConnection, error) {
	buffer, err := extendedTCPTableBuffer(afInet6)
	if err != nil {
		return nil, err
	}
	if len(buffer) < 4 {
		return nil, nil
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
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
			ProcessName:   processName(pid),
			LocalAddress:  netip.AddrFrom16(row.LocalAddr).String(),
			LocalPort:     portFromDWORD(row.LocalPort),
			RemoteAddress: netip.AddrFrom16(row.RemoteAddr).String(),
			RemotePort:    portFromDWORD(row.RemotePort),
			Protocol:      "tcp6",
		})
	}
	return connections, nil
}

func extendedTCPTableBuffer(addressFamily uint32) ([]byte, error) {
	var size uint32
	_, _, _ = procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(addressFamily), uintptr(tcpTableOwnerPIDAll), 0)
	if size == 0 {
		return nil, nil
	}
	buffer := make([]byte, size)
	result, _, err := procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(addressFamily),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if result != 0 {
		return nil, err
	}
	return buffer[:size], nil
}

func processName(pid int) string {
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
