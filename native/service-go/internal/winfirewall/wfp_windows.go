//go:build windows && (amd64 || arm64)

package winfirewall

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows Filtering Platform management API, as much of it as the guard
// uses. Its structures carry unions, which Go cannot express, so each is
// spelled with the union as a pointer-sized word and checked below against the
// layout of the 64-bit Windows headers - amd64 and arm64, the only targets
// this helper is built for. The checks are compile-time: a field that moves
// fails the build instead of producing a filter Windows silently misreads.
//
// The layouts and constants follow wireguard-windows' tunnel/firewall
// package (MIT, Copyright (C) 2019 WireGuard LLC), which has run these
// structures in production for years.

// fwpDataType is FWP_DATA_TYPE. An enum, but in FWP_VALUE0 it is followed by a
// pointer-aligned union, so the full word is spelled out.
type fwpDataType uint64

const (
	fwpUint8                  fwpDataType = 1
	fwpUint16                 fwpDataType = 2
	fwpUint32                 fwpDataType = 3
	fwpUint64                 fwpDataType = 4
	fwpByteBlobType           fwpDataType = 12
	fwpSecurityDescriptorType fwpDataType = 14
	fwpV4AddrMaskType         fwpDataType = 0x100
	fwpV6AddrMaskType         fwpDataType = 0x101
)

// fwpMatchType is FWP_MATCH_TYPE.
type fwpMatchType uint32

const (
	fwpMatchEqual       fwpMatchType = 0
	fwpMatchFlagsAllSet fwpMatchType = 6
)

// fwpActionType is FWP_ACTION_TYPE.
type fwpActionType uint32

const (
	fwpActionFlagTerminating fwpActionType = 0x00001000
	fwpActionBlock                         = 0x00000001 | fwpActionFlagTerminating
	fwpActionPermit                        = 0x00000002 | fwpActionFlagTerminating
)

const (
	fwpConditionFlagIsLoopback    = 0x00000001
	fwpConditionFlagIsReauthorize = 0x00000004
	fwpmSessionFlagDynamic        = 0x00000001
	rpcCAuthnWinNT                = 10
	ipProtoTCP                    = 6
	ipProtoUDP                    = 17
	// sessionTransactionWaitMillis bounds how long beginning a transaction
	// waits for another WFP client's to finish. A guard that cannot be
	// installed is skipped; one that hangs would hold the connect path.
	sessionTransactionWaitMillis = 10_000
)

var (
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4: outbound connections, and the first
	// datagram a UDP socket sends to each remote endpoint.
	layerALEAuthConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	// FWPM_LAYER_ALE_AUTH_CONNECT_V6.
	layerALEAuthConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: incoming connections, and the first
	// datagram a socket receives from each remote endpoint.
	layerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.
	layerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	conditionIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969,
		Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	conditionIPRemoteAddress = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	conditionIPLocalAddress = windows.GUID{Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617,
		Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}}
	conditionIPProtocol = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	conditionIPRemotePort = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	conditionALEAppID = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	conditionALEUserID = windows.GUID{Data1: 0xaf043a0a, Data2: 0xb34d, Data3: 0x4f86,
		Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}}
	conditionFlags = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c,
		Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
)

// fwpByteBlob is FWP_BYTE_BLOB.
type fwpByteBlob struct {
	size uint32
	data *uint8
}

// fwpValue0 is FWP_VALUE0 and, with the same layout, FWP_CONDITION_VALUE0:
// a type tag and a union that holds either a small integer or a pointer.
type fwpValue0 struct {
	kind  fwpDataType
	value uintptr
}

// fwpV4AddrAndMask is FWP_V4_ADDR_AND_MASK, both in host byte order.
type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

// fwpV6AddrAndMask is FWP_V6_ADDR_AND_MASK.
type fwpV6AddrAndMask struct {
	addr         [16]uint8
	prefixLength uint8
}

// fwpmDisplayData0 is FWPM_DISPLAY_DATA0.
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpmFilterCondition0 is FWPM_FILTER_CONDITION0.
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      fwpMatchType
	conditionValue fwpValue0
}

// fwpmAction0 is FWPM_ACTION0: the type and a union of two GUIDs, unused here.
type fwpmAction0 struct {
	kind       fwpActionType
	filterType windows.GUID
}

// fwpmFilter0 is FWPM_FILTER0.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte // the union that follows starts on 8 bytes
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// fwpmSession0 is FWPM_SESSION0.
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

// fwpmSublayer0 is FWPM_SUBLAYER0.
type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// Layout checks against the 64-bit headers. Each pair fails to compile -
// one side becomes a negative array length - unless the two are equal.
var (
	_ [16 - unsafe.Sizeof(fwpByteBlob{})]byte
	_ [unsafe.Sizeof(fwpByteBlob{}) - 16]byte
	_ [8 - unsafe.Offsetof(fwpByteBlob{}.data)]byte
	_ [unsafe.Offsetof(fwpByteBlob{}.data) - 8]byte

	_ [16 - unsafe.Sizeof(fwpValue0{})]byte
	_ [unsafe.Sizeof(fwpValue0{}) - 16]byte
	_ [8 - unsafe.Offsetof(fwpValue0{}.value)]byte
	_ [unsafe.Offsetof(fwpValue0{}.value) - 8]byte

	_ [8 - unsafe.Sizeof(fwpV4AddrAndMask{})]byte
	_ [unsafe.Sizeof(fwpV4AddrAndMask{}) - 8]byte
	_ [17 - unsafe.Sizeof(fwpV6AddrAndMask{})]byte
	_ [unsafe.Sizeof(fwpV6AddrAndMask{}) - 17]byte

	_ [16 - unsafe.Sizeof(fwpmDisplayData0{})]byte
	_ [unsafe.Sizeof(fwpmDisplayData0{}) - 16]byte

	_ [40 - unsafe.Sizeof(fwpmFilterCondition0{})]byte
	_ [unsafe.Sizeof(fwpmFilterCondition0{}) - 40]byte
	_ [16 - unsafe.Offsetof(fwpmFilterCondition0{}.matchType)]byte
	_ [unsafe.Offsetof(fwpmFilterCondition0{}.matchType) - 16]byte
	_ [24 - unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue)]byte
	_ [unsafe.Offsetof(fwpmFilterCondition0{}.conditionValue) - 24]byte

	_ [20 - unsafe.Sizeof(fwpmAction0{})]byte
	_ [unsafe.Sizeof(fwpmAction0{}) - 20]byte

	_ [200 - unsafe.Sizeof(fwpmFilter0{})]byte
	_ [unsafe.Sizeof(fwpmFilter0{}) - 200]byte
	_ [32 - unsafe.Offsetof(fwpmFilter0{}.flags)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.flags) - 32]byte
	_ [40 - unsafe.Offsetof(fwpmFilter0{}.providerKey)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.providerKey) - 40]byte
	_ [64 - unsafe.Offsetof(fwpmFilter0{}.layerKey)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.layerKey) - 64]byte
	_ [80 - unsafe.Offsetof(fwpmFilter0{}.subLayerKey)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.subLayerKey) - 80]byte
	_ [96 - unsafe.Offsetof(fwpmFilter0{}.weight)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.weight) - 96]byte
	_ [112 - unsafe.Offsetof(fwpmFilter0{}.numFilterConditions)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.numFilterConditions) - 112]byte
	_ [120 - unsafe.Offsetof(fwpmFilter0{}.filterCondition)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.filterCondition) - 120]byte
	_ [128 - unsafe.Offsetof(fwpmFilter0{}.action)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.action) - 128]byte
	_ [152 - unsafe.Offsetof(fwpmFilter0{}.providerContextKey)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.providerContextKey) - 152]byte
	_ [176 - unsafe.Offsetof(fwpmFilter0{}.filterID)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.filterID) - 176]byte
	_ [184 - unsafe.Offsetof(fwpmFilter0{}.effectiveWeight)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.effectiveWeight) - 184]byte

	_ [72 - unsafe.Sizeof(fwpmSession0{})]byte
	_ [unsafe.Sizeof(fwpmSession0{}) - 72]byte
	_ [32 - unsafe.Offsetof(fwpmSession0{}.flags)]byte
	_ [unsafe.Offsetof(fwpmSession0{}.flags) - 32]byte
	_ [48 - unsafe.Offsetof(fwpmSession0{}.sid)]byte
	_ [unsafe.Offsetof(fwpmSession0{}.sid) - 48]byte
	_ [64 - unsafe.Offsetof(fwpmSession0{}.kernelMode)]byte
	_ [unsafe.Offsetof(fwpmSession0{}.kernelMode) - 64]byte

	_ [72 - unsafe.Sizeof(fwpmSublayer0{})]byte
	_ [unsafe.Sizeof(fwpmSublayer0{}) - 72]byte
	_ [40 - unsafe.Offsetof(fwpmSublayer0{}.providerKey)]byte
	_ [unsafe.Offsetof(fwpmSublayer0{}.providerKey) - 40]byte
	_ [64 - unsafe.Offsetof(fwpmSublayer0{}.weight)]byte
	_ [unsafe.Offsetof(fwpmSublayer0{}.weight) - 64]byte
)

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0     = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmTransactionBegin0     = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmGetAppIdFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// The management functions return a Win32 error code directly rather than
// through GetLastError.
func fwpmResult(r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

func fwpmEngineOpen0(session *fwpmSession0, engine *uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmEngineOpen0.Addr(), 0, rpcCAuthnWinNT, 0,
		uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(engine)))
	return fwpmResult(r1)
}

func fwpmEngineClose0(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmEngineClose0.Addr(), engine)
	return fwpmResult(r1)
}

func fwpmSubLayerAdd0(engine uintptr, subLayer *fwpmSublayer0) error {
	r1, _, _ := syscall.SyscallN(procFwpmSubLayerAdd0.Addr(), engine, uintptr(unsafe.Pointer(subLayer)), 0)
	return fwpmResult(r1)
}

func fwpmFilterAdd0(engine uintptr, filter *fwpmFilter0, id *uint64) error {
	r1, _, _ := syscall.SyscallN(procFwpmFilterAdd0.Addr(), engine, uintptr(unsafe.Pointer(filter)), 0,
		uintptr(unsafe.Pointer(id)))
	return fwpmResult(r1)
}

func fwpmFilterDeleteById0(engine uintptr, id uint64) error {
	r1, _, _ := syscall.SyscallN(procFwpmFilterDeleteById0.Addr(), engine, uintptr(id))
	return fwpmResult(r1)
}

func fwpmTransactionBegin0(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionBegin0.Addr(), engine, 0)
	return fwpmResult(r1)
}

func fwpmTransactionCommit0(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionCommit0.Addr(), engine)
	return fwpmResult(r1)
}

func fwpmTransactionAbort0(engine uintptr) error {
	r1, _, _ := syscall.SyscallN(procFwpmTransactionAbort0.Addr(), engine)
	return fwpmResult(r1)
}

// fwpmGetAppIdFromFileName0 returns a blob WFP allocated; release it with
// fwpmFreeMemory0.
func fwpmGetAppIdFromFileName0(fileName *uint16, appID **fwpByteBlob) error {
	r1, _, _ := syscall.SyscallN(procFwpmGetAppIdFromFileName0.Addr(), uintptr(unsafe.Pointer(fileName)),
		uintptr(unsafe.Pointer(appID)))
	return fwpmResult(r1)
}

// fwpmFreeMemory0 takes the address of the pointer it frees and clears it.
func fwpmFreeMemory0(memory **fwpByteBlob) {
	_, _, _ = syscall.SyscallN(procFwpmFreeMemory0.Addr(), uintptr(unsafe.Pointer(memory)))
}
