//go:build windows

package tun

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	waitFailed       = 0xFFFFFFFF
	errorNoMoreItems = syscall.Errno(259)
	// maxPacketBytes bounds one packet. WinTun's own limit is 0xFFFF; the
	// buffer is allocated once and reused, so sizing it at the maximum costs
	// 64 KiB for the life of the adapter.
	maxPacketBytes = 0xFFFF
	// createAttempts and createRetryDelay cover an adapter that the previous
	// run has closed but Windows has not finished removing. Reconnecting a
	// tunnel destroys and recreates the adapter within a second or two, which
	// is exactly the window where the old device node can still be present.
	createAttempts   = 6
	createRetryDelay = 400 * time.Millisecond
	// Ring reads park on the adapter's event; a bounded wait lets Close()
	// unblock the reader without relying on the driver signalling first.
	readWaitMs = 250
)

var (
	// A failed load is not memoised: the DLL is a file the user drops next to
	// the executable, and a build that cached "missing" forever would keep
	// reporting no TUN support until the app was restarted.
	wintunMu     sync.Mutex
	wintunLoaded bool

	wintun                   *syscall.LazyDLL
	procCreateAdapter        *syscall.LazyProc
	procCloseAdapter         *syscall.LazyProc
	procGetAdapterLUID       *syscall.LazyProc
	procStartSession         *syscall.LazyProc
	procEndSession           *syscall.LazyProc
	procGetReadWaitEvent     *syscall.LazyProc
	procReceivePacket        *syscall.LazyProc
	procReleaseReceivePacket *syscall.LazyProc
	procAllocateSendPacket   *syscall.LazyProc
	procSendPacket           *syscall.LazyProc

	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procWaitForSingle = kernel32.NewProc("WaitForSingleObject")
)

// loadWintun resolves wintun.dll once. The DLL ships next to the service
// binary, so the default search path finds it without a manifest entry.
func loadWintun() error {
	wintunMu.Lock()
	defer wintunMu.Unlock()
	if wintunLoaded {
		return nil
	}

	// Every candidate is an absolute path rather than a bare name: it keeps the
	// error able to list exactly where it looked, and avoids the default DLL
	// search order picking up a wintun.dll from somewhere unrelated.
	candidates := searchPaths()
	var loaded *syscall.LazyDLL
	for _, candidate := range candidates {
		dll := syscall.NewLazyDLL(candidate)
		if err := dll.Load(); err == nil {
			loaded = dll
			break
		}
	}
	if loaded == nil {
		return fmt.Errorf("%s was not found in any of: %s", wintunDLL, strings.Join(candidates, ", "))
	}
	wintun = loaded
	procCreateAdapter = wintun.NewProc("WintunCreateAdapter")
	procCloseAdapter = wintun.NewProc("WintunCloseAdapter")
	procGetAdapterLUID = wintun.NewProc("WintunGetAdapterLUID")
	procStartSession = wintun.NewProc("WintunStartSession")
	procEndSession = wintun.NewProc("WintunEndSession")
	procGetReadWaitEvent = wintun.NewProc("WintunGetReadWaitEvent")
	procReceivePacket = wintun.NewProc("WintunReceivePacket")
	procReleaseReceivePacket = wintun.NewProc("WintunReleaseReceivePacket")
	procAllocateSendPacket = wintun.NewProc("WintunAllocateSendPacket")
	procSendPacket = wintun.NewProc("WintunSendPacket")
	for _, proc := range []*syscall.LazyProc{
		procCreateAdapter, procCloseAdapter, procGetAdapterLUID,
		procStartSession, procEndSession, procGetReadWaitEvent,
		procReceivePacket, procReleaseReceivePacket,
		procAllocateSendPacket, procSendPacket,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("resolve %s: %w", proc.Name, err)
		}
	}
	wintunLoaded = true
	return nil
}

// available loads wintun.dll and resolves its entry points without creating an
// adapter, which is the part that needs administrator rights. A missing DLL and
// a missing privilege are different problems and are reported separately.
func available() error {
	return loadWintun()
}

type windowsAdapter struct {
	// state guards the lifetime of the session and adapter handles. Readers and
	// writers hold it shared for the whole of a WinTun call - including the
	// bounded wait - and Close takes it exclusively, so the driver can never
	// tear a session down underneath a call already inside it. Close therefore
	// waits at most one readWaitMs for a parked reader.
	state sync.RWMutex
	// read serialises ring reads. WinTun allows one reader per session, and the
	// shared lock above does not provide that on its own.
	read sync.Mutex

	adapter   uintptr
	session   uintptr
	readEvent uintptr
	luid      uint64
	closed    bool
	// packet is the buffer handed back to callers. The ring slice is copied
	// into it and released before ReceivePacket returns, so a caller can hold
	// its result across a Close without reading freed driver memory.
	packet []byte
}

// Open creates the adapter and starts its packet session. It requires
// administrator rights; without them WintunCreateAdapter fails.
func Open(config Config) (Adapter, error) {
	if err := loadWintun(); err != nil {
		return nil, err
	}
	capacity := config.ringCapacity()
	if capacity < MinRingCapacity || capacity > MaxRingCapacity || capacity&(capacity-1) != 0 {
		return nil, fmt.Errorf("ring capacity %d must be a power of two between %d and %d", capacity, MinRingCapacity, MaxRingCapacity)
	}

	name, err := syscall.UTF16PtrFromString(config.Name)
	if err != nil {
		return nil, fmt.Errorf("adapter name: %w", err)
	}
	tunnelType, err := syscall.UTF16PtrFromString(config.TunnelType)
	if err != nil {
		return nil, fmt.Errorf("tunnel type: %w", err)
	}

	handle, callErr := createAdapter(name, tunnelType)
	if handle == 0 {
		return nil, fmt.Errorf("create adapter %q: %w", config.Name, callErr)
	}

	adapter := &windowsAdapter{adapter: handle, packet: make([]byte, maxPacketBytes)}
	procGetAdapterLUID.Call(handle, uintptr(unsafe.Pointer(&adapter.luid)))

	session, _, callErr := procStartSession.Call(handle, uintptr(capacity))
	if session == 0 {
		procCloseAdapter.Call(handle)
		return nil, fmt.Errorf("start session: %w", callErr)
	}
	adapter.session = session

	event, _, _ := procGetReadWaitEvent.Call(session)
	adapter.readEvent = event
	return adapter, nil
}

// createAdapter retries a failed creation for a short while.
//
// Removing an adapter is asynchronous on the Windows side: WintunCloseAdapter
// returns before the device node is gone. A tunnel that is switched off and
// straight back on therefore meets its own leftover adapter, and a single
// attempt turns that into "TUN is unavailable" for the rest of the session -
// with the app silently back on the proxy path, where process rules do not
// hold.
func createAdapter(name *uint16, tunnelType *uint16) (uintptr, error) {
	var lastErr error
	for attempt := 0; attempt < createAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(createRetryDelay)
		}
		handle, _, callErr := procCreateAdapter.Call(
			uintptr(unsafe.Pointer(name)),
			uintptr(unsafe.Pointer(tunnelType)),
			0,
		)
		if handle != 0 {
			return handle, nil
		}
		lastErr = createAdapterError(callErr)
	}
	return 0, lastErr
}

// createAdapterError keeps a failure from reporting itself as "Success".
//
// LazyProc.Call always hands back the thread's last error, which is zero when
// the DLL returned NULL without setting one - so the obvious wording turns a
// failure into a line that reads like everything worked.
func createAdapterError(callErr error) error {
	if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
		return errors.New("the driver returned no adapter and reported no error; check that wintun.dll is the signed WireGuard build and matches this executable's architecture")
	}
	if callErr == nil {
		return errors.New("the driver returned no adapter")
	}
	return callErr
}

func (a *windowsAdapter) LUID() uint64 {
	return a.luid
}

func (a *windowsAdapter) ReceivePacket() ([]byte, error) {
	a.read.Lock()
	defer a.read.Unlock()
	for {
		packet, err, done := a.receiveOnce()
		if done {
			return packet, err
		}
	}
}

// receiveOnce runs one ring poll and, if the ring was empty, one bounded wait,
// entirely inside the shared lock. Returning the loop decision rather than
// looping in place is what keeps the lock scoped to a deferred unlock.
func (a *windowsAdapter) receiveOnce() ([]byte, error, bool) {
	a.state.RLock()
	defer a.state.RUnlock()
	if a.closed {
		return nil, ErrAdapterClosed, true
	}

	var size uint32
	packet, _, callErr := procReceivePacket.Call(a.session, uintptr(unsafe.Pointer(&size)))
	if packet != 0 {
		if int(size) > len(a.packet) {
			size = uint32(len(a.packet))
		}
		copied := copy(a.packet, unsafe.Slice((*byte)(unsafe.Pointer(packet)), size))
		// Released immediately: the ring reclaims memory only on release, and
		// holding one across the next call would let Close free it while the
		// caller still had a slice into it.
		procReleaseReceivePacket.Call(a.session, packet)
		return a.packet[:copied], nil, true
	}

	// Call() always reports the thread's last error, so it is only meaningful
	// once the return value has shown failure. An empty ring is the normal
	// case; anything else is terminal for this session and is better reported
	// than spun on.
	if errno, ok := callErr.(syscall.Errno); ok && errno != 0 && errno != errorNoMoreItems {
		return nil, fmt.Errorf("receive packet: %w", errno), true
	}

	// Park until the driver signals data, re-checking closure periodically so
	// Close() does not have to wait for traffic to arrive.
	result, _, _ := procWaitForSingle.Call(a.readEvent, uintptr(readWaitMs))
	if uint32(result) == waitFailed {
		return nil, errors.New("tun read wait failed"), true
	}
	return nil, nil, false
}

func (a *windowsAdapter) SendPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	a.state.RLock()
	defer a.state.RUnlock()
	if a.closed {
		return ErrAdapterClosed
	}

	buffer, _, callErr := procAllocateSendPacket.Call(a.session, uintptr(len(packet)))
	if buffer == 0 {
		return fmt.Errorf("allocate send packet: %w", callErr)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len(packet)), packet)
	procSendPacket.Call(a.session, buffer)
	return nil
}

// Close ends the session and removes the adapter. It blocks until any call
// already inside the driver has returned - at most one bounded read wait.
func (a *windowsAdapter) Close() error {
	a.state.Lock()
	defer a.state.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.session != 0 {
		procEndSession.Call(a.session)
		a.session = 0
	}
	if a.adapter != 0 {
		procCloseAdapter.Call(a.adapter)
		a.adapter = 0
	}
	return nil
}
