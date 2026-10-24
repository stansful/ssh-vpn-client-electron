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

	"golang.org/x/sys/windows"
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

	wintun                   *windows.DLL
	procCreateAdapter        *windows.Proc
	procCloseAdapter         *windows.Proc
	procGetAdapterLUID       *windows.Proc
	procStartSession         *windows.Proc
	procEndSession           *windows.Proc
	procGetReadWaitEvent     *windows.Proc
	procReceivePacket        *windows.Proc
	procReleaseReceivePacket *windows.Proc
	procAllocateSendPacket   *windows.Proc
	procSendPacket           *windows.Proc

	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procWaitForSingle = kernel32.NewProc("WaitForSingleObject")
)

// loadWintun resolves wintun.dll once. The DLL ships next to the service
// binary; the other folders searchPaths lists are where a user can add it.
func loadWintun() error {
	wintunMu.Lock()
	defer wintunMu.Unlock()
	if wintunLoaded {
		return nil
	}

	// Every candidate is an absolute path rather than a bare name: it keeps the
	// error able to list exactly where it looked, and avoids the default DLL
	// search order picking up a wintun.dll from somewhere unrelated. Each one is
	// verified before it is loaded (see verify.go); one that fails is skipped
	// and said so, not loaded.
	candidates := searchPaths()
	var loaded *windows.DLL
	var problems []string
	anyPresent := false
	for _, candidate := range candidates {
		dll, err := loadVerifiedWintun(candidate)
		if err == nil {
			loaded = dll
			break
		}
		if !errors.Is(err, errWintunMissing) {
			anyPresent = true
		}
		problems = append(problems, candidate+": "+err.Error())
	}
	if loaded == nil {
		if !anyPresent {
			return fmt.Errorf("%s was not found in any of: %s", wintunDLL, strings.Join(candidates, ", "))
		}
		return fmt.Errorf("no usable %s: %s", wintunDLL, strings.Join(problems, "; "))
	}

	var findErr error
	find := func(name string) *windows.Proc {
		proc, err := loaded.FindProc(name)
		if err != nil && findErr == nil {
			findErr = fmt.Errorf("resolve %s: %w", name, err)
		}
		return proc
	}
	createAdapter := find("WintunCreateAdapter")
	closeAdapter := find("WintunCloseAdapter")
	getAdapterLUID := find("WintunGetAdapterLUID")
	startSession := find("WintunStartSession")
	endSession := find("WintunEndSession")
	getReadWaitEvent := find("WintunGetReadWaitEvent")
	receivePacket := find("WintunReceivePacket")
	releaseReceivePacket := find("WintunReleaseReceivePacket")
	allocateSendPacket := find("WintunAllocateSendPacket")
	sendPacket := find("WintunSendPacket")
	if findErr != nil {
		_ = loaded.Release()
		return findErr
	}
	wintun = loaded
	procCreateAdapter = createAdapter
	procCloseAdapter = closeAdapter
	procGetAdapterLUID = getAdapterLUID
	procStartSession = startSession
	procEndSession = endSession
	procGetReadWaitEvent = getReadWaitEvent
	procReceivePacket = receivePacket
	procReleaseReceivePacket = releaseReceivePacket
	procAllocateSendPacket = allocateSendPacket
	procSendPacket = sendPacket
	wintunLoaded = true
	return nil
}

// available loads wintun.dll and resolves its entry points without creating an
// adapter, which is the part that needs administrator rights. A missing DLL and
// a missing privilege are different problems and are reported separately. It
// runs at every capability handshake, so it loads nothing that loadWintun has
// not verified.
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
		copied := copy(a.packet, ringBytes(packet, int(size)))
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
	copy(ringBytes(buffer, len(packet)), packet)
	procSendPacket.Call(a.session, buffer)
	return nil
}

// ringBytes views n bytes of the driver's ring memory at address, which a
// wintun call returned as an integer. The memory is not Go's and never moves,
// so the integer is the only reference there is; reading it back through a
// *uintptr says so to go vet, which otherwise takes it for a Go pointer that
// was laundered through an integer.
func ringBytes(address uintptr, n int) []byte {
	return unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&address))), n)
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
