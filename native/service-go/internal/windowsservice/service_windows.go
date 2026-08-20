//go:build windows

package windowsservice

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"unsafe"
)

const (
	serviceWin32OwnProcess = 0x00000010

	serviceStopped      = 0x00000001
	serviceStartPending = 0x00000002
	serviceStopPending  = 0x00000003
	serviceRunning      = 0x00000004

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop     = 0x00000001
	serviceControlShutdown = 0x00000005
)

var (
	advapi32                         = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW  = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerEx = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus             = advapi32.NewProc("SetServiceStatus")

	activeService *serviceRuntime
)

// syscall.NewCallback panics unless the function takes only uintptr-sized
// arguments and returns exactly one uintptr-sized result. The Win32 prototypes
// these implement return void, but Go has no way to express that, so both must
// return a uintptr the service control manager then ignores. These assertions
// state the shape the runtime demands, so a future edit to either signature
// fails to compile instead of panicking.
var (
	_ func(uint32, uintptr) uintptr                  = serviceMain
	_ func(uint32, uint32, uintptr, uintptr) uintptr = serviceControlHandler
)

// The callbacks are built on first use rather than at package initialisation.
//
// This package is linked into a binary whose usual job is to serve the stdio
// protocol, and a package-level syscall.NewCallback runs - and can panic -
// before main() does. That is exactly what happened: serviceMain returned
// nothing, so every launch of the helper died in init() with exit code 2,
// including the --stdio launches that never touch service mode. Process
// attribution and, later, the TUN dataplane both silently had no helper at all.
// Building them lazily keeps service-mode code from ever taking down a process
// that is not running as a service.
// The two callbacks are memoised separately: serviceMain has to look the
// control callback up while it runs, and a single OnceValues covering both
// would be an initialisation cycle.
var (
	serviceMainCallback    = sync.OnceValue(func() uintptr { return syscall.NewCallback(serviceMain) })
	serviceControlCallback = sync.OnceValue(func() uintptr { return syscall.NewCallback(serviceControlHandler) })
)

type serviceTableEntry struct {
	serviceName *uint16
	serviceProc uintptr
}

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

type serviceRuntime struct {
	name    string
	runner  func(context.Context) error
	ctx     context.Context
	cancel  context.CancelFunc
	handle  uintptr
	runErr  error
	stopped chan struct{}
}

func Run(ctx context.Context, serviceName string, runner func(context.Context) error) error {
	if serviceName == "" {
		serviceName = "ShadowSshService"
	}

	serviceCtx, cancel := context.WithCancel(ctx)
	runtime := &serviceRuntime{
		name:    serviceName,
		runner:  runner,
		ctx:     serviceCtx,
		cancel:  cancel,
		stopped: make(chan struct{}),
	}
	activeService = runtime
	defer func() {
		activeService = nil
		cancel()
	}()

	namePtr, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return err
	}
	table := []serviceTableEntry{
		{serviceName: namePtr, serviceProc: serviceMainCallback()},
		{},
	}

	ok, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if ok == 0 {
		return callErr
	}

	<-runtime.stopped
	return runtime.runErr
}

// serviceMain is LPSERVICE_MAIN_FUNCTIONW. Its result is ignored by the
// service control manager but must exist; see serviceCallbacks.
func serviceMain(uint32, uintptr) uintptr {
	runtime := activeService
	if runtime == nil {
		return 0
	}
	defer close(runtime.stopped)

	namePtr, err := syscall.UTF16PtrFromString(runtime.name)
	if err != nil {
		runtime.runErr = err
		return 0
	}

	handle, _, callErr := procRegisterServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(namePtr)),
		serviceControlCallback(),
		0,
	)
	if handle == 0 {
		runtime.runErr = callErr
		return 0
	}
	runtime.handle = handle

	setStatus(runtime, serviceStartPending, 0, 1, 3000)
	setStatus(runtime, serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)

	err = runtime.runner(runtime.ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		runtime.runErr = err
		setStatus(runtime, serviceStopped, 0, 0, 0)
		return 0
	}

	setStatus(runtime, serviceStopped, 0, 0, 0)
	return 0
}

func serviceControlHandler(control uint32, _ uint32, _ uintptr, _ uintptr) uintptr {
	runtime := activeService
	if runtime == nil {
		return 0
	}

	switch control {
	case serviceControlStop, serviceControlShutdown:
		// The runner waits for any in-flight bounded mutation and performs up to
		// two five-second routing rollbacks before returning.
		setStatus(runtime, serviceStopPending, 0, 1, 20000)
		runtime.cancel()
	}
	return 0
}

func setStatus(runtime *serviceRuntime, state uint32, accepted uint32, checkpoint uint32, waitHint uint32) {
	if runtime.handle == 0 {
		return
	}

	status := serviceStatus{
		serviceType:      serviceWin32OwnProcess,
		currentState:     state,
		controlsAccepted: accepted,
		win32ExitCode:    0,
		checkPoint:       checkpoint,
		waitHint:         waitHint,
	}
	_, _, _ = procSetServiceStatus.Call(runtime.handle, uintptr(unsafe.Pointer(&status)))
}
