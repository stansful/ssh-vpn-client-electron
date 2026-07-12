//go:build windows

package windowsservice

import (
	"context"
	"errors"
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

	serviceMainCallback    = syscall.NewCallback(serviceMain)
	serviceControlCallback = syscall.NewCallback(serviceControlHandler)
	activeService          *serviceRuntime
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
		{serviceName: namePtr, serviceProc: serviceMainCallback},
		{},
	}

	ok, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if ok == 0 {
		return callErr
	}

	<-runtime.stopped
	return runtime.runErr
}

func serviceMain(uint32, uintptr) {
	runtime := activeService
	if runtime == nil {
		return
	}
	defer close(runtime.stopped)

	namePtr, err := syscall.UTF16PtrFromString(runtime.name)
	if err != nil {
		runtime.runErr = err
		return
	}

	handle, _, callErr := procRegisterServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(namePtr)),
		serviceControlCallback,
		0,
	)
	if handle == 0 {
		runtime.runErr = callErr
		return
	}
	runtime.handle = handle

	setStatus(runtime, serviceStartPending, 0, 1, 3000)
	setStatus(runtime, serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)

	err = runtime.runner(runtime.ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		runtime.runErr = err
		setStatus(runtime, serviceStopped, 0, 0, 0)
		return
	}

	setStatus(runtime, serviceStopped, 0, 0, 0)
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
