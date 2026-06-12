//go:build windows

package protocol

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

const (
	pipeAccessDuplex   = 0x00000003
	pipeTypeByte       = 0x00000000
	pipeReadModeByte   = 0x00000000
	pipeWait           = 0x00000000
	pipeUnlimited      = 255
	errorPipeConnected = 535
	invalidHandleValue = ^uintptr(0)
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procCreateNamedPipeW    = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = kernel32.NewProc("DisconnectNamedPipe")
	procConvertSDDLToSD     = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree           = kernel32.NewProc("LocalFree")
)

func DefaultEndpoint() string {
	return `\\.\pipe\shadow-ssh-service`
}

func ServeEndpoint(ctx context.Context, endpoint string, handler Handler) error {
	shutdown := make(chan struct{})
	var closeOnce sync.Once

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-shutdown:
			return ErrShutdown
		default:
		}

		handle, cleanup, err := createPipe(endpoint)
		if err != nil {
			return err
		}

		connectDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = syscall.CloseHandle(handle)
			case <-connectDone:
			}
		}()
		err = connectPipe(handle)
		close(connectDone)
		if err != nil {
			cleanup()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		file := os.NewFile(uintptr(handle), endpoint)
		if file == nil {
			cleanup()
			return errors.New("failed to wrap named pipe handle")
		}

		go func() {
			defer file.Close()
			defer cleanup()
			cancelRead := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = file.Close()
				case <-cancelRead:
				}
			}()
			defer close(cancelRead)
			if err := ServeLines(ctx, file, file, handler); errors.Is(err, ErrShutdown) {
				closeOnce.Do(func() {
					close(shutdown)
				})
			}
			_, _, _ = procDisconnectNamedPipe.Call(uintptr(handle))
		}()
	}
}

func createPipe(endpoint string) (syscall.Handle, func(), error) {
	pipeName, err := syscall.UTF16PtrFromString(endpoint)
	if err != nil {
		return 0, nil, err
	}

	securityAttributes, freeSecurity, err := pipeSecurityAttributes()
	if err != nil {
		return 0, nil, err
	}

	handle, _, callErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeName)),
		uintptr(pipeAccessDuplex),
		uintptr(pipeTypeByte|pipeReadModeByte|pipeWait),
		uintptr(pipeUnlimited),
		uintptr(MaxWireLineBytes),
		uintptr(MaxWireLineBytes),
		uintptr(0),
		uintptr(unsafe.Pointer(securityAttributes)),
	)
	if handle == invalidHandleValue {
		freeSecurity()
		return 0, nil, callErr
	}

	cleanup := func() {
		freeSecurity()
		_ = syscall.CloseHandle(syscall.Handle(handle))
	}
	return syscall.Handle(handle), cleanup, nil
}

func connectPipe(handle syscall.Handle) error {
	ok, _, err := procConnectNamedPipe.Call(uintptr(handle), 0)
	if ok != 0 {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok && errno == errorPipeConnected {
		return nil
	}
	return err
}

func pipeSecurityAttributes() (*syscall.SecurityAttributes, func(), error) {
	sddl, err := syscall.UTF16PtrFromString(`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`)
	if err != nil {
		return nil, nil, err
	}

	var securityDescriptor uintptr
	ok, _, callErr := procConvertSDDLToSD.Call(
		uintptr(unsafe.Pointer(sddl)),
		uintptr(1),
		uintptr(unsafe.Pointer(&securityDescriptor)),
		0,
	)
	if ok == 0 {
		return nil, nil, callErr
	}

	attributes := &syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
		InheritHandle:      0,
	}

	return attributes, func() {
		_, _, _ = procLocalFree.Call(securityDescriptor)
	}, nil
}
