//go:build windows

package protocol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	pipeAccessDuplex = 0x00000003
	// FILE_FLAG_FIRST_PIPE_INSTANCE prevents another local process from
	// pre-creating the service pipe and impersonating the privileged endpoint.
	// It is valid only for the first instance; later instances share the name
	// owned by that first listener.
	fileFlagFirstPipeInstance = 0x00080000
	pipeTypeByte              = 0x00000000
	pipeReadModeByte          = 0x00000000
	pipeWait                  = 0x00000000
	pipeNowait                = 0x00000001
	// Do not allow SMB/remote named-pipe clients even if their credentials would
	// otherwise satisfy the DACL. This control plane is intentionally local-only.
	pipeRejectRemoteClients = 0x00000008
	pipeMaxInstances        = MaxEndpointConnections + 2
	pipeBufferBytes         = 64 * 1024
	errorPipeConnected      = 535
	errorPipeListening      = 536
	invalidHandleValue      = ^uintptr(0)
	pipeConnectRetryMin     = 25 * time.Millisecond
	pipeConnectRetryMax     = 500 * time.Millisecond
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procCreateNamedPipeW    = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = kernel32.NewProc("DisconnectNamedPipe")
	procSetNamedPipeState   = kernel32.NewProc("SetNamedPipeHandleState")
	procConvertSDDLToSD     = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree           = kernel32.NewProc("LocalFree")
	allowedClientSID        string
)

func DefaultEndpoint() string {
	return `\\.\pipe\shadow-ssh-service`
}

func SetAllowedClientSID(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		if err := ValidateWindowsSID(value); err != nil {
			return err
		}
	}
	allowedClientSID = value
	return nil
}

func ServeEndpoint(ctx context.Context, endpoint string, handler Handler) error {
	serveCtx, cancel := context.WithCancel(ctx)
	shutdown := make(chan struct{})
	var closeOnce sync.Once
	var connectionWG sync.WaitGroup
	connectionLimiter := newEndpointConnectionLimiter()
	defer func() {
		cancel()
		connectionWG.Wait()
	}()

	handle, err := createPipe(endpoint, true)
	if err != nil {
		return err
	}
	for {
		connectedHandle := handle
		var closeHandleOnce sync.Once
		closeHandle := func() {
			closeHandleOnce.Do(func() {
				_ = syscall.CloseHandle(connectedHandle)
			})
		}

		err = connectPipe(serveCtx, shutdown, connectedHandle)
		if err != nil {
			closeHandle()
			select {
			case <-shutdown:
				return ErrShutdown
			default:
			}
			if serveCtx.Err() != nil {
				return serveCtx.Err()
			}
			return err
		}
		if serveCtx.Err() != nil {
			closeHandle()
			return serveCtx.Err()
		}
		select {
		case <-shutdown:
			closeHandle()
			return ErrShutdown
		default:
		}

		file := os.NewFile(uintptr(connectedHandle), endpoint)
		if file == nil {
			closeHandle()
			return errors.New("failed to wrap named pipe handle")
		}
		// Create the next listening instance while this connected instance is
		// still owned by the service. There is never a zero-instance namespace gap
		// in which another process can pre-create and impersonate the pipe name.
		nextHandle, nextErr := createPipe(endpoint, false)
		if nextErr != nil {
			_ = file.Close()
			return nextErr
		}
		if !connectionLimiter.tryAcquire() {
			_ = file.Close()
			handle = nextHandle
			continue
		}

		connectionWG.Add(1)
		go func(connection *os.File, pipeHandle syscall.Handle) {
			defer connectionWG.Done()
			defer connectionLimiter.release()
			defer connection.Close()
			if err := ServeEndpointConnection(serveCtx, connection, handler); errors.Is(err, ErrShutdown) {
				closeOnce.Do(func() {
					close(shutdown)
					cancel()
				})
			}
			_, _, _ = procDisconnectNamedPipe.Call(uintptr(pipeHandle))
		}(file, connectedHandle)
		handle = nextHandle
	}
}

func createPipe(endpoint string, firstInstance bool) (syscall.Handle, error) {
	pipeName, err := syscall.UTF16PtrFromString(endpoint)
	if err != nil {
		return 0, err
	}

	securityAttributes, freeSecurity, err := pipeSecurityAttributes()
	if err != nil {
		return 0, err
	}
	defer freeSecurity()

	openMode := uintptr(pipeAccessDuplex)
	if firstInstance {
		openMode |= uintptr(fileFlagFirstPipeInstance)
	}
	handle, _, callErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeName)),
		openMode,
		uintptr(pipeTypeByte|pipeReadModeByte|pipeNowait|pipeRejectRemoteClients),
		uintptr(pipeMaxInstances),
		uintptr(pipeBufferBytes),
		uintptr(pipeBufferBytes),
		uintptr(0),
		uintptr(unsafe.Pointer(securityAttributes)),
	)
	if handle == invalidHandleValue {
		return 0, callErr
	}
	return syscall.Handle(handle), nil
}

func connectPipe(ctx context.Context, shutdown <-chan struct{}, handle syscall.Handle) error {
	retryInterval := pipeConnectRetryMin
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	for {
		ok, _, err := procConnectNamedPipe.Call(uintptr(handle), 0)
		if ok != 0 {
			return setPipeBlocking(handle)
		}
		errno, isErrno := err.(syscall.Errno)
		if isErrno && errno == errorPipeConnected {
			return setPipeBlocking(handle)
		}
		if !isErrno || errno != errorPipeListening {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-shutdown:
			return ErrShutdown
		case <-timer.C:
		}
		// PIPE_NOWAIT is required so cancellation can be observed without a
		// blocked OS thread. Poll promptly while the service is starting, then
		// back off to two checks per second when no desktop client is connected.
		// Reuse one timer to avoid allocations in this long-lived idle loop.
		if retryInterval < pipeConnectRetryMax {
			retryInterval *= 2
			if retryInterval > pipeConnectRetryMax {
				retryInterval = pipeConnectRetryMax
			}
		}
		timer.Reset(retryInterval)
	}
}

func setPipeBlocking(handle syscall.Handle) error {
	mode := uint32(pipeReadModeByte | pipeWait)
	ok, _, err := procSetNamedPipeState.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)), 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}

func pipeSecurityAttributes() (*syscall.SecurityAttributes, func(), error) {
	clientSID := allowedClientSID
	if clientSID == "" {
		current, err := user.Current()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve current Windows user SID: %w", err)
		}
		clientSID = current.Uid
	}
	descriptor, err := WindowsPipeSecurityDescriptor(clientSID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid allowed Windows client SID: %w", err)
	}
	// Limit the pipe to LocalSystem, administrators, and the exact desktop user
	// selected at service installation. "Interactive Users" would expose the
	// privileged control plane to unrelated RDP/local sessions.
	sddl, err := syscall.UTF16PtrFromString(descriptor)
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
