//go:build !windows

package protocol

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

func DefaultEndpoint() string {
	return filepath.Join(defaultRuntimeDirectory(), "shadow-ssh-"+strconv.Itoa(os.Getuid())+".sock")
}

func SetAllowedClientSID(value string) error {
	if value == "" {
		return nil
	}
	return ValidateWindowsSID(value)
}

func ServeEndpoint(ctx context.Context, endpoint string, handler Handler) error {
	if err := os.MkdirAll(filepath.Dir(endpoint), 0o700); err != nil {
		return err
	}
	if err := os.Remove(endpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(endpoint)
	}()
	if err := os.Chmod(endpoint, 0o600); err != nil {
		return err
	}

	shutdown := make(chan struct{})
	var closeOnce sync.Once
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	connectionLimiter := newEndpointConnectionLimiter()
	var connectionWG sync.WaitGroup
	closeConnections := func() {
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}
	closeForShutdown := func() {
		closeOnce.Do(func() {
			close(shutdown)
			_ = listener.Close()
			closeConnections()
		})
	}
	cancelWatcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			closeConnections()
		case <-cancelWatcherDone:
		}
	}()
	defer func() {
		close(cancelWatcherDone)
		_ = listener.Close()
		closeConnections()
		connectionWG.Wait()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-shutdown:
				return ErrShutdown
			default:
				return err
			}
		}
		if !connectionLimiter.tryAcquire() {
			_ = conn.Close()
			continue
		}

		connectionsMu.Lock()
		connections[conn] = struct{}{}
		connectionsMu.Unlock()
		connectionWG.Add(1)
		go func() {
			defer connectionWG.Done()
			defer connectionLimiter.release()
			defer conn.Close()
			defer func() {
				connectionsMu.Lock()
				delete(connections, conn)
				connectionsMu.Unlock()
			}()
			if err := ServeEndpointConnection(ctx, conn, handler); errors.Is(err, ErrShutdown) {
				closeForShutdown()
			}
		}()
	}
}

func defaultRuntimeDirectory() string {
	if value := os.Getenv("SHADOW_SSH_RUNTIME_DIR"); value != "" {
		return value
	}
	if value := os.Getenv("XDG_RUNTIME_DIR"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return filepath.Join(home, ".shadow-ssh", "run")
}
