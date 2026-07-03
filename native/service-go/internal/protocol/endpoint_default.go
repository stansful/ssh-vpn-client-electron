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
	_ = os.Chmod(endpoint, 0o600)

	shutdown := make(chan struct{})
	var closeOnce sync.Once
	closeForShutdown := func() {
		closeOnce.Do(func() {
			close(shutdown)
			_ = listener.Close()
		})
	}

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

		go func() {
			defer conn.Close()
			if err := ServeLines(ctx, conn, conn, handler); errors.Is(err, ErrShutdown) {
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
