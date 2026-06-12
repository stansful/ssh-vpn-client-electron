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
	return filepath.Join(os.TempDir(), "shadow-ssh-"+strconv.Itoa(os.Getuid())+".sock")
}

func ServeEndpoint(ctx context.Context, endpoint string, handler Handler) error {
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
