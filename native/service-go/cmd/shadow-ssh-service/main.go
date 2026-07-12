package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"shadowssh/service/internal/app"
	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/windowsservice"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	endpointDefault := os.Getenv("SHADOW_SSH_SERVICE_ENDPOINT")
	if endpointDefault == "" {
		endpointDefault = protocol.DefaultEndpoint()
	}

	endpoint := flag.String("endpoint", endpointDefault, "Local IPC endpoint. Uses a Windows named pipe on Windows and a Unix socket on macOS/Linux.")
	stdio := flag.Bool("stdio", false, "Serve the service protocol on stdin/stdout.")
	serviceMode := flag.Bool("service", false, "Run as a Windows Service Control Manager service.")
	allowedClientSID := flag.String("allowed-client-sid", "", "Windows SID allowed to connect to the named pipe. Defaults to the current process user.")
	printCapabilities := flag.Bool("print-capabilities", false, "Print service capabilities as JSON and exit.")
	flag.Parse()
	if err := protocol.SetAllowedClientSID(*allowedClientSID); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	driver := platform.NewDriver()
	service := app.New(app.Options{
		AuthToken: os.Getenv("SHADOW_SSH_SERVICE_TOKEN"),
		Driver:    driver,
		Transport: "native-ipc",
	})
	var routingCleanupCompleted atomic.Bool

	if *printCapabilities {
		capabilities := struct {
			ProtocolVersion int `json:"protocolVersion"`
			platform.Capabilities
		}{ProtocolVersion: protocol.Version, Capabilities: driver.Capabilities()}
		if err := protocol.WriteJSONLine(os.Stdout, capabilities); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		return 0
	}
	defer func() {
		// A successful protocol or SCM shutdown already performed the bounded
		// routing rollback. Do not repeat the same potentially five-second cleanup
		// while the desktop client or service manager is waiting for process exit.
		if routingCleanupCompleted.Load() {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Shutdown(cleanupCtx); err != nil {
			writeFatal(fmt.Errorf("native service cleanup failed: %w", err))
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := func(commandCtx context.Context, command protocol.Command) protocol.CommandResult {
		result := service.HandleCommand(commandCtx, command)
		if result.Shutdown && result.Response.OK {
			routingCleanupCompleted.Store(true)
		}
		return result
	}
	if *stdio {
		closeInputDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = os.Stdin.Close()
			case <-closeInputDone:
			}
		}()
		err := protocol.ServeLines(ctx, os.Stdin, os.Stdout, handler)
		close(closeInputDone)
		if err != nil && !errors.Is(err, protocol.ErrShutdown) && !errors.Is(err, context.Canceled) {
			writeFatal(err)
			return 1
		}
		return 0
	}

	if *serviceMode {
		serviceName := os.Getenv("SHADOW_SSH_SERVICE_NAME")
		if serviceName == "" {
			serviceName = "ShadowSshService"
		}
		err := windowsservice.Run(ctx, serviceName, func(serviceCtx context.Context) error {
			serveErr := protocol.ServeEndpoint(serviceCtx, *endpoint, handler)
			if routingCleanupCompleted.Load() {
				return serveErr
			}

			// SCM must not receive SERVICE_STOPPED before routing rollback has
			// completed. Retry once inside the service lifetime; the outer deferred
			// cleanup remains a final fallback if both bounded attempts fail.
			var cleanupErr error
			for attempt := 0; attempt < 2; attempt++ {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				cleanupErr = service.Shutdown(cleanupCtx)
				cancel()
				if cleanupErr == nil {
					routingCleanupCompleted.Store(true)
					break
				}
			}
			if cleanupErr != nil {
				if serveErr == nil || errors.Is(serveErr, context.Canceled) {
					return fmt.Errorf("native service cleanup before SCM stop failed: %w", cleanupErr)
				}
				return errors.Join(serveErr, fmt.Errorf("native service cleanup before SCM stop failed: %w", cleanupErr))
			}
			return serveErr
		})
		if err != nil && !errors.Is(err, protocol.ErrShutdown) && !errors.Is(err, context.Canceled) {
			writeFatal(err)
			return 1
		}
		return 0
	}

	err := protocol.ServeEndpoint(ctx, *endpoint, handler)
	if err != nil && !errors.Is(err, protocol.ErrShutdown) && !errors.Is(err, context.Canceled) {
		writeFatal(err)
		return 1
	}
	return 0
}

func writeFatal(err error) {
	message := map[string]string{
		"level":   "error",
		"message": err.Error(),
	}
	encoded, marshalErr := json.Marshal(message)
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	fmt.Fprintln(os.Stderr, string(encoded))
}
