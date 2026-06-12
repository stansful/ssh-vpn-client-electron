package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"shadowssh/service/internal/app"
	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/windowsservice"
)

func main() {
	os.Exit(run())
}

func run() int {
	endpointDefault := os.Getenv("SHADOW_SSH_SERVICE_ENDPOINT")
	if endpointDefault == "" {
		endpointDefault = protocol.DefaultEndpoint()
	}

	endpoint := flag.String("endpoint", endpointDefault, "Local IPC endpoint. Uses a Windows named pipe on Windows and a Unix socket on macOS/Linux.")
	stdio := flag.Bool("stdio", false, "Serve the service protocol on stdin/stdout.")
	serviceMode := flag.Bool("service", false, "Run as a Windows Service Control Manager service.")
	printCapabilities := flag.Bool("print-capabilities", false, "Print service capabilities as JSON and exit.")
	flag.Parse()

	driver := platform.NewDriver()
	service := app.New(app.Options{
		AuthToken: os.Getenv("SHADOW_SSH_SERVICE_TOKEN"),
		Driver:    driver,
		Transport: "native-ipc",
	})

	if *printCapabilities {
		if err := protocol.WriteJSONLine(os.Stdout, driver.Capabilities()); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := service.HandleCommand
	if *stdio {
		err := protocol.ServeLines(ctx, os.Stdin, os.Stdout, handler)
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
			return protocol.ServeEndpoint(serviceCtx, *endpoint, handler)
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
