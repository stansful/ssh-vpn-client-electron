//go:build !windows

package windowsservice

import (
	"context"
	"errors"
)

var ErrUnsupported = errors.New("Windows Service Control Manager is only available on Windows")

func Run(context.Context, string, func(context.Context) error) error {
	return ErrUnsupported
}
