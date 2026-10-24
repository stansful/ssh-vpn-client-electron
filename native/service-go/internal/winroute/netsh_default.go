//go:build !windows

package winroute

import "os/exec"

// netshPath has nothing to find off Windows.
func netshPath() (string, error) {
	return "", ErrNotSupported
}

// hideConsole has no console to hide off Windows.
func hideConsole(*exec.Cmd) {}
