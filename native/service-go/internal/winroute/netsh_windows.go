//go:build windows

package winroute

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// netshPath is netsh.exe in the system directory. GetSystemDirectory answers
// from the running system rather than from %SystemRoot%, which - like PATH -
// comes from an environment the user controls.
func netshPath() (string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("locate the Windows system directory: %w", err)
	}
	return filepath.Join(system, "netsh.exe"), nil
}

// hideConsole starts netsh without a console of its own. The app starts this
// helper detached, so that it outlives Electron while it takes its routes
// down, and a detached process has no console for netsh to share: Windows
// would give every netsh, a console program, a new and visible one - a window
// flashing up, or a Windows Terminal tab, for each route on every connect and
// disconnect.
func hideConsole(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
