//go:build windows

package winroute

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNetshIsStartedWithoutAConsole(t *testing.T) {
	command := exec.Command("netsh.exe")
	hideConsole(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.HideWindow ||
		command.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("netsh would get a console window: %+v", command.SysProcAttr)
	}
}
