package platform

import (
	"path/filepath"
	"runtime"
)

func CurrentTarget() Target {
	platformName := desktopPlatform(runtime.GOOS)
	archName := runtimeArch(runtime.GOARCH)
	executableName := "shadow-ssh-service"
	if platformName == "windows" {
		executableName += ".exe"
	}

	supported := platformName != "unknown" && archName != "unknown"
	return Target{
		Platform:                  platformName,
		Arch:                      archName,
		ServiceExecutableName:     executableName,
		ServiceRelativePath:       filepath.ToSlash(filepath.Join("native", platformName, archName, executableName)),
		SupportsPrivilegedService: supported,
	}
}

func desktopPlatform(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	default:
		return "unknown"
	}
}

func runtimeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "ia32"
	default:
		return "unknown"
	}
}
