package platform

import (
	"errors"
	"strings"
	"testing"
)

func TestTUNReadinessNamesTheMissingPrerequisite(t *testing.T) {
	// A user running as the Administrator account, told only "start as
	// administrator", has no way to discover that the real problem is a DLL in
	// the wrong folder. Each cause has to name itself.
	missingDriver := errors.New(`wintun.dll was not found next to the service binary in C:\App\native\windows\x64: Module not found`)

	if ready, reason := describeTUNReadiness(true, nil); !ready || reason != "" {
		t.Fatalf("expected an elevated process with the driver to be ready, got %v %q", ready, reason)
	}

	ready, reason := describeTUNReadiness(true, missingDriver)
	if ready || !strings.Contains(reason, "wintun.dll") || strings.Contains(reason, "not elevated") {
		t.Fatalf("expected the driver to be blamed alone, got %v %q", ready, reason)
	}
	if !strings.Contains(reason, `C:\App\native\windows\x64`) {
		t.Fatalf("expected the directory to be named, got %q", reason)
	}

	ready, reason = describeTUNReadiness(false, nil)
	if ready || !strings.Contains(reason, "not elevated") || strings.Contains(reason, "wintun.dll") {
		t.Fatalf("expected elevation to be blamed alone, got %v %q", ready, reason)
	}

	ready, reason = describeTUNReadiness(false, missingDriver)
	if ready || !strings.Contains(reason, "not elevated") || !strings.Contains(reason, "wintun.dll") {
		t.Fatalf("expected both causes to be reported, got %v %q", ready, reason)
	}
}
