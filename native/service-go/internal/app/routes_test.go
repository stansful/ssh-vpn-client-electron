package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"shadowssh/service/internal/dataplane"
	"shadowssh/service/internal/platform"
	"shadowssh/service/internal/winroute"
)

type recoveryCall struct {
	journalPath string
}

func newRecoveringApp(result int, err error) (*App, *[]recoveryCall) {
	var calls []recoveryCall
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	service.recoverRoutes = func(_ context.Context, journalPath string, _ func(string, string)) (int, error) {
		calls = append(calls, recoveryCall{journalPath: journalPath})
		return result, err
	}
	return service, &calls
}

// realTempDir is a fresh folder by the path it really has: the system's temp
// folder is itself reached through a link on some machines.
func realTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRecoverRoutesRunsTheJournalRecovery(t *testing.T) {
	service, calls := newRecoveringApp(3, nil)
	journalPath := filepath.Join(realTempDir(t), winroute.JournalFileName)
	result := service.HandleCommand(context.Background(), command("1", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath}))
	if !result.Response.OK {
		t.Fatalf("expected recovery to succeed, got %+v", result.Response)
	}
	payload, ok := result.Response.Payload.(RouteRecoveryResult)
	if !ok || payload.Recovered != 3 {
		t.Fatalf("expected {recovered: 3}, got %#v", result.Response.Payload)
	}
	if len(*calls) != 1 || (*calls)[0].journalPath != journalPath {
		t.Fatalf("expected one recovery of %s, got %+v", journalPath, *calls)
	}
}

func TestRecoverRoutesFollowsALinkedDataFolder(t *testing.T) {
	// A data folder moved to another drive and linked back is recovered where
	// it really is, not refused.
	service, calls := newRecoveringApp(0, nil)
	dataFolder := realTempDir(t)
	linked := filepath.Join(t.TempDir(), "Shadow SSH")
	if err := os.Symlink(dataFolder, linked); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	result := service.HandleCommand(context.Background(), command("1", "recover-routes",
		RouteRecoveryPayload{JournalPath: filepath.Join(linked, winroute.JournalFileName)}))
	if !result.Response.OK {
		t.Fatalf("expected the linked data folder to be accepted, got %+v", result.Response)
	}
	if want := filepath.Join(dataFolder, winroute.JournalFileName); len(*calls) != 1 || (*calls)[0].journalPath != want {
		t.Fatalf("expected one recovery of %s, got %+v", want, *calls)
	}
}

func TestRecoverRoutesReportsAFailedRecovery(t *testing.T) {
	service, _ := newRecoveringApp(1, errors.New("2 routing changes from a previous run could not be undone"))
	journalPath := filepath.Join(t.TempDir(), winroute.JournalFileName)
	result := service.HandleCommand(context.Background(), command("1", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath}))
	if result.Response.OK || !strings.Contains(result.Response.Error, "could not be undone") {
		t.Fatalf("expected the failure to be reported, got %+v", result.Response)
	}
}

func TestRecoverRoutesRefusesAJournalPathItWouldNotWrite(t *testing.T) {
	// In service mode the helper runs as SYSTEM and the path comes from the
	// client: anything but the journal itself is refused before it is touched.
	service, calls := newRecoveringApp(0, nil)
	for _, journalPath := range []string{
		"",
		winroute.JournalFileName,
		filepath.Join(t.TempDir(), "hosts"),
	} {
		result := service.HandleCommand(context.Background(), command("1", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath}))
		if result.Response.OK {
			t.Fatalf("journal path %q was accepted", journalPath)
		}
	}
	if result := service.HandleCommand(context.Background(), command("2", "recover-routes", nil)); result.Response.OK {
		t.Fatal("a request without a payload was accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("recovery ran for a refused request: %+v", *calls)
	}
}

func TestRecoverRoutesLeavesARunningDataplaneAlone(t *testing.T) {
	// The journal of a running dataplane describes routes in use.
	service, calls := newRecoveringApp(0, nil)
	service.dataplane = &dataplane.Runner{}
	journalPath := filepath.Join(t.TempDir(), winroute.JournalFileName)
	result := service.HandleCommand(context.Background(), command("1", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath}))
	if result.Response.OK || !strings.Contains(result.Response.Error, "running") {
		t.Fatalf("expected recovery to be refused while the dataplane runs, got %+v", result.Response)
	}
	if len(*calls) != 0 {
		t.Fatalf("recovery ran under a live dataplane: %+v", *calls)
	}
}

func TestRecoverRoutesIsAuthorisedAndSerialisedLikeStartDataplane(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), winroute.JournalFileName)
	if !isStateChangingCommand("recover-routes") {
		t.Fatal("recover-routes changes the routing table and must be serialised with the other mutations")
	}

	service, calls := newRecoveringApp(0, nil)
	service.authToken = "secret"
	if result := service.HandleCommand(context.Background(), command("1", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath})); result.Response.OK {
		t.Fatalf("an unauthorised request was accepted: %+v", result.Response)
	}

	service.authToken = ""
	if shutdown := service.HandleCommand(context.Background(), command("2", "shutdown", nil)); !shutdown.Response.OK {
		t.Fatalf("shutdown failed: %+v", shutdown.Response)
	}
	result := service.HandleCommand(context.Background(), command("3", "recover-routes", RouteRecoveryPayload{JournalPath: journalPath}))
	if result.Response.OK || !strings.Contains(result.Response.Error, "shutting down") {
		t.Fatalf("expected recovery to be refused after shutdown, got %+v", result.Response)
	}
	if len(*calls) != 0 {
		t.Fatalf("recovery ran for a refused request: %+v", *calls)
	}
}

func TestRouteRecoveryIsWindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows implementation needs an elevated process")
	}
	journalPath := filepath.Join(t.TempDir(), winroute.JournalFileName)
	if _, err := recoverRoutes(context.Background(), journalPath, nil); !errors.Is(err, winroute.ErrNotSupported) {
		t.Fatalf("expected recovery to be unsupported off Windows, got %v", err)
	}
	if platform.NewDriver().Capabilities().RouteRecovery {
		t.Fatal("a helper that cannot recover routes advertised routeRecovery")
	}
}

func TestStartDataplaneRefusesAJournalPathItWouldNotWrite(t *testing.T) {
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	payload := hysteria2DataplanePayload("443")
	payload.JournalPath = filepath.Join(t.TempDir(), "hosts")
	result := service.HandleCommand(context.Background(), command("1", "start-dataplane", payload))
	if result.Response.OK || !strings.Contains(result.Response.Error, winroute.JournalFileName) {
		t.Fatalf("expected the journal path to be refused, got %+v", result.Response)
	}
}

// leftForRecoveryClose is a closeRunner whose runner came down but left a
// routing change to the journal.
func leftForRecoveryClose(calls *int) func(context.Context, *dataplane.Runner) error {
	return func(context.Context, *dataplane.Runner) error {
		*calls++
		return fmt.Errorf("%w: 1 routing changes could not be undone", dataplane.ErrLeftForRecovery)
	}
}

func TestStopDataplaneLetsGoOfARunnerLeftForRecovery(t *testing.T) {
	// Keeping it would fail every later stop and start on routes that can no
	// longer be undone, and TUN would never come back until a restart.
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	calls := 0
	service.closeRunner = leftForRecoveryClose(&calls)
	service.dataplane = &dataplane.Runner{}
	service.dataplaneSignature = "running"

	result := service.HandleCommand(context.Background(), command("1", "stop-dataplane", nil))
	if result.Response.OK || !strings.Contains(result.Response.Error, "routing journal") {
		t.Fatalf("expected the incomplete teardown to be reported, got %+v", result.Response)
	}
	if service.dataplane != nil {
		t.Fatal("a runner whose teardown is done was kept")
	}
	if second := service.HandleCommand(context.Background(), command("2", "stop-dataplane", nil)); !second.Response.OK || calls != 1 {
		t.Fatalf("expected nothing left to close, got %+v after %d calls", second.Response, calls)
	}
}

func TestRestartGoesAheadAfterATeardownLeftForRecovery(t *testing.T) {
	var logged []string
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(level, message string) { logged = append(logged, level+": "+message) }})
	calls := 0
	service.closeRunner = leftForRecoveryClose(&calls)
	service.dataplane = &dataplane.Runner{}
	service.dataplaneSignature = "an older transport"

	payload := hysteria2DataplanePayload("443")
	payload.JournalPath = filepath.Join(t.TempDir(), winroute.JournalFileName)
	result := service.HandleCommand(context.Background(), command("1", "start-dataplane", payload))
	// The start itself fails here - no adapter in a test - but it was tried
	// instead of being refused behind the old runner.
	if result.Response.OK || strings.Contains(result.Response.Error, "restart dataplane") {
		t.Fatalf("expected the start to go ahead, got %+v", result.Response)
	}
	if service.dataplane != nil || calls != 1 {
		t.Fatalf("expected the old runner to be let go after one close, got %v after %d calls", service.dataplane, calls)
	}
	if len(logged) == 0 || !strings.Contains(strings.Join(logged, "\n"), "incomplete") {
		t.Fatalf("expected the incomplete teardown to be logged, got %v", logged)
	}
}

func TestShutdownRetryReportsATeardownLeftForRecovery(t *testing.T) {
	// The SCM stop and main's deferred cleanup call Shutdown again after a
	// failure. The runner is gone by then, so the retry has nothing to close:
	// it must say so again rather than report a clean stop while a routing
	// change waits in the journal.
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	calls := 0
	service.closeRunner = leftForRecoveryClose(&calls)
	service.dataplane = &dataplane.Runner{}

	for attempt := 1; attempt <= 2; attempt++ {
		err := service.Shutdown(context.Background())
		if !errors.Is(err, dataplane.ErrLeftForRecovery) {
			t.Fatalf("attempt %d: expected the incomplete teardown to be reported, got %v", attempt, err)
		}
		if status := service.currentStatus(); status.State != "Error" {
			t.Fatalf("attempt %d: expected the failed cleanup to show, got %+v", attempt, status)
		}
	}
	if calls != 1 || service.dataplane != nil {
		t.Fatalf("expected one teardown and no runner left, got %d calls, runner %v", calls, service.dataplane)
	}
}

func TestShutdownAfterAStopLeftForRecoveryIsClean(t *testing.T) {
	// A stop-dataplane already reported its own incomplete teardown, and the
	// next start recovers the journal; a shutdown after it has nothing of its
	// own to report.
	service := New(Options{Driver: &fakeDriver{}, LogDiagnostic: func(string, string) {}})
	calls := 0
	service.closeRunner = leftForRecoveryClose(&calls)
	service.dataplane = &dataplane.Runner{}

	if result := service.HandleCommand(context.Background(), command("1", "stop-dataplane", nil)); result.Response.OK {
		t.Fatalf("expected the incomplete teardown to be reported, got %+v", result.Response)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if status := service.currentStatus(); status.State != "Disconnected" {
		t.Fatalf("expected a clean stop, got %+v", status)
	}
}
