package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"shadowssh/service/internal/routing"
)

// failingAdapter is an adapter whose ring fails while it is still open: the
// case in which nothing else would ever take the capture routes down.
type failingAdapter struct {
	*pipeAdapter
	fail chan error
}

func (a *failingAdapter) ReceivePacket() ([]byte, error) {
	select {
	case err := <-a.fail:
		return nil, err
	case packet := <-a.toDataplane:
		return packet, nil
	case <-a.closed:
		return nil, errors.New("adapter closed")
	}
}

func startFailingDataplane(t *testing.T, onFatal func(error)) (*failingAdapter, *Dataplane) {
	t.Helper()
	adapter := &failingAdapter{pipeAdapter: newPipeAdapter(), fail: make(chan error, 1)}
	dialers := newRecordingDialers()
	plane, err := Start(Options{
		Adapter: adapter,
		Tunnel:  dialers,
		Direct:  testDirectDialer{dialers},
		Policy:  NewPolicy(Config{Mode: routing.ModeProxyAll}),
		Log:     func(level, message string) { t.Logf("%s: %s", level, message) },
		OnFatal: onFatal,
	})
	if err != nil {
		t.Fatalf("start dataplane: %v", err)
	}
	return adapter, plane
}

func TestDataplaneReportsAnAdapterThatStopsDeliveringPackets(t *testing.T) {
	reported := make(chan error, 2)
	adapter, plane := startFailingDataplane(t, func(err error) { reported <- err })
	defer plane.Close()

	cause := errors.New("receive packet: The data is invalid.")
	adapter.fail <- cause
	select {
	case err := <-reported:
		if !errors.Is(err, cause) {
			t.Fatalf("reported %v, want %v", err, cause)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a failed adapter was not reported")
	}
	// Close still completes: the hook did not hold the pump.
	closed := make(chan struct{})
	go func() {
		_ = plane.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung after a reported failure")
	}
	if len(reported) != 0 {
		t.Fatal("the failure was reported more than once")
	}
}

func TestDataplaneDoesNotReportItsOwnClose(t *testing.T) {
	reported := make(chan error, 1)
	_, plane := startFailingDataplane(t, func(err error) { reported <- err })
	// Close makes the adapter's read fail; that is the teardown, not a fault.
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reported:
		t.Fatalf("a requested close was reported as a failure: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// fakeRunner stands in for a Windows runner: a teardown in the runner's order
// over fakes, guarded by the same fate.
type fakeRunner struct {
	fate      *runnerFate
	closeOnce sync.Once
	closeErr  error

	mu        sync.Mutex
	steps     []string
	teardowns int
	release   chan struct{}
	restore   error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{fate: newRunnerFate()}
}

func (r *fakeRunner) record(step string) {
	r.mu.Lock()
	r.steps = append(r.steps, step)
	r.mu.Unlock()
}

func (r *fakeRunner) Close(ctx context.Context) error {
	r.fate.claimClose()
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.teardowns++
		r.mu.Unlock()
		if r.release != nil {
			<-r.release
		}
		r.closeErr = runnerTeardown{
			stopRoutesWatch: func() { r.record("watcher") },
			closeGuard:      func() error { r.record("guard"); return nil },
			restoreRoutes: func(ctx context.Context) error {
				if _, ok := ctx.Deadline(); !ok {
					r.record("routes without a deadline")
				}
				r.record("routes")
				return r.restore
			},
			closePlane: func() error { r.record("adapter"); return nil },
			log:        func(string, string) {},
		}.run(ctx)
	})
	return r.closeErr
}

// waitForTeardown returns once the runner's one teardown has begun.
func waitForTeardown(t *testing.T, runner *fakeRunner) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runner.mu.Lock()
		started := runner.teardowns == 1
		runner.mu.Unlock()
		if started {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the teardown never started")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAFailedDataplaneTakesItsRunnerDownInOrderAndReportsIt(t *testing.T) {
	runner := newFakeRunner()
	type report struct{ cause, teardownErr error }
	reports := make(chan report, 2)
	// The failure arrives before the runner is watched, as it can during a
	// start; it is kept, not lost.
	cause := errors.New("receive packet: The handle is invalid.")
	runner.fate.reportFailure(cause)
	runner.fate.reportFailure(errors.New("a second failure"))
	go runner.fate.supervise(runner.Close, func(cause, teardownErr error) { reports <- report{cause, teardownErr} })

	select {
	case got := <-reports:
		if !errors.Is(got.cause, cause) || got.teardownErr != nil {
			t.Fatalf("got %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the failure was not acted on")
	}
	want := []string{"watcher", "guard", "routes", "adapter"}
	if strings.Join(runner.steps, ",") != strings.Join(want, ",") {
		t.Fatalf("teardown ran %v, want %v", runner.steps, want)
	}
	// The owner's Close afterwards does not tear down twice, and reports
	// what the one teardown reported.
	if err := runner.Close(context.Background()); err != nil || runner.teardowns != 1 {
		t.Fatalf("Close after the failure: %v, %d teardowns", err, runner.teardowns)
	}
	if len(reports) != 0 {
		t.Fatal("the failure was reported twice")
	}
}

func TestAFailedTeardownIsPartOfTheReport(t *testing.T) {
	runner := newFakeRunner()
	runner.restore = errors.New("netsh: element not found")
	reports := make(chan error, 1)
	runner.fate.reportFailure(errors.New("receive packet: Reached the end of the file."))
	go runner.fate.supervise(runner.Close, func(cause, teardownErr error) {
		reports <- dataplaneFailure(cause, teardownErr)
	})
	select {
	case err := <-reports:
		message := err.Error()
		if !strings.Contains(message, "end of the file") || !strings.Contains(message, "element not found") {
			t.Fatalf("report %q lost the cause or the teardown error", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the failure was not acted on")
	}
}

func TestARequestedCloseIsNotReportedAsAFailure(t *testing.T) {
	runner := newFakeRunner()
	runner.release = make(chan struct{})
	reported := make(chan struct{}, 1)
	finished := make(chan struct{})
	go func() {
		runner.fate.supervise(runner.Close, func(error, error) { reported <- struct{}{} })
		close(finished)
	}()
	closed := make(chan error, 1)
	go func() { closed <- runner.Close(context.Background()) }()
	waitForTeardown(t, runner)
	// The adapter fails while the requested teardown is under way - which is
	// what removing the adapter does.
	runner.fate.reportFailure(errors.New("receive packet: Reached the end of the file."))
	close(runner.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("supervise did not end when Close was asked for")
	}
	select {
	case <-reported:
		t.Fatal("a requested close was reported as a failure")
	default:
	}
	if runner.teardowns != 1 {
		t.Fatalf("expected one teardown, got %d", runner.teardowns)
	}
}

func TestACloseDuringTheFailureTeardownWaitsForIt(t *testing.T) {
	runner := newFakeRunner()
	runner.release = make(chan struct{})
	reported := make(chan struct{})
	runner.fate.reportFailure(errors.New("tun read wait failed"))
	go runner.fate.supervise(runner.Close, func(error, error) { close(reported) })
	waitForTeardown(t, runner)
	closed := make(chan error, 1)
	go func() { closed <- runner.Close(context.Background()) }()
	select {
	case <-closed:
		t.Fatal("Close returned before the teardown under way had finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(runner.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	<-reported
	if runner.teardowns != 1 {
		t.Fatalf("expected one teardown, got %d", runner.teardowns)
	}
}

func TestRunnerTeardownKeepsGoingAfterAFailedStep(t *testing.T) {
	var steps []string
	var logged []string
	guardErr := errors.New("guard: access denied")
	err := runnerTeardown{
		closeGuard:    func() error { steps = append(steps, "guard"); return guardErr },
		restoreRoutes: func(context.Context) error { steps = append(steps, "routes"); return errors.New("routes failed") },
		closePlane:    func() error { steps = append(steps, "adapter"); return nil },
		log:           func(level, message string) { logged = append(logged, level+": "+message) },
	}.run(context.Background())
	if !errors.Is(err, guardErr) {
		t.Fatalf("expected the first error, got %v", err)
	}
	// The restore is tried once more after the adapter is gone.
	if strings.Join(steps, ",") != "guard,routes,adapter,routes" {
		t.Fatalf("steps %v", steps)
	}
	if len(logged) != 2 {
		t.Fatalf("expected both failures logged, got %v", logged)
	}
}

// Closing the adapter takes its routes and addresses with it, so a restore
// that failed on one of them succeeds afterwards, and the teardown with it.
func TestRunnerTeardownRestoresAgainOnceTheAdapterIsGone(t *testing.T) {
	var steps []string
	adapterClosed := false
	err := runnerTeardown{
		restoreRoutes: func(context.Context) error {
			steps = append(steps, "routes")
			if !adapterClosed {
				return errors.New("1 routing changes could not be undone")
			}
			return nil
		},
		closePlane: func() error { steps = append(steps, "adapter"); adapterClosed = true; return nil },
		log:        func(string, string) {},
	}.run(context.Background())
	if err != nil {
		t.Fatalf("expected the teardown to finish once the adapter was gone, got %v", err)
	}
	if strings.Join(steps, ",") != "routes,adapter,routes" {
		t.Fatalf("steps %v", steps)
	}
}
