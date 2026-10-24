package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// A dataplane can stop on its own: the adapter's packet ring fails, or the
// adapter is removed under it. Nothing then reads what the capture routes
// still send there, so the machine is cut off - or, where the interface took
// its routes with it, everything leaves directly while Electron still shows
// the tunnel up. Neither may be left in place, and neither may go unreported:
// the runner takes itself down and tells its owner, which ends the helper so
// Electron sees the capture end (see app.dataplaneFailed).

// fatalTeardownTimeout bounds the teardown a runner does on its own after its
// dataplane failed. It is the same budget a requested teardown gets.
const fatalTeardownTimeout = 3 * time.Minute

// ErrLeftForRecovery wraps a teardown that took the dataplane down - adapter,
// capture routes - but did not finish cleanly: a routing change it could not
// undo, or a traffic guard that would not close. A routing change left is
// journalled, a guard ends with this process's dynamic session, and the
// runner is finished: retrying could only repeat what failed, while the next
// start, or the application's next launch, recovers the journal anyway. Its
// owner lets the runner go.
var ErrLeftForRecovery = errors.New("the TUN dataplane was taken down, but not cleanly; any routing change it could not undo is left in the routing journal for the next start")

// runnerFate settles who takes a runner down: its owner, asking for Close, or
// the runner itself, after its dataplane failed first. Exactly one of them
// does, and a failure while the owner's teardown is under way is the
// teardown's own business, not a second one.
type runnerFate struct {
	failure chan error
	claimed atomic.Bool
	// closing is closed when the owner claims the teardown, which ends
	// supervise.
	closing chan struct{}
}

func newRunnerFate() *runnerFate {
	return &runnerFate{failure: make(chan error, 1), closing: make(chan struct{})}
}

// reportFailure is the dataplane's OnFatal. It keeps the first failure and
// never blocks: it runs on the packet pump, which Close waits for.
func (f *runnerFate) reportFailure(err error) {
	select {
	case f.failure <- err:
	default:
	}
}

// claimClose records that the owner asked for the teardown. From then on a
// failure is not acted on.
func (f *runnerFate) claimClose() {
	if f.claimed.CompareAndSwap(false, true) {
		close(f.closing)
	}
}

// supervise waits for the dataplane to fail before the owner asks for Close.
// If it does, supervise runs teardown itself - nothing else will - and hands
// fatal the failure and what the teardown reported. A failure reported before
// supervise started is still seen.
func (f *runnerFate) supervise(teardown func(context.Context) error, fatal func(cause error, teardownErr error)) {
	var cause error
	select {
	case <-f.closing:
		return
	case cause = <-f.failure:
	}
	if !f.claimed.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fatalTeardownTimeout)
	defer cancel()
	fatal(cause, teardown(ctx))
}

// dataplaneFailure is the one-line account of a dataplane that stopped on its
// own and was taken down.
func dataplaneFailure(cause error, teardownErr error) error {
	if teardownErr != nil {
		return fmt.Errorf("the TUN adapter stopped delivering packets (%v); the dataplane was taken down, but the teardown reported: %w", cause, teardownErr)
	}
	return fmt.Errorf("the TUN adapter stopped delivering packets (%w); the capture routes and the traffic guard were removed", cause)
}

// runnerTeardown is the order a runner comes down in. The route watcher goes
// first, so it cannot change the guard mid-way. The traffic guard goes next,
// while the routes still send everything to the adapter: the other way round,
// there would be a moment in which interface-bound UDP is refused and nothing
// else carries it. Routing is restored before the adapter goes away, so there
// is no moment in which the machine has capture routes pointing at an
// interface that no longer exists. Every step runs whatever the one before it
// reported; the first error is returned.
//
// A restore that failed is tried once more after the adapter is closed:
// closing it removed every route and address on it, which the manager then
// recognises as gone, so what remains to report is only what is really left -
// typically nothing, or a host route on the network card.
type runnerTeardown struct {
	// stopRoutesWatch ends the route watcher and waits for it; nil when none
	// runs.
	stopRoutesWatch func()
	// closeGuard removes the traffic guard; nil when none was installed.
	closeGuard    func() error
	restoreRoutes func(context.Context) error
	// closePlane stops the stack and closes the adapter.
	closePlane func() error
	log        func(level string, message string)
}

func (t runnerTeardown) run(ctx context.Context) error {
	var guardErr, planeErr error
	if t.stopRoutesWatch != nil {
		t.stopRoutesWatch()
	}
	if t.closeGuard != nil {
		if guardErr = t.closeGuard(); guardErr != nil {
			t.log("warning", "Removing the traffic guard reported: "+guardErr.Error())
		}
	}
	restoreErr := t.restoreRoutes(ctx)
	if restoreErr != nil {
		t.log("warning", "Routing restore reported: "+restoreErr.Error())
	}
	planeErr = t.closePlane()
	if restoreErr != nil {
		restoreErr = t.restoreRoutes(ctx)
	}
	return firstError(guardErr, restoreErr, planeErr)
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
