package winroute

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"shadowssh/service/internal/winnet"
)

const (
	tunnelIndex   = 17
	physicalIndex = 4
	tunnelLUID    = 0x0083000000a10000
	physicalLUID  = 0x0006000000040000
)

func basePlan() Plan {
	return Plan{
		TunnelInterfaceIndex: tunnelIndex,
		TunnelAddress4:       netip.MustParseAddr("10.253.7.2"),
		TunnelMask4:          netip.MustParseAddr("255.255.255.0"),
		TunnelAddress6:       netip.MustParseAddr("fd7a:c0de:5417::2"),
		TunnelPrefixLength6:  64,
		EnforceIPv4:          true,
	}
}

func protectedPlan() Plan {
	plan := basePlan()
	plan.ProtectedRoutes = []ProtectedRoute{{
		Address:        netip.MustParseAddr("198.51.100.4"),
		InterfaceIndex: physicalIndex,
		NextHop:        netip.MustParseAddr("192.168.1.1"),
	}}
	return plan
}

func joined(operations []Operation) []string {
	rendered := make([]string, 0, len(operations))
	for _, operation := range operations {
		rendered = append(rendered, strings.Join(operation.Apply, " "))
	}
	return rendered
}

func testJournalPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), JournalFileName)
}

// interfacesOf answers from byIndex, which a test may change between calls to
// stand in for an adapter going away or an index being handed to another one.
func interfacesOf(byIndex map[uint32]uint64) interfaceTable {
	return interfaceTable{
		luid: func(index uint32) (uint64, error) {
			if luid, ok := byIndex[index]; ok {
				return luid, nil
			}
			return 0, fmt.Errorf("index %d: %w", index, winnet.ErrInterfaceNotFound)
		},
		index: func(luid uint64) (uint32, error) {
			for index, candidate := range byIndex {
				if candidate == luid {
					return index, nil
				}
			}
			return 0, fmt.Errorf("luid %#x: %w", luid, winnet.ErrInterfaceNotFound)
		},
	}
}

func liveInterfaces() map[uint32]uint64 {
	return map[uint32]uint64{tunnelIndex: tunnelLUID, physicalIndex: physicalLUID}
}

func newTestManager(path string, byIndex map[uint32]uint64, run Runner) *Manager {
	manager := NewManager(path, run, nil)
	manager.interfaces = interfacesOf(byIndex)
	// A lock left held by mistake fails a test at once instead of stalling
	// it for the minutes a real start waits.
	manager.lockWait = 0
	return manager
}

// crash leaves the manager as a killed helper leaves the machine: its changes
// and their journal stay, and the operating system lets go of its lock.
func crash(manager *Manager) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.releaseLockLocked()
}

// routeTable stands in for the routing table: the routes it lists are there.
func routeTable(routes ...winnet.Route) func() ([]winnet.Route, error) {
	return func() ([]winnet.Route, error) { return routes, nil }
}

// recorder is a Runner that records every command and fails the ones fail
// picks.
type recorder struct {
	executed []string
	fail     func(line string) bool
}

func (r *recorder) run(ctx context.Context, argv []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	line := strings.Join(argv, " ")
	r.executed = append(r.executed, line)
	if r.fail != nil && r.fail(line) {
		return errors.New("netsh failed")
	}
	return nil
}

func (r *recorder) ran(fragment string) bool {
	for _, line := range r.executed {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func readJournal(t *testing.T, path string) []Operation {
	t.Helper()
	entries, err := NewJournalFile(path).Read()
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	return entries
}

func TestPlanCapturesBothHalvesOfTheAddressSpace(t *testing.T) {
	// Two /1 routes beat the machine's default route on prefix length, which
	// is why the default route itself is never touched.
	operations, err := basePlan().Operations()
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	rendered := strings.Join(joined(operations), "\n")
	for _, prefix := range []string{"prefix=0.0.0.0/1", "prefix=128.0.0.0/1"} {
		if !strings.Contains(rendered, prefix) {
			t.Fatalf("expected %s to be captured, got:\n%s", prefix, rendered)
		}
	}
	if strings.Contains(rendered, "prefix=0.0.0.0/0") {
		t.Fatalf("the machine's default route must not be modified, got:\n%s", rendered)
	}
}

func TestPlanExcludesTheTransportBeforeCapturing(t *testing.T) {
	operations, err := protectedPlan().Operations()
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	rendered := joined(operations)
	if !strings.Contains(rendered[0], "prefix=198.51.100.4/32") || !strings.Contains(rendered[0], "nexthop=192.168.1.1") {
		t.Fatalf("expected the transport's host route first, got %q", rendered[0])
	}
	if !strings.Contains(rendered[0], "interface=4") {
		t.Fatalf("expected the host route on the physical interface, got %q", rendered[0])
	}
}

func TestOnLinkTransportNeedsNoHostRoute(t *testing.T) {
	// An on-link server already has a subnet route more specific than /1.
	plan := basePlan()
	plan.ProtectedRoutes = []ProtectedRoute{{Address: netip.MustParseAddr("192.168.1.50"), InterfaceIndex: 4}}
	operations, err := plan.Operations()
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	if strings.Contains(strings.Join(joined(operations), "\n"), "192.168.1.50") {
		t.Fatalf("expected no host route for an on-link address")
	}
}

func TestIPv6CaptureRequiresAnIPv6Address(t *testing.T) {
	plan := basePlan()
	plan.EnforceIPv6 = true
	plan.TunnelAddress6 = netip.Addr{}
	if _, err := plan.Operations(); err == nil {
		t.Fatalf("expected IPv6 capture without an address to be refused")
	}
}

func TestManagerRollsBackAPartialApply(t *testing.T) {
	// A half-captured machine is the failure this rollback exists to prevent.
	runner := &recorder{fail: func(line string) bool {
		return strings.Contains(line, "prefix=128.0.0.0/1") && strings.Contains(line, " add ")
	}}
	path := testJournalPath(t)
	manager := newTestManager(path, liveInterfaces(), runner.run)

	if err := manager.Apply(context.Background(), basePlan()); err == nil {
		t.Fatalf("expected the apply to fail")
	}
	var deletes int
	for _, line := range runner.executed {
		if strings.Contains(line, " delete ") || strings.Contains(line, "source=dhcp") || strings.Contains(line, "metric=automatic") {
			deletes++
		}
	}
	if deletes == 0 {
		t.Fatalf("expected the applied operations to be undone, got:\n%s", strings.Join(runner.executed, "\n"))
	}
	// Every undo succeeded, so nothing is left to describe.
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected a fully rolled-back apply to clear the journal, got %+v", entries)
	}
	if err := manager.Apply(context.Background(), basePlan()); err == nil {
		t.Fatalf("expected a second apply attempt to be possible after rollback")
	}
}

func TestManagerRecoversAJournalFromAPreviousRun(t *testing.T) {
	path := testJournalPath(t)
	// A run that crashed after applying everything.
	crashed := newTestManager(path, liveInterfaces(), (&recorder{}).run)
	if err := crashed.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	crash(crashed)
	journalled := readJournal(t, path)

	runner := &recorder{}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	// Undo runs in reverse, so a route is removed before the address it needs.
	if len(runner.executed) != len(journalled) {
		t.Fatalf("expected all %d undo commands to run, got %v", len(journalled), runner.executed)
	}
	for position, line := range runner.executed {
		want := strings.Join(journalled[len(journalled)-1-position].Undo, " ")
		if line != want {
			t.Fatalf("undo %d = %q, want %q", position, line, want)
		}
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %v", entries)
	}
}

func TestJournalIsWrittenBeforeTheFirstChange(t *testing.T) {
	// An operation applied but not journalled survives a crash; one journalled
	// but not applied only costs a no-op undo. The order has to be this way.
	path := testJournalPath(t)
	var journalledAtFirstCall []Operation
	manager := newTestManager(path, liveInterfaces(), func(context.Context, []string) error {
		if journalledAtFirstCall == nil {
			entries, err := NewJournalFile(path).Read()
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			journalledAtFirstCall = entries
		}
		return nil
	})
	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(journalledAtFirstCall) == 0 {
		t.Fatalf("expected the journal to exist before the first command ran")
	}
	for _, entry := range journalledAtFirstCall {
		if entry.InterfaceLUID != tunnelLUID {
			t.Fatalf("expected every entry to name the adapter's LUID, got %+v", entry)
		}
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared after restore, got %v", entries)
	}
}

func TestRestoreRunsEveryUndoEvenWhenTheCallerGaveUp(t *testing.T) {
	// Teardown is routinely reached with a context that is already cancelled -
	// the IPC client went away, or the service is being signalled. Honouring it
	// would abort every remaining undo instantly and leave the machine with
	// capture routes pointing at an adapter that is about to disappear, which
	// is what makes the next connect unable to bring the tunnel back up.
	runner := &recorder{}
	manager := newTestManager(testJournalPath(t), liveInterfaces(), runner.run)

	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	applied := len(runner.executed)
	runner.executed = nil

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Restore(cancelled); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(runner.executed) != applied {
		t.Fatalf("expected all %d undo commands to run, got %d", applied, len(runner.executed))
	}
}

func TestRecoverAlsoIgnoresACancelledCaller(t *testing.T) {
	path := testJournalPath(t)
	crashed := newTestManager(path, liveInterfaces(), (&recorder{}).run)
	if err := crashed.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	crash(crashed)

	runner := &recorder{}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Recover(cancelled); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !runner.ran("nexthop=192.168.1.1") {
		t.Fatalf("expected the journalled undo to run, got %v", runner.executed)
	}
}
