package winroute

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func basePlan() Plan {
	return Plan{
		TunnelInterfaceIndex: 17,
		TunnelAddress4:       netip.MustParseAddr("10.253.7.2"),
		TunnelMask4:          netip.MustParseAddr("255.255.255.0"),
		TunnelAddress6:       netip.MustParseAddr("fd7a:c0de:5417::2"),
		TunnelPrefixLength6:  64,
		EnforceIPv4:          true,
	}
}

func joined(operations []Operation) []string {
	rendered := make([]string, 0, len(operations))
	for _, operation := range operations {
		rendered = append(rendered, strings.Join(operation.Apply, " "))
	}
	return rendered
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
	plan := basePlan()
	plan.ProtectedRoutes = []ProtectedRoute{{
		Address:        netip.MustParseAddr("198.51.100.4"),
		InterfaceIndex: 4,
		NextHop:        netip.MustParseAddr("192.168.1.1"),
	}}
	operations, err := plan.Operations()
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
	var executed []string
	failOn := "prefix=128.0.0.0/1"
	manager := NewManager(filepath.Join(t.TempDir(), "routing.json"), func(_ context.Context, argv []string) error {
		line := strings.Join(argv, " ")
		executed = append(executed, line)
		if strings.Contains(line, failOn) && strings.Contains(line, " add ") {
			return errors.New("netsh failed")
		}
		return nil
	}, nil)

	if err := manager.Apply(context.Background(), basePlan()); err == nil {
		t.Fatalf("expected the apply to fail")
	}
	var deletes int
	for _, line := range executed {
		if strings.Contains(line, " delete ") || strings.Contains(line, "source=dhcp") || strings.Contains(line, "metric=automatic") {
			deletes++
		}
	}
	if deletes == 0 {
		t.Fatalf("expected the applied operations to be undone, got:\n%s", strings.Join(executed, "\n"))
	}
	if err := manager.Apply(context.Background(), basePlan()); err == nil {
		t.Fatalf("expected a second apply attempt to be possible after rollback")
	}
}

func TestManagerRecoversAJournalFromAPreviousRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routing.json")
	journal := NewJournalFile(path)
	if err := journal.Write([]Operation{
		{Description: "first", Undo: []string{"netsh", "first"}},
		{Description: "second", Undo: []string{"netsh", "second"}},
	}); err != nil {
		t.Fatalf("write journal: %v", err)
	}

	var executed []string
	manager := NewManager(path, func(_ context.Context, argv []string) error {
		executed = append(executed, strings.Join(argv, " "))
		return nil
	}, nil)
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	// Undo runs in reverse, so a route is removed before the address it needs.
	if len(executed) != 2 || executed[0] != "netsh second" || executed[1] != "netsh first" {
		t.Fatalf("expected the journal to be undone in reverse, got %v", executed)
	}
	if entries, err := journal.Read(); err != nil || entries != nil {
		t.Fatalf("expected the journal to be cleared, got %v (%v)", entries, err)
	}
}

func TestJournalIsWrittenBeforeTheFirstChange(t *testing.T) {
	// An operation applied but not journalled survives a crash; one journalled
	// but not applied only costs a no-op undo. The order has to be this way.
	path := filepath.Join(t.TempDir(), "routing.json")
	var journalledAtFirstCall []Operation
	manager := NewManager(path, func(context.Context, []string) error {
		if journalledAtFirstCall == nil {
			entries, err := NewJournalFile(path).Read()
			if err != nil {
				t.Fatalf("read journal: %v", err)
			}
			journalledAtFirstCall = entries
		}
		return nil
	}, nil)
	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(journalledAtFirstCall) == 0 {
		t.Fatalf("expected the journal to exist before the first command ran")
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if entries, err := NewJournalFile(path).Read(); err != nil || entries != nil {
		t.Fatalf("expected the journal to be cleared after restore, got %v (%v)", entries, err)
	}
}
