package winroute

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestEveryCommandThePlanRendersIsAccepted(t *testing.T) {
	// The grammar is the only thing recovery will run, so anything Plan renders
	// and the grammar refuses could be applied but never undone after a crash.
	plan := protectedPlan()
	plan.EnforceIPv6 = true
	plan.ProtectedRoutes = append(plan.ProtectedRoutes, ProtectedRoute{
		Address:        netip.MustParseAddr("2001:db8::5"),
		InterfaceIndex: physicalIndex,
		NextHop:        netip.MustParseAddr("fe80::1"),
	})
	operations, err := plan.Operations()
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	if len(operations) != 10 {
		t.Fatalf("expected two host routes and four operations per family, got %d", len(operations))
	}
	for _, operation := range operations {
		if err := validateOperation(operation); err != nil {
			t.Fatalf("plan rendered a command the grammar refuses: %v", err)
		}
		undo, err := parseUndo(operation.Undo)
		if err != nil {
			t.Fatalf("undo refused: %v", err)
		}
		wantPinned := strings.Contains(strings.Join(operation.Undo, " "), "nexthop=")
		if undo.pinned() != wantPinned {
			t.Fatalf("pinned() = %v for %q", undo.pinned(), strings.Join(operation.Undo, " "))
		}
	}
}

func TestJournalCommandsRefuseAnythingElse(t *testing.T) {
	refused := map[string][]string{
		"another program":       {"cmd.exe", "/c", "calc"},
		"powershell":            {"powershell.exe", "-Command", "Start-Process calc"},
		"a netsh script":        {"netsh", "exec", `C:\Users\Public\x.txt`},
		"netsh by path":         {`C:\Windows\System32\netsh.exe`, "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=active"},
		"netsh in capitals":     {"NETSH", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=active"},
		"the default route":     {"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/0", "interface=17", "store=active"},
		"a zero-padded index":   {"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=017", "store=active"},
		"interface zero":        {"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=0", "store=active"},
		"an interface name":     {"netsh", "interface", "ipv4", "set", "address", "name=Wi-Fi", "source=dhcp", "store=active"},
		"an extra argument":     {"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=active", "x=y"},
		"a trailing command":    {"netsh", "interface", "ipv4", "set", "address", "name=17", "source=dhcp", "store=active", "&&", "calc"},
		"a persistent change":   {"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=persistent"},
		"reordered arguments":   {"netsh", "interface", "ipv4", "delete", "route", "interface=17", "prefix=0.0.0.0/1", "store=active"},
		"a change, not an undo": {"netsh", "interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=17", "metric=1", "store=active"},
		"a wider host route":    {"netsh", "interface", "ipv4", "delete", "route", "prefix=198.51.100.0/24", "interface=4", "nexthop=192.168.1.1", "store=active"},
		"the wrong family":      {"netsh", "interface", "ipv4", "delete", "route", "prefix=2001:db8::1/128", "interface=4", "nexthop=fe80::1", "store=active"},
		"a zoned next hop":      {"netsh", "interface", "ipv6", "delete", "route", "prefix=2001:db8::1/128", "interface=4", "nexthop=fe80::1%4", "store=active"},
		"a non-canonical form":  {"netsh", "interface", "ipv6", "delete", "route", "prefix=2001:0db8::1/128", "interface=4", "nexthop=fe80::1", "store=active"},
		"a mapped address":      {"netsh", "interface", "ipv6", "delete", "address", "interface=17", "address=::ffff:10.0.0.1", "store=active"},
		"an IPv6 DHCP reset":    {"netsh", "interface", "ipv6", "set", "address", "name=17", "source=dhcp", "store=active"},
		"a reset address":       {"netsh", "interface", "ipv4", "set", "address", "name=17", "source=dhcp", "address=10.0.0.1", "store=active"},
		"nothing":               {},
	}
	for name, argv := range refused {
		if _, err := parseUndo(argv); err == nil {
			t.Fatalf("%s: %q was accepted", name, strings.Join(argv, " "))
		}
	}

	accepted := [][]string{
		{"netsh", "interface", "ipv4", "set", "address", "name=17", "source=dhcp", "store=active"},
		{"netsh", "interface", "ipv6", "delete", "address", "interface=17", "address=fd7a:c0de:5417::2", "store=active"},
		{"netsh", "interface", "ipv6", "set", "interface", "interface=4294967295", "metric=automatic", "store=active"},
		{"netsh", "interface", "ipv6", "delete", "route", "prefix=8000::/1", "interface=17", "store=active"},
		{"netsh", "interface", "ipv4", "delete", "route", "prefix=198.51.100.4/32", "interface=4", "nexthop=192.168.1.1", "store=active"},
	}
	for _, argv := range accepted {
		if _, err := parseUndo(argv); err != nil {
			t.Fatalf("%q was refused: %v", strings.Join(argv, " "), err)
		}
	}
}

func TestAnOperationsUndoMustNameTheSameInterface(t *testing.T) {
	operation := captureRouteOperation("ipv4", "0.0.0.0/1", "17")
	if err := validateOperation(operation); err != nil {
		t.Fatalf("a rendered operation was refused: %v", err)
	}
	operation.Undo = captureRouteOperation("ipv4", "0.0.0.0/1", "18").Undo
	if err := validateOperation(operation); err == nil {
		t.Fatal("an undo for another interface was accepted")
	}
}

func TestApplyRefusesAPlanRecoveryCouldNotReplay(t *testing.T) {
	// A zone carries free text into the command, so the grammar refuses it -
	// and a change that could not be undone after a crash is not made at all.
	plan := basePlan()
	plan.ProtectedRoutes = []ProtectedRoute{{
		Address:        netip.MustParseAddr("2001:db8::5"),
		InterfaceIndex: physicalIndex,
		NextHop:        netip.MustParseAddr("fe80::1%eth0"),
	}}
	path := testJournalPath(t)
	runner := &recorder{}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	if err := manager.Apply(context.Background(), plan); err == nil {
		t.Fatal("expected the plan to be refused")
	}
	if len(runner.executed) != 0 {
		t.Fatalf("a refused plan ran commands: %v", runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("a refused plan was journalled: %+v", entries)
	}
}

func TestOnlyNetshFromTheSystemDirectoryIsRun(t *testing.T) {
	if err := execRunner(context.Background(), []string{"cmd.exe", "/c", "calc"}); err == nil || !strings.Contains(err.Error(), "only netsh") {
		t.Fatalf("expected another program to be refused, got %v", err)
	}
	if err := execRunner(context.Background(), nil); err == nil {
		t.Fatal("expected an empty command to be refused")
	}
	// The manager checks the grammar before the runner sees anything.
	runner := &recorder{}
	manager := newTestManager(testJournalPath(t), liveInterfaces(), runner.run)
	if err := manager.runOne(context.Background(), []string{"netsh", "exec", "script.txt"}); err == nil {
		t.Fatal("expected a command outside the grammar to be refused")
	}
	if len(runner.executed) != 0 {
		t.Fatalf("the runner was given a refused command: %v", runner.executed)
	}
}

func TestNetshIsNotLookedUpThroughPath(t *testing.T) {
	path, err := netshPath()
	if errors.Is(err, ErrNotSupported) {
		t.Skip("netsh exists only on Windows")
	}
	if err != nil {
		t.Fatalf("netshPath: %v", err)
	}
	if !strings.HasSuffix(strings.ToLower(path), `\netsh.exe`) || !strings.Contains(strings.ToLower(path), `\system32\`) {
		t.Fatalf("expected netsh.exe in the system directory, got %q", path)
	}
}
