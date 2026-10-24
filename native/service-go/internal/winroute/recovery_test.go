package winroute

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shadowssh/service/internal/winnet"
)

func writeRawJournal(t *testing.T, path string, journal any) []byte {
	t.Helper()
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatalf("encode journal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	return raw
}

func rejectedCopies(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".rejected-*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return matches
}

// crashAfterApply leaves the journal a run that died after applying plan
// would have left.
func crashAfterApply(t *testing.T, path string, plan Plan) []Operation {
	t.Helper()
	manager := newTestManager(path, liveInterfaces(), (&recorder{}).run)
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	crash(manager)
	return readJournal(t, path)
}

func TestRecoverRefusesAJournalWithACommandItDidNotWrite(t *testing.T) {
	// The file is in the user's own data folder and the reader is elevated. One
	// foreign entry means the file was not written by this program, so none of
	// it is run - not even the entries that look right.
	path := testJournalPath(t)
	raw := writeRawJournal(t, path, map[string]any{
		"version": JournalVersion,
		"entries": []map[string]any{
			{"description": "capture 0.0.0.0/1", "undo": []string{"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=active"}, "interfaceLuid": tunnelLUID},
			{"description": "planted", "undo": []string{"cmd.exe", "/c", "calc"}},
		},
	})

	runner := &recorder{}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	err := manager.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nothing in it was run") {
		t.Fatalf("expected the journal to be refused, got %v", err)
	}
	if len(runner.executed) != 0 {
		t.Fatalf("a refused journal ran commands: %v", runner.executed)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected the refused journal to be moved aside, stat = %v", statErr)
	}
	copies := rejectedCopies(t, path)
	if len(copies) != 1 {
		t.Fatalf("expected one rejected copy, got %v", copies)
	}
	if kept, _ := os.ReadFile(copies[0]); string(kept) != string(raw) {
		t.Fatalf("the rejected copy changed: %s", kept)
	}

	// The next start is not blocked by it.
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("recover after rejection: %v", err)
	}
}

func TestRecoverRefusesJournalsItCannotRead(t *testing.T) {
	cases := map[string][]byte{
		"a newer version": []byte(`{"version":3,"entries":[]}`),
		"no version":      []byte(`{"entries":[]}`),
		"broken JSON":     []byte(`{"version":2,"entries":[`),
		"an empty undo":   []byte(`{"version":2,"entries":[{"description":"x","undo":[]}]}`),
		"too large":       []byte(`{"version":2,"entries":[],"padding":"` + strings.Repeat("x", maxJournalBytes) + `"}`),
		"too long a description": []byte(`{"version":2,"entries":[{"description":"` + strings.Repeat("x", maxDescriptionBytes+1) +
			`","undo":["netsh","interface","ipv4","delete","route","prefix=0.0.0.0/1","interface=17","store=active"]}]}`),
	}
	for name, raw := range cases {
		path := testJournalPath(t)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		runner := &recorder{}
		if err := newTestManager(path, liveInterfaces(), runner.run).Recover(context.Background()); err == nil {
			t.Fatalf("%s: expected the journal to be refused", name)
		}
		if len(runner.executed) != 0 {
			t.Fatalf("%s: ran %v", name, runner.executed)
		}
		if len(rejectedCopies(t, path)) != 1 {
			t.Fatalf("%s: expected the journal to be moved aside", name)
		}
	}
}

func TestRecoverReadsOlderJournalsWithoutTrustingTheirIndices(t *testing.T) {
	// A journal from before interfaces were identified does not say which
	// interface its index meant. A host route deleted by prefix, interface and
	// next hop can only remove that one route; resetting an address or
	// deleting a capture route could hit whichever adapter - another VPN's,
	// say - has that index now.
	//
	// The file is trusted here, as it is off Windows or in a helper that is
	// not elevated. On Windows an elevated helper refuses a file an earlier
	// release wrote before reading any of it (TestRecoverRefusesAJournalItCannotTrust),
	// and the next Apply copes with the host route it left
	// (TestApplyLeavesAHostRouteThatIsAlreadyInPlace).
	path := testJournalPath(t)
	hostRoute := []string{"netsh", "interface", "ipv4", "delete", "route", "prefix=198.51.100.4/32", "interface=4", "nexthop=192.168.1.1", "store=active"}
	writeRawJournal(t, path, map[string]any{
		"version": 1,
		"entries": []map[string]any{
			{"description": "keep 198.51.100.4 on the physical interface", "undo": hostRoute},
			{"description": "capture 0.0.0.0/1 on the tunnel adapter", "undo": []string{"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=17", "store=active"}},
		},
	})

	runner := &recorder{}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	undone, err := manager.recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if undone != 1 || len(runner.executed) != 1 || runner.executed[0] != strings.Join(hostRoute, " ") {
		t.Fatalf("expected only the host route to be undone, got %d: %v", undone, runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}
}

func TestRecoverOnlyActsOnTheInterfaceAChangeWasMadeOn(t *testing.T) {
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())

	// After the crash the adapter went away with the helper, and index 17 now
	// belongs to another VPN's adapter. The network card is still there.
	now := map[uint32]uint64{tunnelIndex: 0x0083000000b20000, physicalIndex: physicalLUID}
	runner := &recorder{}
	undone, err := newTestManager(path, now, runner.run).recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if runner.ran("interface=17") || runner.ran("name=17") {
		t.Fatalf("recovery reconfigured the interface that now has index 17: %v", runner.executed)
	}
	if undone != 1 || !runner.ran("prefix=198.51.100.4/32") {
		t.Fatalf("expected the host route on the network card to be undone, got %d: %v", undone, runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("changes on a vanished adapter went with it; expected an empty journal, got %+v", entries)
	}
}

func TestRecoverDropsAChangeWhoseInterfaceWasCreatedAgain(t *testing.T) {
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())

	// After a reboot the network card is interface 9, and index 4 is
	// something else. Its host route was in the active store and did not
	// survive the reboot; the command would reach the other interface.
	now := map[uint32]uint64{physicalIndex: 0x0006000000990000, 9: physicalLUID}
	runner := &recorder{}
	undone, err := newTestManager(path, now, runner.run).recover(context.Background())
	if err != nil || undone != 0 {
		t.Fatalf("expected nothing to undo and nothing to report, got %d, %v", undone, err)
	}
	if len(runner.executed) != 0 {
		t.Fatalf("expected nothing to run against a reused index, got %v", runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}
}

func TestRecoverTreatsARouteThatIsAlreadyGoneAsUndone(t *testing.T) {
	// After a power cut every change in the active store is gone. The network
	// card is still there under its old index, so its host route's delete runs
	// and fails with "Element not found" - which is not something left over.
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())

	failing := &recorder{fail: func(line string) bool { return strings.Contains(line, "nexthop=") }}
	manager := newTestManager(path, map[uint32]uint64{physicalIndex: physicalLUID}, failing.run)
	manager.interfaces.routes = routeTable(winnet.Route{
		Destination: netip.MustParsePrefix("0.0.0.0/0"), InterfaceLUID: physicalLUID, InterfaceIndex: physicalIndex,
		NextHop: netip.MustParseAddr("192.168.1.1"),
	})
	if _, err := manager.recover(context.Background()); err != nil {
		t.Fatalf("expected a route that is already gone not to be reported, got %v", err)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}

	// A route that is still there and will not go is kept, as before.
	crashAfterApply(t, path, protectedPlan())
	stuck := newTestManager(path, map[uint32]uint64{physicalIndex: physicalLUID}, failing.run)
	stuck.interfaces.routes = routeTable(winnet.Route{
		Destination: netip.MustParsePrefix("198.51.100.4/32"), InterfaceLUID: physicalLUID, InterfaceIndex: physicalIndex,
		NextHop: netip.MustParseAddr("192.168.1.1"),
	})
	if _, err := stuck.recover(context.Background()); err == nil || !strings.Contains(err.Error(), "stay journalled") {
		t.Fatalf("expected the route still in place to stay journalled, got %v", err)
	}
}

func TestApplyLeavesAHostRouteThatIsAlreadyInPlace(t *testing.T) {
	// A helper of an earlier release was killed with the tunnel up, and its
	// journal was refused: the server's host route is still there. Adding it
	// again would fail with "The object already exists" and roll the whole
	// plan back, so it is taken as in place - and, not being this manager's,
	// neither journalled nor deleted with the plan.
	path := testJournalPath(t)
	writeRawJournal(t, path, map[string]any{
		"version": 1,
		"entries": []map[string]any{{
			"description": "keep 198.51.100.4 on the physical interface",
			"undo":        []string{"netsh", "interface", "ipv4", "delete", "route", "prefix=198.51.100.4/32", "interface=4", "nexthop=192.168.1.1", "store=active"},
		}},
	})
	leftover := winnet.Route{
		Destination: netip.MustParsePrefix("198.51.100.4/32"), InterfaceLUID: physicalLUID, InterfaceIndex: physicalIndex,
		NextHop: netip.MustParseAddr("192.168.1.1"),
	}

	runner := &recorder{fail: func(line string) bool { return strings.Contains(line, "add route prefix=198.51.100.4/32") }}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	manager.interfaces.routes = routeTable(leftover)
	original := journalTrust
	journalTrust = func(*os.File) error { return errors.New("lets S-1-5-21-1 change it") }
	err := manager.Recover(context.Background())
	journalTrust = original
	if err == nil || !strings.Contains(err.Error(), "nothing in it was run") {
		t.Fatalf("expected the older journal to be refused, got %v", err)
	}
	if err := manager.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("expected the plan to apply around the route already in place, got %v", err)
	}
	if runner.ran("prefix=198.51.100.4/32") {
		t.Fatalf("expected the host route already in place to be left alone, got %v", runner.executed)
	}
	for _, entry := range readJournal(t, path) {
		if strings.Contains(strings.Join(entry.Undo, " "), "198.51.100.4") {
			t.Fatalf("a route this manager did not add was journalled: %+v", entry)
		}
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if runner.ran("delete route prefix=198.51.100.4/32") {
		t.Fatalf("a route this manager did not add was deleted: %v", runner.executed)
	}

	// The same address through another gateway is a different route, and is
	// added as usual.
	moved := &recorder{}
	other := newTestManager(path, liveInterfaces(), moved.run)
	leftover.NextHop = netip.MustParseAddr("192.168.1.254")
	other.interfaces.routes = routeTable(leftover)
	if err := other.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !moved.ran("add route prefix=198.51.100.4/32 interface=4 nexthop=192.168.1.1") {
		t.Fatalf("expected the host route through the current gateway to be added, got %v", moved.executed)
	}
}

func TestRecoverRefusesAJournalItCannotTrust(t *testing.T) {
	// On Windows an elevated helper refuses a journal that someone other than
	// an administrator could have written; every command in it looks right,
	// and that is the point.
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())
	original := journalTrust
	journalTrust = func(*os.File) error { return errors.New("lets S-1-5-21-1 change it") }
	t.Cleanup(func() { journalTrust = original })

	runner := &recorder{}
	err := newTestManager(path, liveInterfaces(), runner.run).Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nothing in it was run") || !strings.Contains(err.Error(), "S-1-5-21-1") {
		t.Fatalf("expected the journal to be refused, got %v", err)
	}
	if len(runner.executed) != 0 {
		t.Fatalf("an untrusted journal ran commands: %v", runner.executed)
	}
	if len(rejectedCopies(t, path)) != 1 {
		t.Fatal("expected the untrusted journal to be moved aside")
	}
}

func TestRecoverKeepsWhatItCouldNotUndoAndEventuallyGivesUp(t *testing.T) {
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())
	failing := &recorder{fail: func(line string) bool { return strings.Contains(line, "nexthop=") }}

	for attempt := 1; attempt < maxRecoveryAttempts; attempt++ {
		if err := newTestManager(path, liveInterfaces(), failing.run).Recover(context.Background()); err == nil {
			t.Fatalf("attempt %d: expected the failed undo to be reported", attempt)
		}
		// Never cleared while an undo failed.
		entries := readJournal(t, path)
		if len(entries) != 1 || entries[0].Attempts != attempt || entries[0].InterfaceLUID != physicalLUID {
			t.Fatalf("attempt %d: expected only the failed change to stay journalled, got %+v", attempt, entries)
		}
	}
	// One that keeps failing is let go rather than retried at every start.
	if err := newTestManager(path, liveInterfaces(), failing.run).Recover(context.Background()); err != nil {
		t.Fatalf("final attempt: %v", err)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared after the last attempt, got %+v", entries)
	}
}

func TestRecoveryLeftoversSurviveTheNextApply(t *testing.T) {
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())

	failing := &recorder{fail: func(line string) bool { return strings.Contains(line, "nexthop=") }}
	manager := newTestManager(path, liveInterfaces(), failing.run)
	if err := manager.Recover(context.Background()); err == nil {
		t.Fatal("expected the failed undo to be reported")
	}
	// The connect that follows writes its own plan. Overwriting the journal
	// with it would lose the route the recovery could not remove.
	failing.fail = nil
	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if entries := readJournal(t, path); len(entries) == 0 || !strings.Contains(entries[0].Description, "198.51.100.4") {
		t.Fatalf("expected the leftover to stay journalled beside the new plan, got %+v", entries)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	entries := readJournal(t, path)
	if len(entries) != 1 || !strings.Contains(entries[0].Description, "198.51.100.4") {
		t.Fatalf("expected only the leftover to remain after restore, got %+v", entries)
	}
}

func TestRecoverRefusesWhileAPlanIsApplied(t *testing.T) {
	runner := &recorder{}
	manager := newTestManager(testJournalPath(t), liveInterfaces(), runner.run)
	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	runner.executed = nil
	if err := manager.Recover(context.Background()); err == nil {
		t.Fatal("expected recovery to refuse to undo live routes")
	}
	if len(runner.executed) != 0 {
		t.Fatalf("recovery undid live routes: %v", runner.executed)
	}
}

func TestApplyKeepsTheJournalWhenItsRollbackFails(t *testing.T) {
	// The capture route fails to apply, and the rollback cannot reset the
	// adapter's address. The journal must keep describing that address rather
	// than being cleared as if the rollback had worked.
	path := testJournalPath(t)
	runner := &recorder{fail: func(line string) bool {
		return (strings.Contains(line, " add ") && strings.Contains(line, "prefix=128.0.0.0/1")) ||
			strings.Contains(line, "source=dhcp") ||
			// The failed change's own undo: expected to fail, since it was
			// never made, and not worth keeping.
			(strings.Contains(line, " delete ") && strings.Contains(line, "prefix=128.0.0.0/1"))
	}}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	if err := manager.Apply(context.Background(), protectedPlan()); err == nil {
		t.Fatal("expected the apply to fail")
	}
	entries := readJournal(t, path)
	if len(entries) != 1 || entries[0].Undo[len(entries[0].Undo)-2] != "source=dhcp" || entries[0].InterfaceLUID != tunnelLUID {
		t.Fatalf("expected only the address reset to stay journalled, got %+v", entries)
	}
	if !runner.ran("nexthop=192.168.1.1 store=active") {
		t.Fatalf("expected the rest of the rollback to run, got %v", runner.executed)
	}
}

func TestRestoreRetriesOnlyWhatFailed(t *testing.T) {
	path := testJournalPath(t)
	failHost := true
	runner := &recorder{fail: func(line string) bool {
		return failHost && strings.Contains(line, " delete ") && strings.Contains(line, "nexthop=")
	}}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	if err := manager.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := manager.Restore(context.Background()); err == nil {
		t.Fatal("expected the failed undo to be reported")
	}
	entries := readJournal(t, path)
	if len(entries) != 1 || !strings.Contains(entries[0].Description, "198.51.100.4") {
		t.Fatalf("expected only the failed undo to stay journalled, got %+v", entries)
	}

	failHost = false
	runner.executed = nil
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(runner.executed) != 1 || !strings.Contains(runner.executed[0], "nexthop=192.168.1.1") {
		t.Fatalf("expected the retry to run only the undo that failed, got %v", runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}
}

func TestJournalPathMustBeTheJournal(t *testing.T) {
	directory := t.TempDir()
	good := filepath.Join(directory, JournalFileName)
	if err := ValidateJournalPath(good); err != nil {
		t.Fatalf("a journal in the data folder was refused: %v", err)
	}

	victim := filepath.Join(directory, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedFile := filepath.Join(t.TempDir(), JournalFileName)
	if err := os.Symlink(victim, linkedFile); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	linkedDirectory := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(directory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	notAFile := filepath.Join(t.TempDir(), JournalFileName)
	if err := os.Mkdir(notAFile, 0o700); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"a relative path":           JournalFileName,
		"another file name":         filepath.Join(directory, "hosts"),
		"an unclean path":           filepath.Join(directory, "x") + string(filepath.Separator) + ".." + string(filepath.Separator) + JournalFileName,
		"a link to another file":    linkedFile,
		"a file in a linked folder": filepath.Join(linkedDirectory, JournalFileName),
		"a folder":                  notAFile,
	} {
		if err := ValidateJournalPath(path); err == nil {
			t.Fatalf("%s (%s) was accepted", name, path)
		}
	}

	// Every journal operation checks the path, so a linked journal is
	// neither read nor overwritten.
	if err := NewJournalFile(linkedFile).Write(nil); err == nil {
		t.Fatal("wrote through a link")
	}
	if content, _ := os.ReadFile(victim); string(content) != "keep" {
		t.Fatalf("the link target changed: %q", content)
	}

	// A path from a client is resolved first: a linked data folder leads to
	// the folder it points at, and the journal is written there. A linked
	// journal file is still refused.
	realDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveJournalPath(filepath.Join(linkedDirectory, JournalFileName))
	if err != nil {
		t.Fatalf("a journal in a linked data folder was refused: %v", err)
	}
	if want := filepath.Join(realDirectory, JournalFileName); resolved != want {
		t.Fatalf("resolved to %s, want %s", resolved, want)
	}
	if err := NewJournalFile(resolved).Write(nil); err != nil {
		t.Fatalf("write the resolved journal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, JournalFileName)); err != nil {
		t.Fatalf("the journal did not land in the real folder: %v", err)
	}
	if _, err := ResolveJournalPath(linkedFile); err == nil {
		t.Fatal("a link to another file was accepted once resolved")
	}
	for _, path := range []string{JournalFileName, filepath.Join(directory, "hosts")} {
		if _, err := ResolveJournalPath(path); err == nil {
			t.Fatalf("%s was accepted", path)
		}
	}
	// A data folder that does not exist yet is left for the first write.
	missing := filepath.Join(t.TempDir(), "not yet", JournalFileName)
	if resolved, err := ResolveJournalPath(missing); err != nil || resolved != missing {
		t.Fatalf("a missing data folder: got %q, %v", resolved, err)
	}
}

func TestJournalWriteDoesNotFollowAPlantedTemporaryFile(t *testing.T) {
	path := testJournalPath(t)
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	operations, err := protectedPlan().Operations()
	if err != nil {
		t.Fatal(err)
	}
	if err := NewJournalFile(path).Write(operations); err != nil {
		t.Fatalf("write: %v", err)
	}
	if content, _ := os.ReadFile(victim); string(content) != "keep" {
		t.Fatalf("the journal was written through a planted link: %q", content)
	}
	if entries := readJournal(t, path); len(entries) != len(operations) {
		t.Fatalf("expected the journal to be written, got %+v", entries)
	}
}

func TestRecoverJournalReportsWhatItUndid(t *testing.T) {
	// The command-level entry point refuses a bad path before touching
	// anything, and reports an empty journal as nothing undone.
	if _, err := RecoverJournal(context.Background(), "relative.json", nil); err == nil {
		t.Fatal("expected a relative path to be refused")
	}
	undone, err := RecoverJournal(context.Background(), testJournalPath(t), nil)
	if err != nil || undone != 0 {
		t.Fatalf("expected nothing to do, got %d, %v", undone, err)
	}
}

func TestRestoreAfterTheAdapterClosedDoesNotKeepFailing(t *testing.T) {
	// One capture-route delete times out; closing the adapter then removes
	// that route with everything else on it. Retrying the delete could only
	// ever fail again - interface 17 no longer exists - so the retry must
	// find nothing left to do instead of failing for the life of the helper.
	path := testJournalPath(t)
	interfaces := liveInterfaces()
	runner := &recorder{fail: func(line string) bool {
		return strings.Contains(line, " delete ") && strings.Contains(line, "prefix=128.0.0.0/1")
	}}
	manager := newTestManager(path, interfaces, runner.run)
	if err := manager.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := manager.Restore(context.Background()); err == nil {
		t.Fatal("expected the failed undo to be reported")
	}

	delete(interfaces, tunnelIndex)
	runner.executed = nil
	for attempt := 1; attempt <= 2; attempt++ {
		if err := manager.Restore(context.Background()); err != nil {
			t.Fatalf("restore %d after the adapter closed: %v", attempt, err)
		}
	}
	if len(runner.executed) != 0 {
		t.Fatalf("ran commands against an interface that is gone: %v", runner.executed)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}
	// And the journal is free for the next start.
	if err := newTestManager(path, liveInterfaces(), runner.run).Recover(context.Background()); err != nil {
		t.Fatalf("recover after the restore: %v", err)
	}
}

func TestRestoreTreatsAHostRouteThatVanishedAsUndone(t *testing.T) {
	// A network change dropped the server's host route while the tunnel was
	// up, so its delete fails at disconnect.
	path := testJournalPath(t)
	runner := &recorder{fail: func(line string) bool {
		return strings.Contains(line, " delete ") && strings.Contains(line, "nexthop=")
	}}
	manager := newTestManager(path, liveInterfaces(), runner.run)
	manager.interfaces.routes = routeTable(winnet.Route{
		Destination: netip.MustParsePrefix("0.0.0.0/1"), InterfaceLUID: tunnelLUID, InterfaceIndex: tunnelIndex,
	})
	if err := manager.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("expected a vanished host route not to fail the restore, got %v", err)
	}
	if entries := readJournal(t, path); entries != nil {
		t.Fatalf("expected the journal to be cleared, got %+v", entries)
	}
}

func TestRestoreSkipsAChangeWhoseIndexNowNamesAnotherInterface(t *testing.T) {
	path := testJournalPath(t)
	interfaces := liveInterfaces()
	runner := &recorder{}
	manager := newTestManager(path, interfaces, runner.run)
	if err := manager.Apply(context.Background(), basePlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The adapter went away and another one was handed its index.
	interfaces[tunnelIndex] = 0x0083000000b20000
	runner.executed = nil
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(runner.executed) != 0 {
		t.Fatalf("reconfigured the interface that now has index 17: %v", runner.executed)
	}
}

func TestAnAppliedPlanKeepsTheJournalFromOtherHelpers(t *testing.T) {
	// The startup recovery runs in its own helper. Started late, it would read
	// a live dataplane's journal as leftovers and delete its capture routes;
	// finishing late, it would clear that journal.
	path := testJournalPath(t)
	live := newTestManager(path, liveInterfaces(), (&recorder{}).run)
	if err := live.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	journalled := readJournal(t, path)

	startup := &recorder{}
	other := newTestManager(path, liveInterfaces(), startup.run)
	if err := other.Recover(context.Background()); !errors.Is(err, ErrJournalInUse) {
		t.Fatalf("expected the journal to be in use, got %v", err)
	}
	if undone, err := RecoverJournal(context.Background(), path, nil); err != nil || undone != 0 {
		t.Fatalf("expected the startup recovery to leave a live journal alone, got %d, %v", undone, err)
	}
	if len(startup.executed) != 0 || len(readJournal(t, path)) != len(journalled) {
		t.Fatalf("a live plan was touched: ran %v, journal %+v", startup.executed, readJournal(t, path))
	}

	// Once the plan is restored the journal is free again.
	if err := live.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := other.Recover(context.Background()); err != nil {
		t.Fatalf("recover after the restore: %v", err)
	}
}

func TestADataplaneStartWaitsForARecoveryInProgress(t *testing.T) {
	path := testJournalPath(t)
	crashAfterApply(t, path, protectedPlan())

	// The startup recovery is stuck in a netsh call when the transport's
	// helper starts its own.
	inUndo := make(chan struct{})
	release := make(chan struct{})
	slow := newTestManager(path, map[uint32]uint64{physicalIndex: physicalLUID}, func(_ context.Context, argv []string) error {
		if strings.Contains(strings.Join(argv, " "), "nexthop=") {
			close(inUndo)
			<-release
		}
		return nil
	})
	recovered := make(chan error, 1)
	go func() { _, err := slow.recover(context.Background()); recovered <- err }()
	<-inUndo

	starting := &recorder{}
	start := newTestManager(path, liveInterfaces(), starting.run)
	start.lockWait = 5 * time.Second
	started := make(chan error, 1)
	go func() { started <- start.Recover(context.Background()) }()
	select {
	case err := <-started:
		t.Fatalf("the start did not wait for the recovery in progress: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-recovered; err != nil {
		t.Fatalf("startup recovery: %v", err)
	}
	if err := <-started; err != nil {
		t.Fatalf("start recovery: %v", err)
	}
	// The startup recovery did the work; the start found nothing to repeat.
	if len(starting.executed) != 0 {
		t.Fatalf("the same changes were undone twice: %v", starting.executed)
	}
	if err := start.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if entries := readJournal(t, path); len(entries) == 0 {
		t.Fatal("the live plan's journal was lost")
	}
}

func TestAFailedApplyAndReleaseLetTheJournalGo(t *testing.T) {
	path := testJournalPath(t)
	failing := &recorder{fail: func(line string) bool {
		return (strings.Contains(line, " add ") && strings.Contains(line, "prefix=128.0.0.0/1")) || strings.Contains(line, "source=dhcp")
	}}
	manager := newTestManager(path, liveInterfaces(), failing.run)
	if err := manager.Apply(context.Background(), protectedPlan()); err == nil {
		t.Fatal("expected the apply to fail")
	}
	// What the rollback could not undo is left to the next recovery, which
	// may be another helper's.
	if err := newTestManager(path, liveInterfaces(), (&recorder{}).run).Recover(context.Background()); err != nil {
		t.Fatalf("recover after a failed apply: %v", err)
	}

	// A runner whose adapter is gone releases what it could not undo.
	stuck := &recorder{fail: func(line string) bool {
		return strings.Contains(line, "nexthop=") && strings.Contains(line, " delete ")
	}}
	owner := newTestManager(path, liveInterfaces(), stuck.run)
	if err := owner.Apply(context.Background(), protectedPlan()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := owner.Restore(context.Background()); err == nil {
		t.Fatal("expected the host route to stay")
	}
	owner.Release()
	if entries := readJournal(t, path); len(entries) != 1 || !strings.Contains(entries[0].Description, "198.51.100.4") {
		t.Fatalf("expected the host route to stay journalled after release, got %+v", entries)
	}
	if _, err := newTestManager(path, liveInterfaces(), (&recorder{}).run).recover(context.Background()); err != nil {
		t.Fatalf("expected another manager to recover the released journal, got %v", err)
	}
}

func TestOlderHelpersReadOnlyTheHostRoutes(t *testing.T) {
	// A downgraded helper reads version 1 and replays every entry by index.
	// It must still find the host route - or it would overwrite the journal
	// and strand it - and must not find the adapter's changes, whose indices
	// it cannot check.
	path := testJournalPath(t)
	operations := crashAfterApply(t, path, protectedPlan())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var older struct {
		Version int `json:"version"`
		Entries []struct {
			Undo []string `json:"undo"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &older); err != nil {
		t.Fatal(err)
	}
	if older.Version != 1 || len(older.Entries) != 1 || !strings.Contains(strings.Join(older.Entries[0].Undo, " "), "nexthop=192.168.1.1") {
		t.Fatalf("an older helper would read %+v", older)
	}
	if len(operations) != 5 {
		t.Fatalf("expected this helper to read every entry back, got %+v", operations)
	}
}
