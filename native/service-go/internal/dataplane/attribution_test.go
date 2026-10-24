package dataplane

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestOwnerTableRefreshesForASocketNewerThanTheSnapshot(t *testing.T) {
	// A socket the stack has just seen cannot be in a snapshot taken before it
	// existed. One forced refresh is what turns that miss into an answer.
	calls := 0
	rows := []OwnerRow{}
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		calls++
		return rows, nil
	})
	now := time.Unix(1_700_000_000, 0)
	table.now = func() time.Time { return now }

	local := netip.MustParseAddrPort("192.168.1.10:51000")
	if name := table.Owner(ProtocolTCP, local); name != "" {
		t.Fatalf("expected no owner before the socket exists, got %q", name)
	}
	rows = []OwnerRow{{Protocol: ProtocolTCP, Local: local, ProcessName: `C:\Apps\Discord.exe`, PID: 3120}}

	// Past the cooldown the retry is taken at once.
	table.sleep = func(time.Duration) { t.Fatal("waited past the cooldown") }
	now = now.Add(ownerRefreshCooldown + time.Millisecond)
	if owner := table.Process(ProtocolTCP, local); owner != (SocketOwner{Name: "discord.exe", PID: 3120}) {
		t.Fatalf("expected the refreshed snapshot to name the owner and its process, got %+v", owner)
	}
	if calls < 2 {
		t.Fatalf("expected the table to be re-read, got %d calls", calls)
	}
}

func TestOwnerTableWaitsOutTheCooldownForASocketNewerThanTheSnapshot(t *testing.T) {
	// The report: a browser opens its connections within a few milliseconds of
	// each other. The first miss took a snapshot; every later one fell inside
	// the cooldown, gave up, and its flow went out directly although the
	// browser was selected by a process rule.
	var mu sync.Mutex
	calls := 0
	rows := []OwnerRow{}
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return append([]OwnerRow(nil), rows...), nil
	})
	now := time.Unix(1_700_000_000, 0)
	var slept []time.Duration
	table.now = func() time.Time { return now }
	table.sleep = func(wait time.Duration) {
		slept = append(slept, wait)
		now = now.Add(wait)
	}

	first := netip.MustParseAddrPort("192.168.1.10:51000")
	if name := table.Owner(ProtocolTCP, first); name != "" {
		t.Fatalf("expected no owner before the socket exists, got %q", name)
	}
	mu.Lock()
	rows = []OwnerRow{{Protocol: ProtocolTCP, Local: first, ProcessName: "chrome.exe"}}
	mu.Unlock()

	// The clock has not moved: the snapshot is fresh and the cooldown is on.
	if name := table.Owner(ProtocolTCP, first); name != "chrome.exe" {
		t.Fatalf("expected the miss to wait for a new snapshot, got %q", name)
	}
	if calls != 2 {
		t.Fatalf("expected exactly one more snapshot, got %d calls", calls)
	}
	if len(slept) != 1 || slept[0] <= 0 || slept[0] > ownerRefreshCooldown {
		t.Fatalf("expected one wait of at most the cooldown, got %v", slept)
	}

	// A hit is answered from the snapshot without waiting.
	if name := table.Owner(ProtocolTCP, first); name != "chrome.exe" || calls != 2 || len(slept) != 1 {
		t.Fatalf("a hit re-read the table or waited: %q, %d calls, %v", name, calls, slept)
	}
}

func TestOwnerTableCoalescesABurstOfMissesIntoOneSnapshot(t *testing.T) {
	const burst = 20
	var mu sync.Mutex
	calls := 0
	var rows []OwnerRow
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return append([]OwnerRow(nil), rows...), nil
	})
	var clock sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	table.now = func() time.Time {
		clock.Lock()
		defer clock.Unlock()
		return now
	}
	gate := make(chan struct{})
	var sleeping sync.WaitGroup
	sleeping.Add(burst)
	table.sleep = func(time.Duration) {
		sleeping.Done()
		<-gate
	}

	// The first snapshot is taken before any of the burst's sockets exist.
	table.Owner(ProtocolTCP, netip.MustParseAddrPort("192.168.1.10:50999"))
	locals := make([]netip.AddrPort, burst)
	mu.Lock()
	for i := range locals {
		locals[i] = netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), uint16(51000+i))
		rows = append(rows, OwnerRow{Protocol: ProtocolTCP, Local: locals[i], ProcessName: "chrome.exe"})
	}
	mu.Unlock()

	names := make([]string, burst)
	var done sync.WaitGroup
	for i := range locals {
		done.Add(1)
		go func() {
			defer done.Done()
			names[i] = table.Owner(ProtocolTCP, locals[i])
		}()
	}
	// Every miss is inside the cooldown and waiting it out; then it passes.
	sleeping.Wait()
	clock.Lock()
	now = now.Add(ownerRefreshCooldown)
	clock.Unlock()
	close(gate)
	done.Wait()

	for i, name := range names {
		if name != "chrome.exe" {
			t.Fatalf("socket %d: got %q", i, name)
		}
	}
	if calls != 2 {
		t.Fatalf("expected the burst to share one snapshot, got %d snapshots in all", calls)
	}
}

func TestOwnerTableDoesNotRepeatASnapshotBegunAfterTheLookup(t *testing.T) {
	// A stale snapshot is refreshed by the lookup itself. If the socket is not
	// in that one, it is not attributable, and a second read would only
	// repeat the same syscall.
	calls := 0
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		calls++
		return nil, nil
	})
	now := time.Unix(1_700_000_000, 0)
	table.now = func() time.Time { return now }
	table.sleep = func(time.Duration) { t.Fatal("waited although a fresh snapshot had been taken") }
	if name := table.Owner(ProtocolTCP, netip.MustParseAddrPort("192.168.1.10:51000")); name != "" || calls != 1 {
		t.Fatalf("got %q after %d snapshots", name, calls)
	}
	now = now.Add(time.Second)
	if name := table.Owner(ProtocolTCP, netip.MustParseAddrPort("192.168.1.10:51001")); name != "" || calls != 2 {
		t.Fatalf("got %q after %d snapshots", name, calls)
	}
}

func TestOwnerTableMatchesWildcardBinds(t *testing.T) {
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		return []OwnerRow{{
			Protocol:    ProtocolUDP,
			Local:       netip.MustParseAddrPort("0.0.0.0:50000"),
			ProcessName: "Telegram.exe",
		}}, nil
	})
	if name := table.Owner(ProtocolUDP, netip.MustParseAddrPort("192.168.1.10:50000")); name != "telegram.exe" {
		t.Fatalf("expected a wildcard bind to own the flow, got %q", name)
	}
	if name := table.Owner(ProtocolTCP, netip.MustParseAddrPort("192.168.1.10:50000")); name != "" {
		t.Fatalf("expected protocols to be kept apart, got %q", name)
	}
}

func TestOwnerTableKeepsTheLastGoodSnapshotOnFailure(t *testing.T) {
	fail := false
	table := NewOwnerTable(func() ([]OwnerRow, error) {
		if fail {
			return nil, errors.New("table read failed")
		}
		return []OwnerRow{{
			Protocol:    ProtocolTCP,
			Local:       netip.MustParseAddrPort("192.168.1.10:51000"),
			ProcessName: "chrome.exe",
		}}, nil
	})
	now := time.Unix(1_700_000_000, 0)
	table.now = func() time.Time { return now }

	local := netip.MustParseAddrPort("192.168.1.10:51000")
	if name := table.Owner(ProtocolTCP, local); name != "chrome.exe" {
		t.Fatalf("expected the first snapshot to answer, got %q", name)
	}
	fail = true
	now = now.Add(time.Second)
	if name := table.Owner(ProtocolTCP, local); name != "chrome.exe" {
		t.Fatalf("expected the last good snapshot to keep answering, got %q", name)
	}
}

func TestProtocolFromTableName(t *testing.T) {
	for value, expected := range map[string]Protocol{"tcp4": ProtocolTCP, "tcp6": ProtocolTCP, "udp4": ProtocolUDP, "udp6": ProtocolUDP} {
		got, ok := ProtocolFromTableName(value)
		if !ok || got != expected {
			t.Fatalf("expected %q to map to %q, got %q (ok=%v)", value, expected, got, ok)
		}
	}
	if _, ok := ProtocolFromTableName("icmp"); ok {
		t.Fatalf("expected an unknown protocol to be rejected")
	}
}
