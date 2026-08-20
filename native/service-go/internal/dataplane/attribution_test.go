package dataplane

import (
	"errors"
	"net/netip"
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
	rows = []OwnerRow{{Protocol: ProtocolTCP, Local: local, ProcessName: `C:\Apps\Discord.exe`}}

	// The cooldown is what stops a busy stack from re-reading the table for
	// every unattributable flow, so time has to move before the retry.
	now = now.Add(ownerRefreshCooldown + time.Millisecond)
	if name := table.Owner(ProtocolTCP, local); name != "discord.exe" {
		t.Fatalf("expected the refreshed snapshot to name the owner, got %q", name)
	}
	if calls < 2 {
		t.Fatalf("expected the table to be re-read, got %d calls", calls)
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
