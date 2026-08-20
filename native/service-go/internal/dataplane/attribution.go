package dataplane

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Attribution answers "which application opened this socket" for every flow
// the stack accepts. The answer is what makes a `process.name` rule mean
// anything: a packet carries addresses, not identities.
//
// The owner tables are a per-snapshot syscall, not a per-socket one. A browser
// can open dozens of connections in a single tick, and a table read for each
// of them would put a kernel enumeration of every socket on the machine on the
// hot path. Instead one snapshot serves every lookup within a short window,
// and a miss - which is what a brand-new socket looks like against a stale
// snapshot - forces one refresh and retries.

// OwnerRow is one socket and the process that owns it.
type OwnerRow struct {
	Protocol    Protocol
	Local       netip.AddrPort
	ProcessName string
}

// OwnerSnapshotter enumerates every local socket. It is injected so the
// dataplane can be exercised without Windows.
type OwnerSnapshotter func() ([]OwnerRow, error)

const (
	// ownerSnapshotTTL is how long a snapshot serves lookups unconditionally.
	// Long enough to absorb a connection burst, short enough that a miss
	// caused by staleness is rare.
	ownerSnapshotTTL = 250 * time.Millisecond
	// ownerRefreshCooldown bounds forced refreshes when lookups keep missing,
	// which is the normal state for machines with traffic we cannot attribute.
	ownerRefreshCooldown = 50 * time.Millisecond
)

// OwnerTable caches socket ownership.
type OwnerTable struct {
	snapshot OwnerSnapshotter
	now      func() time.Time

	mu          sync.Mutex
	exact       map[ownerKey]string
	wildcard    map[ownerKey]string
	capturedAt  time.Time
	lastAttempt time.Time
	inflight    *sync.WaitGroup
}

type ownerKey struct {
	protocol Protocol
	address  netip.Addr
	port     uint16
}

// NewOwnerTable returns a table backed by snapshot.
func NewOwnerTable(snapshot OwnerSnapshotter) *OwnerTable {
	return &OwnerTable{snapshot: snapshot, now: time.Now}
}

// Owner implements Attributor.
func (t *OwnerTable) Owner(protocol Protocol, local netip.AddrPort) string {
	if !local.IsValid() || local.Port() == 0 {
		return ""
	}
	if name := t.lookup(protocol, local, true); name != "" {
		return name
	}
	// A socket newer than the snapshot cannot be in it. One forced refresh
	// distinguishes "too new" from "genuinely unattributable"; a second would
	// only repeat the same syscall.
	t.refresh()
	return t.lookup(protocol, local, false)
}

func (t *OwnerTable) lookup(protocol Protocol, local netip.AddrPort, allowRefresh bool) string {
	t.mu.Lock()
	stale := t.capturedAt.IsZero() || t.now().Sub(t.capturedAt) > ownerSnapshotTTL
	exact := t.exact
	wildcard := t.wildcard
	t.mu.Unlock()

	if stale && allowRefresh {
		t.refresh()
		t.mu.Lock()
		exact = t.exact
		wildcard = t.wildcard
		t.mu.Unlock()
	}

	address := local.Addr().Unmap()
	if name, ok := exact[ownerKey{protocol, address, local.Port()}]; ok {
		return name
	}
	// A socket bound to the unspecified address serves every local address, so
	// a flow from any of them belongs to it.
	if name, ok := wildcard[ownerKey{protocol: protocol, port: local.Port()}]; ok {
		return name
	}
	return ""
}

// refresh takes at most one snapshot at a time; concurrent callers wait for
// the one in flight rather than piling more syscalls onto a busy moment.
func (t *OwnerTable) refresh() {
	t.mu.Lock()
	if waiter := t.inflight; waiter != nil {
		t.mu.Unlock()
		waiter.Wait()
		return
	}
	if !t.lastAttempt.IsZero() && t.now().Sub(t.lastAttempt) < ownerRefreshCooldown {
		t.mu.Unlock()
		return
	}
	waiter := &sync.WaitGroup{}
	waiter.Add(1)
	t.inflight = waiter
	t.lastAttempt = t.now()
	t.mu.Unlock()

	rows, err := t.snapshot()

	t.mu.Lock()
	if err == nil {
		t.exact, t.wildcard = indexOwnerRows(rows)
		t.capturedAt = t.now()
	}
	t.inflight = nil
	t.mu.Unlock()
	waiter.Done()
}

func indexOwnerRows(rows []OwnerRow) (map[ownerKey]string, map[ownerKey]string) {
	exact := make(map[ownerKey]string, len(rows))
	wildcard := make(map[ownerKey]string)
	for _, row := range rows {
		name := NormalizeProcessName(row.ProcessName)
		if name == "" || !row.Local.IsValid() || row.Local.Port() == 0 {
			continue
		}
		address := row.Local.Addr().Unmap()
		if address.IsUnspecified() {
			// First row wins: the table lists both address families for a
			// dual-stack socket, and later rows describe the same owner.
			if _, exists := wildcard[ownerKey{protocol: row.Protocol, port: row.Local.Port()}]; !exists {
				wildcard[ownerKey{protocol: row.Protocol, port: row.Local.Port()}] = name
			}
			continue
		}
		key := ownerKey{row.Protocol, address, row.Local.Port()}
		if _, exists := exact[key]; !exists {
			exact[key] = name
		}
	}
	return exact, wildcard
}

// ProtocolFromTableName maps the protocol strings the platform tables report
// ("tcp4", "udp6") onto the dataplane's two protocols.
func ProtocolFromTableName(value string) (Protocol, bool) {
	switch {
	case strings.HasPrefix(value, "tcp"):
		return ProtocolTCP, true
	case strings.HasPrefix(value, "udp"):
		return ProtocolUDP, true
	default:
		return "", false
	}
}
