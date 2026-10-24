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
// snapshot - waits for one snapshot taken after the lookup began and retries.

// OwnerRow is one socket and the process that owns it.
type OwnerRow struct {
	Protocol    Protocol
	Local       netip.AddrPort
	ProcessName string
	// PID is the owning process's ID, or 0 when the table did not say.
	PID uint32
}

// SocketOwner is the process that owns a socket. The zero value means
// "unknown".
type SocketOwner struct {
	// Name is the lowercase image name, `.exe` included (see
	// NormalizeProcessName).
	Name string
	// PID is the process ID, or 0 when it is not known. The name says which
	// program it is; only the ID says which running copy of it.
	PID uint32
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
	// A miss inside it waits it out rather than giving up, so it is also the
	// longest a miss is ever held back before its own snapshot is taken.
	ownerRefreshCooldown = 50 * time.Millisecond
)

// OwnerTable caches socket ownership.
type OwnerTable struct {
	snapshot OwnerSnapshotter
	now      func() time.Time
	sleep    func(time.Duration)

	mu          sync.Mutex
	exact       map[ownerKey]SocketOwner
	wildcard    map[ownerKey]SocketOwner
	capturedAt  time.Time
	lastAttempt time.Time
	// attempts counts the snapshots begun so far. A lookup notes it on entry:
	// only a snapshot numbered higher began after the socket being looked up
	// existed, so only such a snapshot can show that it is not there. Clock
	// readings cannot tell that apart on Windows, where they are coarser than
	// the gap between two connects.
	attempts uint64
	inflight *sync.WaitGroup
}

type ownerKey struct {
	protocol Protocol
	address  netip.Addr
	port     uint16
}

// NewOwnerTable returns a table backed by snapshot.
func NewOwnerTable(snapshot OwnerSnapshotter) *OwnerTable {
	return &OwnerTable{snapshot: snapshot, now: time.Now, sleep: time.Sleep}
}

// Owner is the image name of the process that owns a socket, "" when it is
// not known.
func (t *OwnerTable) Owner(protocol Protocol, local netip.AddrPort) string {
	return t.Process(protocol, local).Name
}

// Process implements Attributor.
func (t *OwnerTable) Process(protocol Protocol, local netip.AddrPort) SocketOwner {
	if !local.IsValid() || local.Port() == 0 {
		return SocketOwner{}
	}
	t.mu.Lock()
	seen := t.attempts
	t.mu.Unlock()
	if owner := t.lookup(protocol, local, true); owner.Name != "" {
		return owner
	}
	// A socket newer than the snapshot cannot be in it. One snapshot begun
	// after this lookup distinguishes "too new" from "genuinely
	// unattributable"; a second would only repeat the same syscall. Giving up
	// inside the cooldown instead - as this once did - answered "" for every
	// socket of a connection burst, and a selected application's flows went
	// out directly.
	t.refreshAfter(seen)
	return t.lookup(protocol, local, false)
}

func (t *OwnerTable) lookup(protocol Protocol, local netip.AddrPort, allowRefresh bool) SocketOwner {
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
	if owner, ok := exact[ownerKey{protocol, address, local.Port()}]; ok {
		return owner
	}
	// A socket bound to the unspecified address serves every local address, so
	// a flow from any of them belongs to it.
	if owner, ok := wildcard[ownerKey{protocol: protocol, port: local.Port()}]; ok {
		return owner
	}
	return SocketOwner{}
}

// refresh takes at most one snapshot at a time; concurrent callers wait for
// the one in flight rather than piling more syscalls onto a busy moment.
// Inside the cooldown it does nothing.
func (t *OwnerTable) refresh() {
	t.mu.Lock()
	if waiter := t.inflight; waiter != nil {
		t.mu.Unlock()
		waiter.Wait()
		return
	}
	if t.coolingLocked() > 0 {
		t.mu.Unlock()
		return
	}
	waiter := t.beginLocked()
	t.mu.Unlock()
	t.capture(waiter)
}

// refreshAfter returns once a snapshot begun after attempt number seen has
// completed, taking one if need be. Inside the cooldown it waits the cooldown
// out instead of giving up, so the wait is bounded by ownerRefreshCooldown,
// and every miss of a burst shares the one snapshot taken when it ends.
func (t *OwnerTable) refreshAfter(seen uint64) {
	cooled := false
	for {
		t.mu.Lock()
		fresh := t.attempts > seen
		switch waiter := t.inflight; {
		case waiter != nil:
			t.mu.Unlock()
			waiter.Wait()
			if fresh {
				return
			}
			// That snapshot began before this lookup did, so it cannot hold the
			// socket. It is the only such one: any later is fresh.
		case fresh:
			t.mu.Unlock()
			return
		case !cooled && t.coolingLocked() > 0:
			wait := t.coolingLocked()
			t.mu.Unlock()
			t.sleep(wait)
			// Not re-checked against the clock afterwards: a coarse clock can
			// still read inside the cooldown after it has passed.
			cooled = true
		default:
			started := t.beginLocked()
			t.mu.Unlock()
			t.capture(started)
			return
		}
	}
}

// coolingLocked is how much of the cooldown since the last attempt is left.
func (t *OwnerTable) coolingLocked() time.Duration {
	if t.lastAttempt.IsZero() {
		return 0
	}
	return min(ownerRefreshCooldown-t.now().Sub(t.lastAttempt), ownerRefreshCooldown)
}

// beginLocked registers a snapshot about to be taken.
func (t *OwnerTable) beginLocked() *sync.WaitGroup {
	waiter := &sync.WaitGroup{}
	waiter.Add(1)
	t.inflight = waiter
	t.lastAttempt = t.now()
	t.attempts++
	return waiter
}

// capture takes the snapshot beginLocked registered. A failed read keeps the
// last good snapshot answering.
func (t *OwnerTable) capture(waiter *sync.WaitGroup) {
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

func indexOwnerRows(rows []OwnerRow) (map[ownerKey]SocketOwner, map[ownerKey]SocketOwner) {
	exact := make(map[ownerKey]SocketOwner, len(rows))
	wildcard := make(map[ownerKey]SocketOwner)
	for _, row := range rows {
		name := NormalizeProcessName(row.ProcessName)
		if name == "" || !row.Local.IsValid() || row.Local.Port() == 0 {
			continue
		}
		owner := SocketOwner{Name: name, PID: row.PID}
		address := row.Local.Addr().Unmap()
		if address.IsUnspecified() {
			// First row wins: the table lists both address families for a
			// dual-stack socket, and later rows describe the same owner.
			if _, exists := wildcard[ownerKey{protocol: row.Protocol, port: row.Local.Port()}]; !exists {
				wildcard[ownerKey{protocol: row.Protocol, port: row.Local.Port()}] = owner
			}
			continue
		}
		key := ownerKey{row.Protocol, address, row.Local.Port()}
		if _, exists := exact[key]; !exists {
			exact[key] = owner
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
