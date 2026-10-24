package winroute

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"shadowssh/service/internal/winnet"
)

// ErrNotSupported is returned when routing changes are attempted on an OS this
// package cannot drive.
var ErrNotSupported = errors.New("routing changes are only implemented on Windows")

const (
	// commandTimeout bounds one netsh invocation. netsh occasionally blocks on
	// a busy network stack, and a stuck apply must not hold the connect path
	// open.
	commandTimeout = 20 * time.Second
	// rollbackBudget bounds a whole undo pass. A plan is a handful of netsh
	// calls, each of which can take a second or more on a busy machine, so the
	// budget has to be a multiple of commandTimeout rather than of one call.
	rollbackBudget = 2 * time.Minute
	// maxRecoveryAttempts bounds how many recoveries an entry gets. An undo
	// that keeps failing is usually one whose route has already gone some
	// other way; retrying it on every start forever helps nobody.
	maxRecoveryAttempts = 3
)

// Runner executes one command. It exists so the manager's sequencing can be
// tested without touching a routing table.
type Runner func(ctx context.Context, argv []string) error

// interfaceTable answers which interface an index or a LUID names right now,
// and which routes the routing table holds. It exists so the identity checks
// undoing relies on can be tested off Windows.
type interfaceTable struct {
	luid  func(index uint32) (uint64, error)
	index func(luid uint64) (uint32, error)
	// routes reads the routing table; nil when it cannot be read.
	routes func() ([]winnet.Route, error)
}

var systemInterfaces = interfaceTable{luid: winnet.InterfaceLUID, index: winnet.InterfaceIndex, routes: winnet.Routes}

// Manager applies a plan and can always undo it, including across a crash.
type Manager struct {
	mu         sync.Mutex
	journal    *JournalFile
	run        Runner
	interfaces interfaceTable
	// applied is what this manager changed and has not undone yet. After a
	// failed undo it holds only the operations whose undo failed, so a retry
	// runs exactly those again.
	applied []Operation
	// leftover is what recovery found from a previous run and could not
	// finish. It stays in the journal beside this manager's own operations,
	// so the next recovery tries it again instead of losing it.
	leftover []Operation
	// lock keeps the other helpers out of the journal while this manager
	// recovers it or has a plan applied (see journal_lock.go); nil otherwise.
	lock *journalLock
	// lockWait is how long to wait for another helper to finish with the
	// journal before giving up with ErrJournalInUse.
	lockWait time.Duration
	log      func(level string, message string)
}

// NewManager returns a manager journalling to journalPath. A nil runner uses
// the real command runner.
func NewManager(journalPath string, run Runner, log func(level string, message string)) *Manager {
	if run == nil {
		run = execRunner
	}
	if log == nil {
		log = func(string, string) {}
	}
	return &Manager{journal: NewJournalFile(journalPath), run: run, interfaces: systemInterfaces, lockWait: journalLockWait, log: log}
}

// Recover undoes anything a previous run left behind. It is safe to call at
// every start and does nothing when there is no journal.
//
// A helper that is recovering the same journal is waited for, so the two do
// not undo the same changes at once, and so is one whose plan is applied:
// ErrJournalInUse means it did not let go in time.
func (m *Manager) Recover(ctx context.Context) error {
	_, err := m.recover(ctx)
	return err
}

// RecoverJournal runs the same recovery as a dataplane start, without starting
// one, and reports how many changes it undid. It lets the application clean up
// after a crash when it starts, rather than at the next TUN connect.
//
// It does not wait for the journal. If another helper has it, that helper is
// either running a dataplane - and the journal describes routes in use, not
// left over - or recovering it already; there is nothing for this one to do.
func RecoverJournal(ctx context.Context, journalPath string, log func(level string, message string)) (int, error) {
	manager := NewManager(journalPath, nil, log)
	manager.lockWait = 0
	undone, err := manager.recover(ctx)
	if errors.Is(err, ErrJournalInUse) {
		manager.log("info", "The routing journal is in use by another helper, which undoes what it finds itself; nothing was recovered here.")
		return 0, nil
	}
	return undone, err
}

type recoveryAction int

const (
	// recoveryUndo runs the entry's undo command.
	recoveryUndo recoveryAction = iota
	// recoveryGone drops the entry: its interface no longer exists, and
	// everything this program configured on it went with it.
	recoveryGone
	// recoveryKeep leaves the entry journalled for a later recovery.
	recoveryKeep
	// recoveryAbandon drops an entry that can never be undone safely.
	recoveryAbandon
)

func (m *Manager) recover(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applied) > 0 {
		// The journal then describes this manager's own live routes, which
		// are not left over from anything.
		return 0, errors.New("a routing plan is applied; there is nothing left over to recover")
	}
	if err := m.acquireLockLocked(m.lockWait); err != nil {
		return 0, err
	}
	// Nothing is applied while recovering, so the lock goes with the end of it.
	defer m.releaseLockLocked()

	ctx, cancel := rollbackContext(ctx)
	defer cancel()

	entries, err := m.journal.Read()
	if errors.Is(err, errJournalInvalid) {
		return 0, m.rejectJournalLocked(err)
	}
	if err != nil {
		return 0, err
	}
	m.leftover = nil
	if len(entries) == 0 {
		return 0, m.journal.Clear()
	}
	m.log("warning", fmt.Sprintf("Undoing %d routing changes left by a previous run.", len(entries)))

	undone, gone := 0, 0
	var kept []Operation
	// Reverse order, same as Restore: a route has to go before the address it
	// was installed on.
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		action, reason := m.recoveryActionLocked(entry)
		switch action {
		case recoveryGone:
			gone++
			continue
		case recoveryAbandon:
			m.log("warning", reason)
			continue
		case recoveryKeep:
			m.log("warning", reason)
			kept = append(kept, entry)
			continue
		}
		if err := m.runOne(ctx, entry.Undo); err != nil {
			if m.routeAbsentLocked(entry) {
				// The route went some other way - a reboot, a network change -
				// so there was nothing left to delete.
				gone++
				continue
			}
			m.log("warning", fmt.Sprintf("Could not undo %q: %s", entry.Description, err))
			kept = append(kept, entry)
			continue
		}
		undone++
	}
	if gone > 0 {
		m.log("info", fmt.Sprintf("%d of those changes were already gone with their interface or route.", gone))
	}

	var retained []Operation
	for _, entry := range kept {
		entry.Attempts++
		if entry.Attempts >= maxRecoveryAttempts {
			m.log("warning", fmt.Sprintf("Giving up on undoing %q after %d attempts; it is removed from the routing journal.", entry.Description, entry.Attempts))
			continue
		}
		retained = append(retained, entry)
	}
	slices.Reverse(retained)
	m.leftover = retained
	if err := m.persistLocked(); err != nil {
		return undone, fmt.Errorf("update routing journal: %w", err)
	}
	if len(retained) > 0 {
		// Never cleared while something could not be undone: an undo that
		// failed is exactly the state the next run has to finish.
		return undone, fmt.Errorf("%d routing changes from a previous run could not be undone; they stay journalled at %s", len(retained), m.journal.Path())
	}
	return undone, nil
}

// recoveryActionLocked decides what recovery may do with one journal entry.
//
// Every command names its interface by index, and Windows reuses indices: by
// the time recovery runs, the index may belong to another VPN's adapter or to
// the network card. So the command runs only while the index still names the
// interface it was written for.
func (m *Manager) recoveryActionLocked(entry Operation) (recoveryAction, string) {
	command, err := parseUndo(entry.Undo)
	if err != nil {
		// Read accepted it, so this cannot happen; refusing is still the safe
		// answer.
		return recoveryAbandon, fmt.Sprintf("Not undoing %q: %s", entry.Description, err)
	}
	if entry.InterfaceLUID == 0 {
		// An interface that could not be identified when the change was made
		// (see identifyLocked), or a journal from before interfaces were
		// identified - one recovery only gets to read off Windows, or from a
		// helper that is not elevated: on Windows an elevated helper refuses a
		// file an earlier release wrote, because the user could change it (see
		// journal_acl_windows.go). A host route deleted by prefix, interface
		// and next hop can only ever remove that route; anything else could
		// reconfigure whatever interface has the index now.
		if command.pinned() {
			return recoveryUndo, ""
		}
		return recoveryAbandon, fmt.Sprintf(
			"Not undoing %q: the journal does not say which interface it was made on, and interface %d may now be a different one.",
			entry.Description, command.index)
	}
	gone, err := m.interfaceGoneLocked(entry, command)
	switch {
	case err != nil:
		return recoveryKeep, fmt.Sprintf("Not undoing %q yet: could not check which interface it was made on: %s", entry.Description, err)
	case gone:
		return recoveryGone, ""
	}
	return recoveryUndo, ""
}

// interfaceGoneLocked reports whether the interface an entry's change was
// made on is gone, and the change with it: no interface has its LUID any
// more, or the one that has it was created again under another index - after
// a reboot, or a driver reinstall - and a change in the active store does not
// outlive the interface it was made on. Either way the command's index may
// now name a different interface, so it must not run. An entry made before
// interfaces were identified, or an interface that cannot be checked, is not
// taken to be gone.
func (m *Manager) interfaceGoneLocked(entry Operation, command netshCommand) (bool, error) {
	if entry.InterfaceLUID == 0 {
		return false, nil
	}
	index, err := m.interfaces.index(entry.InterfaceLUID)
	if errors.Is(err, winnet.ErrInterfaceNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return index != command.index, nil
}

// routeAbsentLocked reports whether the route an entry's undo deletes is no
// longer in the routing table, so a failed delete had nothing left to do:
// Windows drops the routes of an interface that goes down, and a host route on
// the network card is gone after a network change or a reboot. A table that
// cannot be read proves nothing, and only route deletes can be checked.
func (m *Manager) routeAbsentLocked(entry Operation) bool {
	if m.interfaces.routes == nil {
		return false
	}
	command, err := parseUndo(entry.Undo)
	if err != nil {
		return false
	}
	prefix, nextHop, ok := command.routeTarget()
	if !ok {
		return false
	}
	routes, err := m.interfaces.routes()
	if err != nil {
		return false
	}
	for _, route := range routes {
		if route.Destination.Masked() != prefix.Masked() {
			continue
		}
		if entry.InterfaceLUID != 0 && route.InterfaceLUID != entry.InterfaceLUID {
			continue
		}
		if entry.InterfaceLUID == 0 && route.InterfaceIndex != command.index {
			continue
		}
		if nextHop.IsValid() && route.NextHop.Unmap() != nextHop.Unmap() {
			continue
		}
		return false
	}
	return true
}

// rejectJournalLocked sets aside a journal this program did not write.
func (m *Manager) rejectJournalLocked(cause error) error {
	rejected, err := m.journal.Reject()
	if err != nil {
		m.log("warning", fmt.Sprintf("Refused the routing journal, and could not move it aside: %s (%s)", cause, err))
		return fmt.Errorf("%w; moving it aside failed: %v", cause, err)
	}
	m.log("warning", fmt.Sprintf("Refused the routing journal; nothing in it was run, and it was moved to %s: %s", rejected, cause))
	return fmt.Errorf("%w; nothing in it was run, and it was moved to %s", cause, rejected)
}

// Apply installs the plan. On the first failure everything already applied is
// undone, so the machine is never left half-captured.
func (m *Manager) Apply(ctx context.Context, plan Plan) error {
	operations, err := plan.Operations()
	if err != nil {
		return err
	}
	// The plan and the forms recovery accepts must agree, or a change made now
	// could not be undone after a crash. Checked before anything is
	// journalled or run.
	for _, operation := range operations {
		if err := validateOperation(operation); err != nil {
			return fmt.Errorf("routing plan for %q: %w", operation.Description, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applied) > 0 {
		return errors.New("routing plan is already applied")
	}
	// Held from here for as long as the plan is applied: another helper's
	// recovery must not take these routes for leftovers, nor rewrite the
	// journal that describes them.
	if err := m.acquireLockLocked(m.lockWait); err != nil {
		return err
	}
	operations = m.withoutRoutesInPlaceLocked(operations)
	m.identifyLocked(operations)

	// Journal first. An operation recorded but not applied costs one no-op
	// undo; an operation applied but not recorded is a leak that survives a
	// crash.
	if err := m.journal.Write(m.journalEntriesLocked(operations)); err != nil {
		m.releaseLockLocked()
		return fmt.Errorf("write routing journal: %w", err)
	}

	for index, operation := range operations {
		if err := m.runOne(ctx, operation.Apply); err != nil {
			m.rollbackLocked(ctx, operations[:index], operation)
			// No plan is applied after a failed one. What the rollback could
			// not undo stays journalled for the next recovery, which may be
			// another helper's.
			m.abandonAppliedLocked()
			m.releaseLockLocked()
			return fmt.Errorf("%s: %w", operation.Description, err)
		}
	}
	m.applied = operations
	return nil
}

// withoutRoutesInPlaceLocked drops the host routes the routing table already
// holds exactly: the same prefix, interface and next hop. Adding one again
// fails with "The object already exists", and that would roll the whole plan
// back. Such a route is usually one a killed helper left behind in a journal
// recovery refused - one written by an earlier release, say (see
// journal_acl_windows.go). It already keeps the server on the physical path,
// which is all the plan wants of it. It is left as it is: this manager did not
// add it, so it is neither journalled nor deleted when the plan is undone. A
// table that cannot be read changes nothing.
func (m *Manager) withoutRoutesInPlaceLocked(operations []Operation) []Operation {
	if m.interfaces.routes == nil {
		return operations
	}
	var routes []winnet.Route
	read := false
	kept := make([]Operation, 0, len(operations))
	for _, operation := range operations {
		command, err := parseUndo(operation.Undo)
		if err != nil || !command.pinned() {
			kept = append(kept, operation)
			continue
		}
		prefix, nextHop, ok := command.routeTarget()
		if !ok {
			kept = append(kept, operation)
			continue
		}
		if !read {
			read = true
			if routes, err = m.interfaces.routes(); err != nil {
				routes = nil
			}
		}
		if routeInPlace(routes, prefix, command.index, nextHop) {
			m.log("info", fmt.Sprintf("Not adding %s again: the routing table already has that route, which is left as it is.", operation.Description))
			continue
		}
		kept = append(kept, operation)
	}
	return kept
}

func routeInPlace(routes []winnet.Route, prefix netip.Prefix, index uint32, nextHop netip.Addr) bool {
	for _, route := range routes {
		if route.Destination.Masked() == prefix.Masked() && route.InterfaceIndex == index &&
			route.NextHop.Unmap() == nextHop.Unmap() {
			return true
		}
	}
	return false
}

// rollbackLocked undoes a partial apply: the operation that failed - netsh can
// make a change and still report an error - and then everything before it.
// It runs on its own budget, like Restore, because the caller's context may be
// the reason the apply failed.
func (m *Manager) rollbackLocked(ctx context.Context, done []Operation, failed Operation) {
	ctx, cancel := rollbackContext(ctx)
	defer cancel()
	if err := m.runOne(ctx, failed.Undo); err != nil {
		// Expected when the change itself was never made, so it is not kept.
		m.log("info", fmt.Sprintf("Undoing the failed change %q reported: %s", failed.Description, err))
	}
	m.applied = m.undoLocked(ctx, done)
	if err := m.persistLocked(); err != nil {
		m.log("warning", "Unable to update the routing journal: "+err.Error())
	}
	if len(m.applied) > 0 {
		m.log("warning", fmt.Sprintf("%d routing changes could not be rolled back; they stay journalled at %s.", len(m.applied), m.journal.Path()))
	}
}

// Restore undoes the applied plan. It reports the first failure but always
// attempts every undo, because stopping halfway is what leaves a machine
// without a working default route.
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applied) > 0 {
		ctx, cancel := rollbackContext(ctx)
		defer cancel()
		// Only the operations whose undo failed stay applied, so calling
		// Restore again retries exactly those.
		m.applied = m.undoLocked(ctx, m.applied)
	}
	persistErr := m.persistLocked()
	if len(m.applied) > 0 {
		// The journal is deliberately kept: an undo that failed is exactly the
		// state the next run has to finish, and clearing it here would strand
		// those routes until reboot with nothing left to describe them.
		if persistErr != nil {
			m.log("warning", "Unable to update the routing journal: "+persistErr.Error())
		}
		return fmt.Errorf("%d routing changes could not be undone; they stay journalled at %s", len(m.applied), m.journal.Path())
	}
	m.releaseLockLocked()
	return persistErr
}

// Release lets the journal go: whatever this manager still has applied is
// left to the next recovery - this helper's next start, another helper's, or
// the application's next launch - which finds it journalled. It is for an
// owner that will not call Restore again, such as a runner whose adapter is
// gone. Releasing a manager with nothing applied only drops its lock.
func (m *Manager) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.abandonAppliedLocked()
	m.releaseLockLocked()
}

// abandonAppliedLocked turns what is still applied into leftovers: still
// journalled, no longer this manager's to undo.
func (m *Manager) abandonAppliedLocked() {
	if len(m.applied) == 0 {
		return
	}
	m.leftover = append(m.leftover, m.applied...)
	m.applied = nil
	if err := m.persistLocked(); err != nil {
		m.log("warning", "Unable to update the routing journal: "+err.Error())
	}
}

// undoLocked runs the undo commands of operations, last applied first, and
// returns - in the order they were applied - the operations whose undo failed.
//
// A change whose interface is gone is not undone: whatever was configured on
// an adapter went with it, and its index may already name another interface.
// A delete that fails because its route is no longer there has nothing left to
// do. Neither counts as a failure, or a teardown that closed the adapter could
// never finish: its retries would keep failing on routes that cannot come back.
func (m *Manager) undoLocked(ctx context.Context, operations []Operation) []Operation {
	var failed []Operation
	alreadyGone := 0
	for index := len(operations) - 1; index >= 0; index-- {
		operation := operations[index]
		if len(operation.Undo) == 0 {
			continue
		}
		if command, err := parseUndo(operation.Undo); err == nil {
			if gone, _ := m.interfaceGoneLocked(operation, command); gone {
				alreadyGone++
				continue
			}
		}
		if err := m.runOne(ctx, operation.Undo); err != nil {
			if m.routeAbsentLocked(operation) {
				alreadyGone++
				continue
			}
			failed = append(failed, operation)
			m.log("warning", fmt.Sprintf("Could not undo %q: %s", operation.Description, err))
		}
	}
	if alreadyGone > 0 {
		m.log("info", fmt.Sprintf("%d routing changes were already gone with their interface or route.", alreadyGone))
	}
	slices.Reverse(failed)
	return failed
}

// acquireLockLocked takes the journal lock unless this manager holds it,
// waiting up to wait for another helper to let it go. Only a lock another
// helper keeps holding is an error; one that cannot be taken at all - the lock
// file cannot be opened - leaves this helper working as before locking
// existed, which is better than refusing to route.
func (m *Manager) acquireLockLocked(wait time.Duration) error {
	if m.lock != nil {
		return nil
	}
	if err := ValidateJournalPath(m.journal.Path()); err != nil {
		return err
	}
	lock, err := lockJournal(m.journal.Path(), wait)
	if errors.Is(err, ErrJournalInUse) {
		return err
	}
	if err != nil {
		m.log("warning", "Could not lock the routing journal, so another helper could change it at the same time: "+err.Error())
		return nil
	}
	m.lock = lock
	return nil
}

func (m *Manager) releaseLockLocked() {
	if m.lock == nil {
		return
	}
	m.lock.release()
	m.lock = nil
}

// identifyLocked records the LUID of the interface each operation names. Now
// is the one moment the index is certain to mean that interface: the adapter
// was just created, the physical route just looked up.
func (m *Manager) identifyLocked(operations []Operation) {
	known := make(map[uint32]uint64)
	for position := range operations {
		command, err := parseUndo(operations[position].Undo)
		if err != nil {
			continue
		}
		luid, seen := known[command.index]
		if !seen {
			luid, err = m.interfaces.luid(command.index)
			if err != nil {
				m.log("warning", fmt.Sprintf(
					"Could not identify interface %d for the routing journal; after a crash only its host routes will be undone: %s",
					command.index, err))
				luid = 0
			}
			known[command.index] = luid
		}
		operations[position].InterfaceLUID = luid
	}
}

// persistLocked records what is still outstanding - leftovers from a previous
// run and this manager's operations that are not undone - or removes the
// journal when that is nothing.
func (m *Manager) persistLocked() error {
	entries := m.journalEntriesLocked(m.applied)
	if len(entries) == 0 {
		return m.journal.Clear()
	}
	return m.journal.Write(entries)
}

func (m *Manager) journalEntriesLocked(operations []Operation) []Operation {
	entries := make([]Operation, 0, len(m.leftover)+len(operations))
	entries = append(entries, m.leftover...)
	return append(entries, operations...)
}

func (m *Manager) runOne(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	// Whatever path a command took to get here, only the forms Plan renders
	// reach the runner.
	if _, err := parseNetsh(argv); err != nil {
		return err
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return m.run(commandCtx, argv)
}

// rollbackContext detaches an undo pass from the caller's context.
//
// Undo is the one thing that must not be abandoned: half-removed capture routes
// leave the machine pointing at an adapter that is about to disappear. Callers
// routinely hand in a context that is already cancelled - the IPC client went
// away, the service is being signalled - and honouring it would abort every
// remaining command instantly. Only the total budget applies here, so a hung
// netsh still cannot wedge shutdown.
func rollbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	_ = parent
	return context.WithTimeout(context.Background(), rollbackBudget)
}

// execRunner runs netsh from the system directory. The bare name would be
// looked up through PATH, which the user's own environment controls, and this
// process is elevated.
func execRunner(ctx context.Context, argv []string) error {
	if len(argv) == 0 || argv[0] != netshProgram {
		return fmt.Errorf("only %s is run to change routing", netshProgram)
	}
	program, err := netshPath()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, program, argv[1:]...)
	// Started in the system directory as well, so nothing it resolves against
	// its working directory comes from a folder the user can write to.
	command.Dir = filepath.Dir(program)
	hideConsole(command)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	// netsh reports failures in prose on stdout with a zero exit status often
	// enough that the output is worth carrying into the error either way.
	message := strings.TrimSpace(string(output))
	if message == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, collapseWhitespace(message))
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
