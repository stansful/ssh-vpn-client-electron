package winroute

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
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
)

// Runner executes one command. It exists so the manager's sequencing can be
// tested without touching a routing table.
type Runner func(ctx context.Context, argv []string) error

// Manager applies a plan and can always undo it, including across a crash.
type Manager struct {
	mu      sync.Mutex
	journal *JournalFile
	run     Runner
	applied []Operation
	log     func(level string, message string)
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
	return &Manager{journal: NewJournalFile(journalPath), run: run, log: log}
}

// Recover undoes anything a previous run left behind. It is safe to call at
// every start and does nothing when there is no journal.
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := rollbackContext(ctx)
	defer cancel()

	entries, err := m.journal.Read()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return m.journal.Clear()
	}
	m.log("warning", fmt.Sprintf("Undoing %d routing changes left by a previous run.", len(entries)))
	// Reverse order, same as Restore: a route has to go before the address it
	// was installed on.
	failures := m.undoLocked(ctx, UndoOrder(entries))
	if failures > 0 {
		// Almost always because the adapter they referred to is already gone,
		// which is the outcome we wanted. The journal is cleared either way:
		// retrying the same commands forever on every start would be worse
		// than accepting the one that is now meaningless.
		m.log("warning", fmt.Sprintf("%d of those changes reported an error, most likely because the adapter is already gone.", failures))
	}
	return m.journal.Clear()
}

// Apply installs the plan. On the first failure everything already applied is
// undone, so the machine is never left half-captured.
func (m *Manager) Apply(ctx context.Context, plan Plan) error {
	operations, err := plan.Operations()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applied) > 0 {
		return errors.New("routing plan is already applied")
	}

	// Journal first. An operation recorded but not applied costs one no-op
	// undo; an operation applied but not recorded is a leak that survives a
	// crash.
	if err := m.journal.Write(operations); err != nil {
		return fmt.Errorf("write routing journal: %w", err)
	}

	for index, operation := range operations {
		if err := m.runOne(ctx, operation.Apply); err != nil {
			m.undoLocked(ctx, UndoOrder(operations[:index+1]))
			if clearErr := m.journal.Clear(); clearErr != nil {
				m.log("warning", "Unable to clear the routing journal: "+clearErr.Error())
			}
			return fmt.Errorf("%s: %w", operation.Description, err)
		}
	}
	m.applied = operations
	return nil
}

// Restore undoes the applied plan. It reports the first failure but always
// attempts every undo, because stopping halfway is what leaves a machine
// without a working default route.
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applied) == 0 {
		return m.journal.Clear()
	}
	ctx, cancel := rollbackContext(ctx)
	defer cancel()
	failures := m.undoLocked(ctx, UndoOrder(m.applied))
	if failures > 0 {
		// The journal is deliberately kept: an undo that failed is exactly the
		// state the next run has to finish, and clearing it here would strand
		// those routes until reboot with nothing left to describe them.
		m.applied = nil
		return fmt.Errorf("%d routing changes could not be undone; they stay journalled at %s", failures, m.journal.Path())
	}
	m.applied = nil
	return m.journal.Clear()
}

func (m *Manager) undoLocked(ctx context.Context, operations []Operation) int {
	failures := 0
	for _, operation := range operations {
		if len(operation.Undo) == 0 {
			continue
		}
		if err := m.runOne(ctx, operation.Undo); err != nil {
			failures++
			m.log("warning", fmt.Sprintf("Could not undo %q: %s", operation.Description, err))
		}
	}
	return failures
}

func (m *Manager) runOne(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return nil
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

func execRunner(ctx context.Context, argv []string) error {
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
