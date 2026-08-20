package winroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// A crash between applying a route and removing it leaves the machine in a
// state this process no longer remembers. The journal is what makes that
// recoverable: every operation is written to disk before it is applied, so any
// later run - including the next launch after a hard kill - can replay the undo
// commands without knowing why they were added.
//
// This mirrors how WindowsSystemProxyManager journals registry state on the
// TypeScript side, and for the same reason.

// JournalVersion guards against an older build reading a newer file. An
// unknown version is treated as "cannot safely undo" and reported rather than
// guessed at.
const JournalVersion = 1

// Journal is the on-disk record of applied operations.
type Journal struct {
	Version int         `json:"version"`
	Entries []Operation `json:"entries"`
}

// JournalFile reads and writes one journal path atomically.
type JournalFile struct {
	path string
}

// NewJournalFile returns a journal stored at path.
func NewJournalFile(path string) *JournalFile {
	return &JournalFile{path: path}
}

// Path is where the journal lives.
func (f *JournalFile) Path() string {
	return f.path
}

// Write replaces the journal. Writing happens before the operations are
// applied, so a crash can only ever leave a journal that claims more than was
// done - and an undo command for an operation that never happened is a no-op.
func (f *JournalFile) Write(entries []Operation) error {
	encoded, err := json.Marshal(Journal{Version: JournalVersion, Entries: entries})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	// A torn journal is worse than none: it would leave undo commands that
	// cannot be parsed. Write beside the target and rename over it.
	temporary := f.path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, f.path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

// Read returns the journalled operations, or nil when there is no journal.
func (f *JournalFile) Read() ([]Operation, error) {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var journal Journal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, fmt.Errorf("read routing journal %s: %w", f.path, err)
	}
	if journal.Version != JournalVersion {
		return nil, fmt.Errorf("routing journal %s has unsupported version %d", f.path, journal.Version)
	}
	return journal.Entries, nil
}

// Clear removes the journal. It is called only after every undo has run.
func (f *JournalFile) Clear() error {
	err := os.Remove(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// UndoOrder returns the operations in the order they must be undone: the
// reverse of the order they were applied, so a route is removed before the
// address it depends on.
func UndoOrder(entries []Operation) []Operation {
	reversed := make([]Operation, 0, len(entries))
	for index := len(entries) - 1; index >= 0; index-- {
		reversed = append(reversed, entries[index])
	}
	return reversed
}
