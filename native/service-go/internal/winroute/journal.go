package winroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A crash between applying a route and removing it leaves the machine in a
// state this process no longer remembers. The journal is what makes that
// recoverable: every operation is written to disk before it is applied, so any
// later run - including the next launch after a hard kill - can replay the undo
// commands without knowing why they were added.
//
// This mirrors how WindowsSystemProxyManager journals registry state on the
// TypeScript side, and for the same reason.
//
// The file sits in the user's own data folder and is read by an elevated
// process, so it is read as untrusted input: bounded in size, every undo
// checked against the forms Plan renders (see command.go), and refused whole if
// any of it does not fit. On Windows an elevated helper also writes it so that
// only administrators can change it, and refuses one anybody else could have
// written (see journal_acl_windows.go): otherwise any program the user runs
// could list valid undo commands for another VPN's routes or another network
// card's address, and have the helper run them with its rights.

// JournalVersion guards against an older build reading a newer file. An
// unknown version is treated as "cannot safely undo" and reported rather than
// guessed at.
//
// Entries record the identity (LUID) of the interface they name, so recovery
// never acts on an interface that has since been given the same index. The
// version is still 1, which is what older helpers read, so a downgraded app
// still recovers what a crash left behind instead of overwriting the journal
// it could not read. Those helpers trust indices, though, so `entries` holds
// only the host routes - deleted by prefix, interface and next hop, they can
// only ever remove the route they name - and the changes on the tunnel
// adapter go in `adapterEntries`, which older helpers ignore: after a crash
// that adapter is gone, and its changes with it. A version 2 file, which no
// release wrote, is read the same way.
const JournalVersion = 1

// JournalFileName is the only name a journal may have. The path comes from the
// client, and in service mode the file is written, renamed and deleted with
// SYSTEM rights: a fixed name keeps that from reaching any other file.
const JournalFileName = "tun-routing-journal.json"

const (
	// maxJournalBytes and maxJournalEntries bound what is read. A plan is a
	// dozen operations plus a host route per transport address.
	maxJournalBytes   = 1 << 20
	maxJournalEntries = 256
	// maxDescriptionBytes bounds the free text that reaches the log.
	maxDescriptionBytes = 512
)

// errJournalInvalid marks a journal this program did not write: unreadable
// JSON, an unknown version, or an entry that is not a command Plan renders.
var errJournalInvalid = errors.New("routing journal was refused")

// Journal is the on-disk record of applied operations. Read in order, entries
// and then adapter entries, they are the operations in the order they were
// applied - leftovers of earlier runs aside, whose changes sit on interfaces
// of their own.
type Journal struct {
	Version int `json:"version"`
	// Entries are the host routes, the only changes an older helper may
	// replay (see JournalVersion).
	Entries []Operation `json:"entries"`
	// AdapterEntries are every other change.
	AdapterEntries []Operation `json:"adapterEntries,omitempty"`
}

// journalTrust checks that an open journal was written by a helper with the
// rights to keep it from everyone else. A variable only so tests can stand in
// for the Windows check.
var journalTrust = checkJournalFile

// splitJournalEntries puts the host routes first and everything else after,
// each in the order given.
func splitJournalEntries(entries []Operation) (hostRoutes []Operation, adapter []Operation) {
	for _, entry := range entries {
		if command, err := parseUndo(entry.Undo); err == nil && command.pinned() {
			hostRoutes = append(hostRoutes, entry)
			continue
		}
		adapter = append(adapter, entry)
	}
	return hostRoutes, adapter
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

// ResolveJournalPath checks a journal path a client sent and returns the one
// to use from then on: the same file name in the folder the path really
// leads to. A data folder moved to another drive and linked back - a junction
// or a directory symbolic link - is an ordinary setup, and refusing it turned
// TUN off for every connect. It is resolved once, here, and every later
// journal operation checks the resolved path as ValidateJournalPath does, so
// a link put in its place afterwards is still refused. A folder that does not
// exist yet is left as it is: the first write creates it.
func ResolveJournalPath(path string) (string, error) {
	if err := validateJournalName(path); err != nil {
		return "", err
	}
	directory := filepath.Dir(path)
	resolved, err := finalDirectory(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return path, ValidateJournalPath(path)
	}
	if err != nil {
		return "", fmt.Errorf("resolve routing journal folder %s: %w", directory, err)
	}
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("routing journal folder %s resolves to %s, which is not an absolute path", directory, resolved)
	}
	journalPath := filepath.Join(resolved, filepath.Base(path))
	if err := ValidateJournalPath(journalPath); err != nil {
		return "", err
	}
	return journalPath, nil
}

// validateJournalName accepts only an absolute, clean path to a file called
// JournalFileName.
func validateJournalName(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("routing journal path %q must be absolute and clean", path)
	}
	if !strings.EqualFold(filepath.Base(path), JournalFileName) {
		return fmt.Errorf("routing journal path %q must name a file called %s", path, JournalFileName)
	}
	return nil
}

// ValidateJournalPath accepts only an absolute, clean path to a file called
// JournalFileName that is not a link, in a folder that is not one either. A
// missing file or folder is fine: the first write creates them. A path from a
// client goes through ResolveJournalPath first, which follows a linked folder
// to the one it leads to.
func ValidateJournalPath(path string) error {
	if err := validateJournalName(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("routing journal %s is not a regular file", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect routing journal %s: %w", path, err)
	}
	directory := filepath.Dir(path)
	if info, err := os.Lstat(directory); err == nil {
		if info.Mode().Type() != fs.ModeDir {
			return fmt.Errorf("routing journal folder %s is a link or reparse point", directory)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect routing journal folder %s: %w", directory, err)
	}
	return nil
}

// Write replaces the journal. Writing happens before the operations are
// applied, so a crash can only ever leave a journal that claims more than was
// done - and an undo command for an operation that never happened is a no-op.
func (f *JournalFile) Write(entries []Operation) error {
	if err := ValidateJournalPath(f.path); err != nil {
		return err
	}
	hostRoutes, adapter := splitJournalEntries(entries)
	if hostRoutes == nil {
		hostRoutes = []Operation{}
	}
	encoded, err := json.Marshal(Journal{Version: JournalVersion, Entries: hostRoutes, AdapterEntries: adapter})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	// A torn journal is worse than none: it would leave undo commands that
	// cannot be parsed. Write beside the target and rename over it.
	//
	// The temporary file is created, never opened: opening follows a link
	// someone left at that name, and this process may be elevated. A leftover
	// is removed first - which removes a link itself, not what it points at -
	// and an exclusive create then fails rather than follow one planted in the
	// meantime. It is created with the protection it keeps once renamed, so
	// there is no moment in which someone else could open it for writing.
	temporary := f.path + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := createJournalFile(temporary)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, f.path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

// Read returns the journalled operations, or nil when there is no journal. A
// journal this program did not write is reported as errJournalInvalid and left
// in place for the caller to set aside.
func (f *JournalFile) Read() ([]Operation, error) {
	if err := ValidateJournalPath(f.path); err != nil {
		return nil, err
	}
	file, err := os.Open(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// Checked on the open file, which is what is read next: a check by name
	// could be answered by one file and the read by another put there since.
	if err := journalTrust(file); err != nil {
		return nil, fmt.Errorf("%w: %s %v", errJournalInvalid, f.path, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJournalBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", errJournalInvalid, f.path, maxJournalBytes)
	}
	var journal Journal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", errJournalInvalid, f.path, err)
	}
	switch journal.Version {
	case JournalVersion, 2:
		// A file written before interfaces were identified has no LUIDs, and
		// recovery replays only its host routes (see recoveryActionLocked).
		// On Windows such a file - written by an earlier release, with the
		// data folder's permissions - has already been refused above by an
		// elevated helper; what it described stays until reboot, and Apply
		// does not trip over a host route it left (withoutRoutesInPlaceLocked).
	default:
		return nil, fmt.Errorf("%w: %s has unsupported version %d", errJournalInvalid, f.path, journal.Version)
	}
	entries := append(journal.Entries, journal.AdapterEntries...)
	if len(entries) > maxJournalEntries {
		return nil, fmt.Errorf("%w: %s lists %d entries", errJournalInvalid, f.path, len(entries))
	}
	for index, entry := range entries {
		if len(entry.Description) > maxDescriptionBytes || entry.Attempts < 0 {
			return nil, fmt.Errorf("%w: entry %d of %s is malformed", errJournalInvalid, index+1, f.path)
		}
		if _, err := parseUndo(entry.Undo); err != nil {
			return nil, fmt.Errorf("%w: entry %d of %s: %v", errJournalInvalid, index+1, f.path, err)
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries, nil
}

// Clear removes the journal. It is called only when nothing is left to undo.
func (f *JournalFile) Clear() error {
	if err := ValidateJournalPath(f.path); err != nil {
		return err
	}
	err := os.Remove(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Reject moves a journal this program did not write out of the way, to
// <name>.rejected-<unix seconds>: nothing in it is run, the next start is not
// blocked by it, and it is still there for anyone who wants to see what it was.
func (f *JournalFile) Reject() (string, error) {
	target := fmt.Sprintf("%s.rejected-%d", f.path, time.Now().Unix())
	if err := os.Rename(f.path, target); err != nil {
		return "", err
	}
	return target, nil
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
