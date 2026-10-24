package winroute

import (
	"errors"
	"os"
	"time"
)

// Every helper process shares one journal: the one an app start runs to
// recover what a killed helper left behind, and the one each transport runs
// its dataplane in. Each keeps its own manager, so nothing in memory stops two
// of them from undoing the same changes at once, or a recovery that finishes
// late from clearing the journal a dataplane has just written - or, starting
// late, from taking that dataplane's live routes for leftovers and deleting
// them. A lock on a file beside the journal is what they agree on: held while
// a manager recovers the journal and for as long as it has a plan applied.
// The operating system releases it when the process holding it dies, which is
// exactly when its routes become leftovers.

// ErrJournalInUse reports that another helper kept the journal for longer
// than this one would wait.
var ErrJournalInUse = errors.New("the routing journal is in use by another helper")

const (
	// journalLockSuffix names the lock file beside the journal.
	journalLockSuffix = ".lock"
	// journalLockWait is how long a dataplane start waits for another helper
	// to finish with the journal: a recovery that runs its full rollback
	// budget, and a little more.
	journalLockWait = rollbackBudget + 30*time.Second
	// journalLockPoll is how often a waiting helper tries again.
	journalLockPoll = 100 * time.Millisecond
)

// journalLock is a held lock on a journal.
type journalLock struct {
	file *os.File
}

// lockJournal takes the lock of the journal at journalPath, trying until wait
// has passed; a zero wait tries once. It fails with ErrJournalInUse when
// another helper holds the lock throughout, and with another error when the
// lock file cannot be used at all.
func lockJournal(journalPath string, wait time.Duration) (*journalLock, error) {
	file, err := openJournalLockFile(journalPath + journalLockSuffix)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		locked, err := tryLockFile(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		if locked {
			return &journalLock{file: file}, nil
		}
		if !time.Now().Before(deadline) {
			file.Close()
			return nil, ErrJournalInUse
		}
		time.Sleep(journalLockPoll)
	}
}

func (l *journalLock) release() {
	unlockFile(l.file)
	l.file.Close()
}
