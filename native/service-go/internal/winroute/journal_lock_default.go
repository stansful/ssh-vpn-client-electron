//go:build !windows

package winroute

import (
	"errors"
	"os"
	"syscall"
)

// openJournalLockFile opens the lock file, creating it when missing, without
// following a link at its name. Off Windows it exists so the locking can be
// tested; no helper runs a dataplane here.
func openJournalLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
}

// tryLockFile takes an exclusive lock without waiting. flock locks belong to
// the open file, so a second manager in this process is kept out as surely as
// another process is.
func tryLockFile(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
