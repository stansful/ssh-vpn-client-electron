//go:build !windows

package winroute

import "os"

// createJournalFile creates a new journal file exclusively. Off Windows no
// helper runs elevated, so there is nothing to keep anyone out of.
func createJournalFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// checkJournalFile accepts every journal off Windows.
func checkJournalFile(*os.File) error {
	return nil
}
