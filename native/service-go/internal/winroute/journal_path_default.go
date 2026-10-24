//go:build !windows

package winroute

import "path/filepath"

// finalDirectory is where directory really is, every symbolic link on the way
// followed.
func finalDirectory(directory string) (string, error) {
	return filepath.EvalSymlinks(directory)
}
