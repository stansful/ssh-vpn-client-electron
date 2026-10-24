//go:build windows

package winroute

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// The flags GetFinalPathNameByHandle is asked with: a normalised name on a
// drive letter (FILE_NAME_NORMALIZED | VOLUME_NAME_DOS, both zero).
const finalPathFlags = 0

// finalDirectory is where directory really is, every junction and symbolic
// link on the way followed - which filepath.EvalSymlinks no longer does for
// junctions. It is read from an open handle, so it names the folder Windows
// opened, not one a name lookup could be talked into.
func finalDirectory(directory string) (string, error) {
	name, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), finalPathFlags)
	if err != nil {
		return "", err
	}
	if int(length) >= len(buffer) {
		return "", errors.New("the folder's final path is too long")
	}
	final := windows.UTF16ToString(buffer[:length])
	switch {
	case strings.HasPrefix(final, `\\?\UNC\`):
		final = `\\` + final[len(`\\?\UNC\`):]
	case strings.HasPrefix(final, `\\?\`):
		final = final[len(`\\?\`):]
	}
	return filepath.Clean(final), nil
}
