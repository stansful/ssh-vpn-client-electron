//go:build windows

package tun

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// errWintunMissing marks a candidate path with nothing at it.
var errWintunMissing = errors.New("not found")

// finalPathFlags is FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: a drive-letter
// path with every link and junction resolved.
const finalPathFlags = 0

// loadVerifiedWintun loads path only if it is the pinned WireGuard build.
//
// The file is opened sharing read access only, so while the handle is open
// nobody can write to it, replace it or delete it - and NTFS will not rename a
// folder above an open file either. It is hashed through that handle, and then
// loaded by the path the handle resolves to, links and junctions included, so
// a link re-pointed after the check leads nowhere. The handle is closed only
// once the loader has mapped the image.
func loadVerifiedWintun(path string) (*windows.DLL, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, errWintunMissing
	}
	if err != nil {
		return nil, fmt.Errorf("open it: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()

	if kind, err := windows.GetFileType(handle); err != nil || kind != windows.FILE_TYPE_DISK {
		return nil, errors.New("it is not a file")
	}
	if err := verifyWintun(file, runtime.GOARCH); err != nil {
		return nil, err
	}
	final, err := finalPathName(handle)
	if err != nil {
		return nil, fmt.Errorf("resolve where it is: %w", err)
	}
	// Its own imports come from System32 only. The folder it sits in is as
	// writable as the folder it was found in, so a dependency must not be
	// looked up beside it.
	module, err := windows.LoadLibraryEx(final, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("load it: %w", err)
	}
	return &windows.DLL{Name: final, Handle: module}, nil
}

func finalPathName(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), finalPathFlags)
		if err != nil {
			return "", err
		}
		// A buffer that was too small is answered with the size it needs,
		// terminator included; one that fitted, with the length without it.
		if int(length) < len(buffer) {
			return loadablePath(windows.UTF16ToString(buffer[:length])), nil
		}
		buffer = make([]uint16, length+1)
	}
}
