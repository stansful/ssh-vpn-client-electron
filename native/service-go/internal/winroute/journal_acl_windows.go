//go:build windows

package winroute

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"shadowssh/service/internal/winnet"
)

// The journal sits in the user's roaming data folder, which every program the
// user runs can write to, and an elevated helper replays it. Files an elevated
// process creates there inherit that folder's permissions, so any of those
// programs could have rewritten one - and every command in it, however
// well-formed, would then run with administrator rights. An elevated helper
// therefore writes the journal owned by Administrators and changeable only by
// them and SYSTEM, and reads only a journal that is still like that. Anybody
// can still delete it or put another file in its place; that file is then not
// theirs to have written as an administrator, and is refused.

// journalSecurity is what an elevated helper creates a journal with: owned by
// Administrators, a protected DACL - nothing inherited from the folder - that
// gives SYSTEM and Administrators full control and nobody else anything. The
// journal names the transport's server and the LAN gateway, and the data
// folder it replaces the permissions of kept those to the user; a read entry
// for anyone else would hand them to every account on the machine that knows
// the path. The app, not elevated, only needs to see that a journal is there,
// and the folder's own listing right already lets it read the attributes.
const journalSecurity = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

// journalSecurityWithoutOwner is the same without asking for the owner, for a
// token that may not assign it; its default owner is then an administrator
// group or SYSTEM, which the check accepts as well.
const journalSecurityWithoutOwner = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// journalWriteRights are the rights that let a holder change what the journal
// says, or who may.
const journalWriteRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// isElevated is a variable so the checks below could be pointed elsewhere in a
// test on Windows; it is the process's own elevation.
var isElevated = winnet.IsElevated

// createJournalFile creates a new journal file exclusively, protected from the
// start when this process is elevated: a protection added after creation would
// leave a moment in which someone else could open the file for writing and
// keep that handle.
func createJournalFile(path string) (*os.File, error) {
	if !isElevated() {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	file, err := createProtectedFile(path, journalSecurity)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		file, err = createProtectedFile(path, journalSecurityWithoutOwner)
	}
	return file, err
}

func createProtectedFile(path string, sddl string) (*os.File, error) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// checkJournalFile refuses, in an elevated helper, a journal that anyone but
// SYSTEM and Administrators could have written: one owned by someone else, or
// one whose DACL lets someone else change it. A helper that is not elevated
// cannot run what the journal says anyway.
func checkJournalFile(file *os.File) error {
	if !isElevated() {
		return nil
	}
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("its permissions could not be read: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("its owner could not be read: %w", err)
	}
	if !isAdministrativeSID(owner) {
		return fmt.Errorf("is owned by %s, not by Administrators, so it was not written by this helper", owner)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("its permissions could not be read: %w", err)
	}
	if dacl == nil {
		return errors.New("lets everyone change it")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("its permissions could not be read: %w", err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("has a permission entry of type %d this helper does not read", ace.Header.AceType)
		}
		if ace.Mask&journalWriteRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !isAdministrativeSID(sid) {
			return fmt.Errorf("lets %s change it", sid)
		}
	}
	return nil
}

func isAdministrativeSID(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid))
}
