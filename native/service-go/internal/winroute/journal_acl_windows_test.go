//go:build windows

package winroute

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The journal names the transport's server and the LAN gateway: only SYSTEM
// and Administrators may open it, as the user-only data folder it sits in
// would have allowed.
func TestJournalSecurityGrantsOnlyAdministrators(t *testing.T) {
	for _, sddl := range []string{journalSecurity, journalSecurityWithoutOwner} {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("%s: no DACL: %v", sddl, err)
		}
		if dacl.AceCount == 0 {
			t.Fatalf("%s: an empty DACL", sddl)
		}
		for index := uint32(0); index < uint32(dacl.AceCount); index++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, index, &ace); err != nil {
				t.Fatalf("%s: %v", sddl, err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !isAdministrativeSID(sid) {
				t.Fatalf("%s grants %s access to the journal", sddl, sid)
			}
		}
	}
}
