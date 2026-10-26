package tun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// The helper is elevated when TUN is in use, and every folder it looks in for
// wintun.dll is one the user can write to - even the one beside the helper,
// because the portable build runs from a folder it unpacks into %TEMP%.
// Loading whatever DLL sits there would run that code with administrator
// rights. So only the WireGuard build this project ships is loaded: the file is
// opened so nobody can change it, its SHA-256 is compared with the values
// below, and it is loaded from the very file that was checked.

// pinnedWintunVersion is the wintun release the digests belong to. It is the
// release scripts/lib/download-wintun.mjs fetches and
// scripts/lib/wintun-checksums.json pins (as a zip archive; these are the DLLs
// inside that archive).
const pinnedWintunVersion = "0.14.1"

// pinnedWintunSHA256 maps GOARCH to the SHA-256 of bin/<arch>/wintun.dll in
// wintun-0.14.1.zip. Updating wintun means updating these together with the
// checksum file.
var pinnedWintunSHA256 = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
}

// maxWintunBytes bounds what is read while hashing. The real DLLs are a few
// hundred kilobytes.
const maxWintunBytes = 8 << 20

// verifyWintun reads the whole DLL from r and checks it against the build
// pinned for arch.
func verifyWintun(r io.Reader, arch string) error {
	want, ok := pinnedWintunSHA256[arch]
	if !ok {
		return fmt.Errorf("no %s build of %s %s is known to this helper", arch, wintunDLL, pinnedWintunVersion)
	}
	return checkDigest(r, want, arch)
}

func checkDigest(r io.Reader, want string, arch string) error {
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(r, maxWintunBytes+1))
	if err != nil {
		return fmt.Errorf("read it: %w", err)
	}
	if read > maxWintunBytes {
		return fmt.Errorf("it is larger than any %s", wintunDLL)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		return fmt.Errorf("it is not the signed WireGuard %s %s for %s (sha256 %s)", wintunDLL, pinnedWintunVersion, arch, got)
	}
	return nil
}

// maxPathChars is MAX_PATH, in UTF-16 code units.
const maxPathChars = 260

// loadablePath turns what GetFinalPathNameByHandle returns ("\\?\C:\...",
// "\\?\UNC\server\share\...") into an ordinary path when one fits in MAX_PATH,
// and leaves the extended form for the paths that need it.
func loadablePath(final string) string {
	var short string
	switch {
	case strings.HasPrefix(final, `\\?\UNC\`):
		short = `\\` + final[len(`\\?\UNC\`):]
	case strings.HasPrefix(final, `\\?\`):
		short = final[len(`\\?\`):]
	default:
		return final
	}
	if len(utf16.Encode([]rune(short))) >= maxPathChars {
		return final
	}
	return short
}
