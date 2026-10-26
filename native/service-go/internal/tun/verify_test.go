package tun

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOnlyThePinnedWintunBuildIsAccepted(t *testing.T) {
	genuine := []byte("MZ stand-in for the vendor's DLL")
	sum := sha256.Sum256(genuine)
	want := hex.EncodeToString(sum[:])

	if err := checkDigest(bytes.NewReader(genuine), want, "amd64"); err != nil {
		t.Fatalf("the pinned build was refused: %v", err)
	}
	planted := append([]byte(nil), genuine...)
	planted[len(planted)-1] ^= 1
	err := checkDigest(bytes.NewReader(planted), want, "amd64")
	if err == nil || !strings.Contains(err.Error(), "not the signed WireGuard") {
		t.Fatalf("a modified DLL was accepted or misreported: %v", err)
	}
	huge := bytes.NewReader(make([]byte, maxWintunBytes+1))
	if err := checkDigest(huge, want, "amd64"); err == nil {
		t.Fatal("a file larger than any wintun.dll was accepted")
	}
	// An architecture with no pinned build loads nothing.
	if err := verifyWintun(bytes.NewReader(genuine), "386"); err == nil {
		t.Fatal("a DLL for an architecture without a pinned digest was accepted")
	}
}

func TestPinnedWintunDigestsCoverTheShippedArchitectures(t *testing.T) {
	digest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, arch := range []string{"amd64", "arm64"} {
		if !digest.MatchString(pinnedWintunSHA256[arch]) {
			t.Fatalf("no well-formed digest pinned for %s: %q", arch, pinnedWintunSHA256[arch])
		}
	}
}

func TestPinnedWintunVersionIsTheOneTheBuildFetches(t *testing.T) {
	// Bumping wintun in the download script without updating the pinned DLL
	// digests here would ship a helper that refuses its own DLL.
	root := filepath.Join("..", "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "lib", "wintun-checksums.json"))
	if err != nil {
		t.Skipf("checksum file unavailable: %v", err)
	}
	var checksums struct {
		Archives map[string]string `json:"archives"`
	}
	if err := json.Unmarshal(raw, &checksums); err != nil {
		t.Fatalf("parse checksum file: %v", err)
	}
	if checksums.Archives[pinnedWintunVersion] == "" {
		t.Fatalf("scripts/lib/wintun-checksums.json does not pin wintun %s", pinnedWintunVersion)
	}
	script, err := os.ReadFile(filepath.Join(root, "scripts", "lib", "download-wintun.mjs"))
	if err != nil {
		t.Fatalf("read download script: %v", err)
	}
	if !strings.Contains(string(script), `const defaultVersion = "`+pinnedWintunVersion+`";`) {
		t.Fatalf("scripts/lib/download-wintun.mjs no longer fetches wintun %s; update pinnedWintunSHA256 with the new DLLs", pinnedWintunVersion)
	}
}

func TestPinnedWintunDigestsMatchTheFetchedDLLs(t *testing.T) {
	// `npm run wintun:download` installs the vendor's DLLs here; they are not
	// committed, so the check runs wherever they have been fetched.
	checked := 0
	for directory, arch := range map[string]string{"x64": "amd64", "arm64": "arm64"} {
		path := filepath.Join("..", "..", "..", "windows", directory, wintunDLL)
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		err = verifyWintun(file, arch)
		file.Close()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("wintun.dll has not been fetched (npm run wintun:download)")
	}
}

func TestLoadablePathDropsTheExtendedPrefixWhenItCan(t *testing.T) {
	long := `\\?\C:\` + strings.Repeat("a", maxPathChars) + `\wintun.dll`
	cases := map[string]string{
		`\\?\C:\Users\me\AppData\Roaming\Shadow SSH\wintun.dll`: `C:\Users\me\AppData\Roaming\Shadow SSH\wintun.dll`,
		`\\?\UNC\server\share\wintun.dll`:                       `\\server\share\wintun.dll`,
		`C:\already\plain\wintun.dll`:                           `C:\already\plain\wintun.dll`,
		long:                                                    long,
	}
	for final, want := range cases {
		if got := loadablePath(final); got != want {
			t.Fatalf("loadablePath(%q) = %q, want %q", final, got, want)
		}
	}
}
