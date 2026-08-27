package tun

import (
	"os"
	"path/filepath"
	"strings"
)

// The portable build unpacks itself into a fresh `%TEMP%\<random>` directory on
// every launch and deletes it on exit, so the directory the DLL loader searches
// first cannot be written to by hand - it does not exist until the app starts
// and is gone before the user can look at it. A build that shipped without the
// DLL therefore had no way to gain it, and the honest diagnostic only proved
// the folder was unreachable.
//
// So the search is widened to the places a person can actually put a file: the
// folder holding the portable executable, the application data folder, anywhere
// the host names explicitly. The host passes them in this variable because only
// it knows where it was started from.
const SearchDirectoriesEnv = "SHADOW_SSH_WINTUN_DIRS"

// wintunDLL is the file every candidate directory is checked for.
const wintunDLL = "wintun.dll"

// searchDirectoriesSeparator matches the host's join character. `;` cannot
// appear in a Windows path, so a plain split is unambiguous.
const searchDirectoriesSeparator = ";"

// searchPaths lists the absolute candidate paths for the DLL, most specific
// first: beside the service binary, then each directory the host named.
func searchPaths() []string {
	var paths []string
	seen := make(map[string]struct{})
	add := func(directory string) {
		directory = strings.TrimSpace(directory)
		if directory == "" {
			return
		}
		candidate := filepath.Join(directory, wintunDLL)
		key := strings.ToLower(candidate)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		paths = append(paths, candidate)
	}

	if executable, err := os.Executable(); err == nil {
		add(filepath.Dir(executable))
	}
	for _, directory := range strings.Split(os.Getenv(SearchDirectoriesEnv), searchDirectoriesSeparator) {
		add(directory)
	}
	return paths
}
