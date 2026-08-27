package tun

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchPathsCoverTheDirectoriesTheHostNames(t *testing.T) {
	// A portable build unpacks into a random temp directory that is created at
	// launch and deleted on exit, so the only folders a user can actually put
	// the DLL in are the ones the host knows about and passes down.
	portable := t.TempDir()
	appData := t.TempDir()
	t.Setenv(SearchDirectoriesEnv, strings.Join([]string{portable, "", appData, portable}, searchDirectoriesSeparator))

	paths := searchPaths()
	if len(paths) != 3 {
		t.Fatalf("expected the binary's own directory plus both named ones, got %v", paths)
	}
	for _, path := range paths {
		if filepath.Base(path) != wintunDLL {
			t.Fatalf("every candidate must name the DLL, got %q", path)
		}
		if !filepath.IsAbs(path) {
			t.Fatalf("every candidate must be absolute so the error can name it, got %q", path)
		}
	}

	// The binary's own directory stays first: a DLL shipped with the build must
	// win over a stray one the user left somewhere else.
	if strings.HasPrefix(paths[0], portable) || strings.HasPrefix(paths[0], appData) {
		t.Fatalf("expected the service binary's own directory first, got %v", paths)
	}
	if paths[1] != filepath.Join(portable, wintunDLL) || paths[2] != filepath.Join(appData, wintunDLL) {
		t.Fatalf("expected the named directories in order, got %v", paths)
	}
}

func TestSearchPathsWithoutTheEnvironmentStillLooksBesideTheBinary(t *testing.T) {
	t.Setenv(SearchDirectoriesEnv, "")
	paths := searchPaths()
	if len(paths) != 1 {
		t.Fatalf("expected only the binary's own directory, got %v", paths)
	}
}
