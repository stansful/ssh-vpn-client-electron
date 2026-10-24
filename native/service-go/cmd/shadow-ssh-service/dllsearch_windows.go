//go:build windows

package main

import "golang.org/x/sys/windows"

// restrictDLLSearch makes every library this process loads by name come from
// System32. The helper runs elevated from a folder the user can write to - the
// portable build unpacks into %TEMP% - and a bare-name load, including the
// ones wintun.dll delay-loads on first use, would otherwise look in that folder
// first. wintun.dll itself is loaded by absolute path after verification.
func restrictDLLSearch() error {
	return windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
}
