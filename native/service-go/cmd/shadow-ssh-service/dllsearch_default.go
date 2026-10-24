//go:build !windows

package main

// restrictDLLSearch has nothing to restrict off Windows.
func restrictDLLSearch() error { return nil }
