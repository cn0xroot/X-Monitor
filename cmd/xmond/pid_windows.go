//go:build windows

package main

// parentPID is a stub on Windows; L3 proctree will supply this later.
func parentPID(pid int) int { return 0 }

// pidAlive is optimistic on Windows; the ES client that consumes the roots file
// is macOS-only.
func pidAlive(pid int) bool { return true }
