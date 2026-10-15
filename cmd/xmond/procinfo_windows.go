//go:build windows

package main

// procInfo is a stub on Windows; GUI identification there uses ETW/WMI in the
// L1 probe. The proxy resolver falls back to host-based identification.
func procInfo(pid int) (comm, exe, argv string) { return "", "", "" }
