//go:build !windows

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// procInfo returns (comm, exe, argv) for a pid via ps. On macOS, comm for an
// app bundle is the executable name; argv includes the full path, which carries
// the ".app/Contents/..." fragment used to match GUI clients.
func procInfo(pid int) (comm, exe, argv string) {
	out, err := exec.Command("ps", "-o", "comm=,args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", "", ""
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", "", ""
	}
	// comm is the first whitespace field; args is the rest (the full path+argv).
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", ""
	}
	exe = fields[0]
	comm = exe
	if i := strings.LastIndexByte(comm, '/'); i >= 0 {
		comm = comm[i+1:]
	}
	argv = line
	return comm, exe, argv
}
