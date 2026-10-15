//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// parentPID returns the parent PID via `ps` (portable across Linux and macOS).
func parentPID(pid int) int {
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	ppid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return ppid
}

// pidAlive reports whether a process with this pid currently exists.
func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil || errors.Is(syscall.Kill(pid, 0), syscall.EPERM)
}
