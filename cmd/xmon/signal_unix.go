//go:build !windows

package main

import (
	"os"
	"syscall"
)

func signalStop(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
