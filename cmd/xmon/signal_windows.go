//go:build windows

package main

import "os"

func signalStop(p *os.Process) error { return p.Kill() }
