//go:build linux

package main

import (
	"fmt"

	"xmonitor/internal/enforce"
)

// cmdSandbox is the hidden launcher used by `xmon run --sandbox` on Linux:
//
//	xmon __sandbox --rw <dir>... -- <command> [args...]
//
// Landlock can only be installed by the process it restricts, so xmon re-execs
// itself here, applies the ruleset, then execs the real command (same PID).
func cmdSandbox(args []string) error {
	var rw []string
	i := 0
	for i < len(args) {
		if args[i] == "--rw" && i+1 < len(args) {
			rw = append(rw, args[i+1])
			i += 2
			continue
		}
		if args[i] == "--" {
			i++
		}
		break
	}
	if i >= len(args) {
		return fmt.Errorf("usage: xmon __sandbox --rw <dir>... -- <command>")
	}
	return enforce.RunSandboxed(rw, args[i:])
}
