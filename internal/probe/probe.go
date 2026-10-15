// Package probe is the L1 system-layer collector (DESIGN.md §11). L1 is an
// optional enhancement: it observes real execve/connect on the agent process
// tree to cross-verify the application layer. This implementation uses
// subprocess backends (bpftrace on Linux, eslogger on macOS) so it builds
// everywhere with no cgo/eBPF toolchain; each backend degrades to "unavailable"
// when its tool or privilege is missing. Kernel-level enforcement (BPF-LSM,
// ESF AUTH) is future work; today L1 audits and cross-verifies only.
package probe

import (
	"context"
)

// Exec is one observed process execution.
type Exec struct {
	PID     int
	PPID    int
	Comm    string
	Command string // argv / filename
}

// Connect is one observed outbound network connection.
type Connect struct {
	PID  int
	Comm string
	IP   string
	Port int
	Host string // DNS name captured at getaddrinfo time, when available
}

// Backend is a platform collector.
type Backend interface {
	// Name identifies the backend (bpftrace / eslogger / none).
	Name() string
	// Available reports whether it can run here (tool present + privilege).
	Available() (bool, string)
	// Start begins collection; events arrive on the channels until ctx ends.
	Start(ctx context.Context, execs chan<- Exec, conns chan<- Connect) error
}

// Caps describes what the active backend can do.
type Caps struct {
	Backend string `json:"backend"`
	Exec    bool   `json:"exec"`
	Connect bool   `json:"connect"`
	Reason  string `json:"reason,omitempty"`
}
