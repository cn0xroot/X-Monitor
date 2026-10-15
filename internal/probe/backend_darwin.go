//go:build darwin

package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// New returns the macOS backend. During the transition phase this uses
// `eslogger` (macOS 13+, root, no entitlement) for exec events; the signed ES
// system extension and NetworkExtension are future work (DESIGN.md §11.2).
func New() Backend { return &esloggerBackend{} }

type esloggerBackend struct{}

func (b *esloggerBackend) Name() string { return "eslogger" }

func (b *esloggerBackend) Available() (bool, string) {
	if _, err := exec.LookPath("eslogger"); err != nil {
		return false, "eslogger not available (needs macOS 13+)"
	}
	if os.Geteuid() != 0 {
		return false, "needs root and Full Disk Access"
	}
	return true, ""
}

func (b *esloggerBackend) Start(ctx context.Context, execs chan<- Exec, conns chan<- Connect) error {
	// eslogger streams NDJSON ES events. We subscribe to exec only; ESF has no
	// TCP connect event, so network cross-verification on macOS relies on
	// nettop/NetworkExtension elsewhere.
	cmd := exec.CommandContext(ctx, "eslogger", "exec")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// ESF has no TCP connect event, so Connect events come from sampling nettop
	// (see net_darwin.go) alongside eslogger exec collection.
	go startNettop(ctx, conns)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 256*1024), 8<<20)
		for sc.Scan() {
			parseESLine(sc.Bytes(), execs)
		}
	}()
	return cmd.Wait()
}

func parseESLine(b []byte, execs chan<- Exec) {
	var m struct {
		Process struct {
			AuditToken struct {
				PID int `json:"pid"`
			} `json:"audit_token"`
			PPID       int `json:"ppid"`
			Executable struct {
				Path string `json:"path"`
			} `json:"executable"`
		} `json:"process"`
		Event struct {
			Exec struct {
				Target struct {
					Executable struct {
						Path string `json:"path"`
					} `json:"executable"`
				} `json:"target"`
			} `json:"exec"`
		} `json:"event"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	path := m.Event.Exec.Target.Executable.Path
	if path == "" {
		path = m.Process.Executable.Path
	}
	if path == "" {
		return
	}
	comm := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		comm = path[i+1:]
	}
	send(execs, Exec{PID: m.Process.AuditToken.PID, PPID: m.Process.PPID, Comm: comm, Command: path})
}

func send[T any](ch chan<- T, v T) {
	select {
	case ch <- v:
	default:
	}
}
