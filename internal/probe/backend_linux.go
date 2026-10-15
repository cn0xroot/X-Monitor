//go:build linux

package probe

import (
	"bufio"
	"context"
	_ "embed"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

//go:embed scripts/probe_linux.bt
var bpfScript string

// New returns the Linux backend (bpftrace).
func New() Backend { return &bpftraceBackend{} }

type bpftraceBackend struct{}

func (b *bpftraceBackend) Name() string { return "bpftrace" }

func (b *bpftraceBackend) Available() (bool, string) {
	if _, err := exec.LookPath("bpftrace"); err != nil {
		return false, "bpftrace not installed"
	}
	if os.Geteuid() != 0 {
		return false, "needs root (CAP_BPF/CAP_PERFMON)"
	}
	return true, ""
}

func (b *bpftraceBackend) Start(ctx context.Context, execs chan<- Exec, conns chan<- Connect) error {
	f, err := os.CreateTemp("", "xmon-probe-*.bt")
	if err != nil {
		return err
	}
	_, _ = f.WriteString(bpfScript)
	_ = f.Close()
	defer os.Remove(f.Name())

	cmd := exec.CommandContext(ctx, "bpftrace", f.Name())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			parseLine(sc.Text(), execs, conns)
		}
	}()
	return cmd.Wait()
}

func parseLine(line string, execs chan<- Exec, conns chan<- Connect) {
	parts := strings.Split(line, "\t")
	switch parts[0] {
	case "EXEC":
		if len(parts) >= 5 {
			pid, _ := strconv.Atoi(parts[1])
			ppid, _ := strconv.Atoi(parts[2])
			send(execs, Exec{PID: pid, PPID: ppid, Comm: parts[3], Command: strings.Join(parts[4:], "\t")})
		}
	case "CONNECT":
		if len(parts) >= 5 {
			pid, _ := strconv.Atoi(parts[1])
			port, _ := strconv.Atoi(parts[4])
			host := ""
			if len(parts) >= 6 {
				host = parts[5]
			}
			send(conns, Connect{PID: pid, Comm: parts[2], IP: parts[3], Port: port, Host: host})
		}
	}
}

func send[T any](ch chan<- T, v T) {
	select {
	case ch <- v:
	default:
	}
}
