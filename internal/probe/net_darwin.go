//go:build darwin

package probe

// macOS network backend. ESF (eslogger) has no TCP connect event, so Connect
// events on macOS come from sampling the built-in `nettop` tool instead
// (DESIGN.md §11.2). nettop needs no root and reports per-connection remote
// endpoints, giving us the outbound IP:port cross-verification the exec-only
// eslogger backend cannot. This complements backend_darwin.go, which wires
// startNettop into esloggerBackend.Start. The `send` generic helper is defined
// in backend_darwin.go (same package + build tag) and reused here.

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// startNettop runs `nettop` in continuous CSV logging mode and forwards every
// observed outbound connection to conns until ctx is cancelled. It is
// best-effort: if nettop is missing or exits, it simply returns (eslogger exec
// collection keeps working). Intended to be launched with `go startNettop(...)`.
func startNettop(ctx context.Context, conns chan<- Connect) {
	// -P would collapse to per-process rows and drop the per-connection remote
	// address we need, so it is intentionally omitted. -n keeps addresses
	// numeric (no DNS), -x emits raw values, -L 0 streams CSV samples forever,
	// and -t limits to real wifi/wired links.
	cmd := exec.CommandContext(ctx, "nettop", "-n", "-x", "-L", "0", "-t", "wifi", "-t", "wired")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var curPID int
	var curComm string
	for sc.Scan() {
		parseNettopLine(sc.Text(), &curPID, &curComm, conns)
	}
	_ = cmd.Wait()
}

// parseNettopLine consumes one CSV row of nettop logging output. nettop emits a
// process header row (name column = "comm.pid") followed by one row per live
// connection (name column = "tcp4 local<->remote"). We track the most recent
// process header and attribute each following connection row to it.
func parseNettopLine(line string, curPID *int, curComm *string, conns chan<- Connect) {
	fields := strings.Split(line, ",")
	if len(fields) < 2 {
		return
	}
	// In logging mode the first column is the timestamp and the second is the
	// process/connection name column.
	name := strings.TrimSpace(fields[1])
	if name == "" {
		return
	}

	if i := strings.Index(name, "<->"); i >= 0 {
		// Connection row: "<proto> local<->remote". Drop the protocol prefix.
		endpoints := name
		if sp := strings.IndexByte(endpoints, ' '); sp >= 0 {
			endpoints = endpoints[sp+1:]
		}
		parts := strings.SplitN(endpoints, "<->", 2)
		if len(parts) != 2 {
			return
		}
		ip, port := splitNettopEndpoint(parts[1])
		if ip == "" || *curPID == 0 {
			return
		}
		send(conns, Connect{PID: *curPID, Comm: *curComm, IP: ip, Port: port})
		return
	}

	// Process header row: "comm.pid" (the comm itself may contain dots, so split
	// on the last one).
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		if pid, err := strconv.Atoi(name[dot+1:]); err == nil {
			*curPID = pid
			*curComm = name[:dot]
		}
	}
}

// splitNettopEndpoint splits a nettop remote endpoint into IP and port. nettop
// writes IPv4 as "1.2.3.4:443", bracketed IPv6 as "[::1]:443", and bare IPv6
// with a dot before the port ("2001:db8::1.443").
func splitNettopEndpoint(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "[") {
		if end := strings.IndexByte(addr, ']'); end >= 0 {
			ip := addr[1:end]
			rest := strings.TrimPrefix(addr[end+1:], ":")
			port, _ := strconv.Atoi(rest)
			return ip, port
		}
	}
	// Scan from the right for the separator that precedes an all-digit port.
	for i := len(addr) - 1; i >= 0; i-- {
		if c := addr[i]; c == ':' || c == '.' {
			if port, err := strconv.Atoi(addr[i+1:]); err == nil {
				return addr[:i], port
			}
			break
		}
	}
	return addr, 0
}
