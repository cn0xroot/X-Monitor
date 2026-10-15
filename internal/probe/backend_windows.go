//go:build windows

// Windows L1 backend (DESIGN.md §11.3). Rather than linking a real ETW library
// (an extra dependency that is impossible to test off-Windows), this reads
// Sysmon's event log via a `powershell` subprocess: Get-WinEvent on
// Microsoft-Windows-Sysmon/Operational, Event ID 1 = process create (exec) and
// Event ID 3 = network connect. It polls for new events every few seconds,
// advancing a timestamp watermark so each event is reported once. When Sysmon
// is not installed the backend reports unavailable; like the other backends it
// audits and cross-verifies only.

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// pollInterval is how often we query Sysmon for new events.
const pollInterval = 2 * time.Second

// New returns the Windows backend (Sysmon via powershell).
func New() Backend { return &sysmonBackend{} }

type sysmonBackend struct{}

func (b *sysmonBackend) Name() string { return "sysmon" }

func (b *sysmonBackend) Available() (bool, string) {
	if _, err := exec.LookPath("powershell"); err != nil {
		return false, "powershell not found"
	}
	if !isAdmin() {
		return false, "needs administrator privilege"
	}
	if !sysmonLogPresent() {
		return false, "needs Sysmon installed (Microsoft-Windows-Sysmon/Operational)"
	}
	return true, ""
}

func (b *sysmonBackend) Start(ctx context.Context, execs chan<- Exec, conns chan<- Connect) error {
	// Start just below "now" so the first poll only sees fresh events.
	watermark := time.Now().Add(-pollInterval)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		queryStart := time.Now()
		if out, err := queryEvents(ctx, watermark); err == nil {
			parseSysmonEvents(out, execs, conns)
		}
		// Advance the watermark regardless of query success to avoid an
		// ever-growing window; a transient failure drops at most one interval.
		watermark = queryStart

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// queryEvents pulls Sysmon exec/connect events newer than since, as JSON.
func queryEvents(ctx context.Context, since time.Time) ([]byte, error) {
	script := fmt.Sprintf(
		"$ErrorActionPreference='SilentlyContinue';"+
			"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3; StartTime=[datetime]'%s'} |"+
			" Sort-Object TimeCreated |"+
			" Select-Object Id,Message |"+
			" ConvertTo-Json -Depth 3 -Compress",
		since.Format("2006-01-02T15:04:05.000"),
	)
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Output()
}

// sysmonEvent is one Get-WinEvent record projected to Id + Message.
type sysmonEvent struct {
	ID      int    `json:"Id"`
	Message string `json:"Message"`
}

// parseSysmonEvents decodes ConvertTo-Json output (which is a single object when
// there is exactly one event, otherwise an array) and dispatches each event.
func parseSysmonEvents(out []byte, execs chan<- Exec, conns chan<- Connect) {
	out = []byte(strings.TrimSpace(string(out)))
	if len(out) == 0 {
		return
	}
	var events []sysmonEvent
	if out[0] == '[' {
		if json.Unmarshal(out, &events) != nil {
			return
		}
	} else {
		var one sysmonEvent
		if json.Unmarshal(out, &one) != nil {
			return
		}
		events = []sysmonEvent{one}
	}
	for _, ev := range events {
		switch ev.ID {
		case 1:
			emitSysmonExec(ev.Message, execs)
		case 3:
			emitSysmonConnect(ev.Message, conns)
		}
	}
}

// parseSysmonMessage turns a Sysmon message body ("Key: Value" per line) into a
// map keyed by field name.
func parseSysmonMessage(msg string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ':'); i > 0 {
			key := strings.TrimSpace(line[:i])
			val := strings.TrimSpace(line[i+1:])
			if key != "" {
				fields[key] = val
			}
		}
	}
	return fields
}

func emitSysmonExec(msg string, execs chan<- Exec) {
	f := parseSysmonMessage(msg)
	pid, _ := strconv.Atoi(f["ProcessId"])
	ppid, _ := strconv.Atoi(f["ParentProcessId"])
	image := f["Image"]
	if image == "" {
		return
	}
	command := f["CommandLine"]
	if command == "" {
		command = image
	}
	send(execs, Exec{PID: pid, PPID: ppid, Comm: baseName(image), Command: command})
}

func emitSysmonConnect(msg string, conns chan<- Connect) {
	f := parseSysmonMessage(msg)
	ip := f["DestinationIp"]
	if ip == "" {
		return
	}
	pid, _ := strconv.Atoi(f["ProcessId"])
	port, _ := strconv.Atoi(f["DestinationPort"])
	send(conns, Connect{PID: pid, Comm: baseName(f["Image"]), IP: ip, Port: port})
}

// baseName returns the final path component of a Windows path.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// sysmonLogPresent reports whether the Sysmon operational log exists.
func sysmonLogPresent() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational -ErrorAction Stop | Out-Null")
	return cmd.Run() == nil
}

// isAdmin reports whether the process holds administrator privileges. Opening a
// raw physical drive handle succeeds only for elevated processes, which avoids
// pulling in golang.org/x/sys/windows just for the token check.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// send is the non-blocking channel helper (mirrors the Linux/macOS backends;
// those build-tagged files are not compiled on Windows, so it is defined here).
func send[T any](ch chan<- T, v T) {
	select {
	case ch <- v:
	default:
	}
}
