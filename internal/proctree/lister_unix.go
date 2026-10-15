//go:build !windows

package proctree

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

// PSLister lists processes via `ps`, which is available without privileges on
// Linux and macOS. It avoids a cgo dependency on gopsutil for the core layer.
func PSLister() ([]Proc, error) {
	// -A all processes; -o pid,ppid,comm,args. comm is the short name, args the
	// full command line. Use a wide args field.
	out, err := exec.Command("ps", "-A", "-o", "pid=,ppid=,comm=,args=").Output()
	if err != nil {
		return nil, err
	}
	var procs []Proc
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		comm := fields[2]
		// args is everything after the first three columns; recover it by
		// finding comm's position is fragile, so re-split with known prefix.
		args := ""
		if idx := indexAfterN(line, 3); idx >= 0 {
			args = strings.TrimSpace(line[idx:])
		}
		procs = append(procs, Proc{
			PID: pid, PPID: ppid, Comm: baseComm(comm), Exe: firstToken(args), Cmdline: args,
		})
	}
	return procs, sc.Err()
}

// indexAfterN returns the byte offset in line just past the Nth whitespace-
// delimited field (so the remainder is the args column).
func indexAfterN(line string, n int) int {
	count := 0
	inField := false
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			if inField {
				count++
				inField = false
				if count == n {
					// skip remaining spaces
					for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
						i++
					}
					return i
				}
			}
		} else {
			inField = true
		}
	}
	return -1
}

func baseComm(c string) string {
	if i := strings.LastIndexByte(c, '/'); i >= 0 {
		return c[i+1:]
	}
	return c
}

func firstToken(args string) string {
	if i := strings.IndexByte(args, ' '); i >= 0 {
		return args[:i]
	}
	return args
}

// DefaultLister is the platform process lister.
func DefaultLister() Lister { return PSLister }
