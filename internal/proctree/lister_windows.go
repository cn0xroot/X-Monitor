//go:build windows

package proctree

import (
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
)

// WMICLister lists processes on Windows via `tasklist` (CSV). Parent PID and
// full command line need WMI/admin; this best-effort lister covers the
// zero-privilege L3 inventory, with L1 (ETW) supplying the rest.
func WMICLister() ([]Proc, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var procs []Proc
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(row[1]))
		if err != nil {
			continue
		}
		name := row[0]
		procs = append(procs, Proc{PID: pid, Comm: strings.TrimSuffix(name, ".exe"), Exe: name, Cmdline: name})
	}
	return procs, nil
}

// DefaultLister is the platform process lister.
func DefaultLister() Lister { return WMICLister }
