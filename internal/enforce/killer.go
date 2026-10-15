package enforce

import (
	"fmt"
	"os"
)

// Killer is the portable kill-after-exec tier: when the L1 probe reports that a
// process in a monitored agent tree executed something the policy denies, the
// process is terminated. It works on already-running agents and on every
// platform, but it is inherently racy (the program runs for a few milliseconds
// before the kill lands), so it complements the managed-mode sandboxes rather
// than replacing them.
type Killer struct {
	// Policy returns the current policy (may change at runtime).
	Policy func() *Policy
	// Kill terminates a pid. nil means os.Process.Kill.
	Kill func(pid int) error
}

// Action describes what the killer did for one exec event.
type Action struct {
	Matched string // the policy entry that matched
	Command string
	PID     int
	Killed  bool
	Err     error
}

// OnExec evaluates one observed exec. inTree must be true only for processes
// verified to belong to a monitored agent tree: the killer never touches
// anything else, since system-wide exec feeds (eslogger) see every process.
func (k *Killer) OnExec(pid int, command string, inTree bool) (Action, bool) {
	if !inTree || pid <= 1 || pid == os.Getpid() {
		return Action{}, false
	}
	p := k.Policy()
	if p == nil {
		return Action{}, false
	}
	entry, ok := p.MatchExec(command)
	if !ok {
		return Action{}, false
	}
	a := Action{Matched: entry, Command: command, PID: pid}
	kill := k.Kill
	if kill == nil {
		kill = defaultKill
	}
	if err := kill(pid); err != nil {
		a.Err = fmt.Errorf("kill %d: %w", pid, err)
	} else {
		a.Killed = true
	}
	return a, true
}

func defaultKill(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
