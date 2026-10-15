// Package proctree is the L3 process-tree tracker (DESIGN.md §9). It is
// zero-privilege and cross-platform: it polls the process table, identifies AI
// agent roots, and propagates the mark to descendants so child processes are
// attributed to their agent/session. Its job is attribution and long-lived
// process inventory — not exec-level security audit (that's L1).
package proctree

import (
	"context"
	"os"
	"sort"
	"sync"
	"time"

	"xmonitor/internal/agents"
	"xmonitor/internal/event"
)

// Proc is a snapshot of one process.
type Proc struct {
	PID     int
	PPID    int
	Comm    string
	Exe     string
	Cmdline string
	Start   time.Time
}

// Lister returns the current process table.
type Lister func() ([]Proc, error)

// Tracked is a process known to belong to a monitored agent tree.
type Tracked struct {
	PID     int
	RootPID int
	Agent   string
	Session string
}

// Tracker maintains the agent process forest.
type Tracker struct {
	list     Lister
	interval time.Duration

	mu      sync.RWMutex
	tracked map[int]*Tracked   // pid -> tracking info
	roots   map[int]*Tracked   // rootPID -> info (from xmon run)
	known   map[int]Proc       // last snapshot
	self    int                // this daemon's pid: it and its whole subtree are never tracked
	onExec  func(*event.Event) // new descendant observed
	onAgent func(a, session string, pid int, already bool)
}

// New creates a tracker.
func New(list Lister, interval time.Duration) *Tracker {
	if interval <= 0 {
		interval = time.Second
	}
	return &Tracker{
		list: list, interval: interval,
		tracked: map[int]*Tracked{}, roots: map[int]*Tracked{}, known: map[int]Proc{},
		self: os.Getpid(),
	}
}

// OnExec sets the callback for a newly observed descendant process.
func (t *Tracker) OnExec(fn func(*event.Event)) { t.onExec = fn }

// OnAgentSpawn sets the callback for a newly discovered agent root. already is
// true for agents that were running before the daemon's first scan.
func (t *Tracker) OnAgentSpawn(fn func(agent, session string, pid int, already bool)) { t.onAgent = fn }

// Register binds a known root PID (from `xmon run`) to an agent/session.
func (t *Tracker) Register(rootPID int, agent, session string) {
	t.mu.Lock()
	info := &Tracked{PID: rootPID, RootPID: rootPID, Agent: agent, Session: session}
	t.roots[rootPID] = info
	t.tracked[rootPID] = info
	t.mu.Unlock()
}

// Lookup returns tracking info for a pid, walking cached parents.
func (t *Tracker) Lookup(pid int) (*Tracked, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.tracked[pid]
	return info, ok
}

// Start runs the polling loop until ctx is cancelled.
func (t *Tracker) Start(ctx context.Context) {
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		procs, err := t.list()
		if err != nil {
			continue
		}
		t.scan(procs, first)
		first = false
	}
}

func (t *Tracker) scan(procs []Proc, first bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cur := make(map[int]Proc, len(procs))
	byPID := make(map[int]Proc, len(procs))
	for _, p := range procs {
		cur[p.PID] = p
		byPID[p.PID] = p
	}

	// The monitor must not monitor itself: the daemon can be started from inside
	// an agent's shell, which would otherwise attribute its own once-a-second
	// `ps` poll (and everything else it spawns) to that agent.
	own := map[int]bool{t.self: true}
	for changed := true; changed; {
		changed = false
		for _, p := range procs {
			if !own[p.PID] && own[p.PPID] {
				own[p.PID] = true
				changed = true
			}
		}
	}

	// An agent's own helper (opencode runs `opencode.exe serve` under `opencode`)
	// matches the same signature; it belongs to its parent's tree, not a new root.
	matched := map[int]string{}
	for _, p := range procs {
		if !own[p.PID] {
			if a := agents.Match(p.Comm, p.Exe, p.Cmdline); a != nil {
				matched[p.PID] = a.ID
			}
		}
	}
	for _, p := range procs {
		if own[p.PID] {
			continue
		}
		id, ok := matched[p.PID]
		if !ok {
			continue
		}
		if _, tracked := t.tracked[p.PID]; tracked {
			continue
		}
		if parent, ok := t.tracked[p.PPID]; ok && parent.Agent == id {
			continue // propagation below attaches it to the parent's tree
		}
		if matched[p.PPID] == id {
			continue
		}
		info := &Tracked{PID: p.PID, RootPID: p.PID, Agent: id}
		t.tracked[p.PID] = info
		t.roots[p.PID] = info
		if t.onAgent != nil {
			t.onAgent(id, "", p.PID, first)
		}
	}

	// Propagate marks down the tree: repeat until stable (parents before kids
	// isn't guaranteed by PID order).
	for changed := true; changed; {
		changed = false
		for _, p := range procs {
			if own[p.PID] {
				continue
			}
			if _, ok := t.tracked[p.PID]; ok {
				continue
			}
			if parent, ok := t.tracked[p.PPID]; ok {
				info := &Tracked{PID: p.PID, RootPID: parent.RootPID, Agent: parent.Agent, Session: parent.Session}
				t.tracked[p.PID] = info
				changed = true
				if !first && t.onExec != nil {
					t.onExec(t.execEvent(p, info))
				}
			}
		}
	}

	// Prune dead PIDs.
	for pid := range t.tracked {
		if _, ok := cur[pid]; !ok {
			delete(t.tracked, pid)
			delete(t.roots, pid)
		}
	}
	t.known = byPID
}

// Running describes one agent process tree found on the host.
type Running struct {
	Agent    string `json:"agent"`
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	Cmdline  string `json:"cmdline"`
	Managed  bool   `json:"managed"` // started through `xmon run` (has a session)
	Session  string `json:"session,omitempty"`
	Children int    `json:"children"`
}

// Snapshot lists the agent roots currently alive, with the size of their trees.
func (t *Tracker) Snapshot() []Running {
	t.mu.RLock()
	defer t.mu.RUnlock()
	kids := map[int]int{}
	for pid, info := range t.tracked {
		if pid != info.RootPID {
			kids[info.RootPID]++
		}
	}
	out := []Running{}
	for pid, info := range t.roots {
		p := t.known[pid]
		out = append(out, Running{Agent: info.Agent, PID: pid, Comm: shortComm(p), Cmdline: clip(p.Cmdline, 200),
			Managed: info.Session != "", Session: info.Session, Children: kids[pid]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (t *Tracker) execEvent(p Proc, info *Tracked) *event.Event {
	return &event.Event{
		Layer: event.LayerL3, Kind: event.KindIntent, Type: "proc_spawn",
		Agent: info.Agent, Session: info.Session, PID: p.PID,
		Risk:  event.RiskInfo,
		Title: "Agent 进程树新进程",
		Fields: map[string]any{
			"comm": shortComm(p), "ppid": p.PPID, "root_pid": info.RootPID, "exe": p.Exe, "cmdline": clip(p.Cmdline, 400),
		},
	}
}

func shortComm(p Proc) string {
	if p.Comm != "" {
		return p.Comm
	}
	return p.Exe
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
