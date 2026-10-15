// Package sessionview builds the dashboard's session list: every AI agent
// X-Monitor can see, whether it was launched through `xmon run`, was found
// running on the host, or was imported from CC-Monitor, each with a heartbeat.
//
// The heartbeat idea is CC-Monitor's (MIT License, see NOTICE): a session is
// "working" while it produced activity in the last few minutes, "idle" when its
// process is alive but quiet, "blocked" while it waits for a human approval,
// and "dead" once the process is gone. It is agent-agnostic: activity is
// whatever X-Monitor recorded for that agent, not anything Claude-specific.
package sessionview

import (
	"sort"
	"strconv"
	"time"

	"xmonitor/internal/store"
)

// WorkingWindow: activity newer than this counts as "working". Tool calls are
// sparse (a model thinking or a human reading can take minutes), so this is
// deliberately generous.
const WorkingWindow = 5 * time.Minute

// startGrace: a session registered moments ago may not be in the process
// scan yet; don't call it dead.
const startGrace = 10 * time.Second

// Statuses.
const (
	Working = "working"
	Idle    = "idle"
	Blocked = "blocked"
	Dead    = "dead"
)

// Kinds.
const (
	KindManaged  = "managed"  // started through `xmon run`
	KindProcess  = "process"  // found running on the host, not managed
	KindHook     = "hook"     // reported by a native hook (xmon-hook / OpenCode plugin) without xmon run
	KindImported = "imported" // read from CC-Monitor's database
)

// Live is an agent process tree currently alive on the host.
type Live struct {
	Agent    string
	PID      int
	Comm     string
	Cmdline  string
	Children int
}

// Row is one line of the session list.
type Row struct {
	ID        string `json:"id"`
	Agent     string `json:"agent"`
	Kind      string `json:"kind"`
	CWD       string `json:"cwd,omitempty"`
	RootPID   int    `json:"root_pid,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	StartedAt int64  `json:"started_at,omitempty"`
	EndedAt   int64  `json:"ended_at,omitempty"`
	Alive     bool   `json:"alive"`
	Status    string `json:"status"`
	AgoMs     *int64 `json:"ago_ms"` // since the last activity; null = never seen active
	LastTS    int64  `json:"last_ts,omitempty"`
	Events    int    `json:"events"`
	Blocked   int    `json:"blocked"`
	Pending   int    `json:"pending"`
	Children  int    `json:"children,omitempty"`
	Branch    string `json:"branch,omitempty"` // filled in by the server (needs the file system)
}

// Input is everything Build needs; it does no I/O.
type Input struct {
	Sessions []*store.Session
	Stats    map[string]store.ActivityStat // by session id
	Agents   map[string]store.ActivityStat // by agent, events with no session (unmanaged / system layers)
	Pending  map[string]int                // pending approvals by session id
	Live     []Live
	Now      time.Time
}

func status(alive bool, pending int, ago *int64) string {
	switch {
	case !alive:
		return Dead
	case pending > 0:
		return Blocked
	case ago != nil && time.Duration(*ago)*time.Millisecond < WorkingWindow:
		return Working
	}
	return Idle
}

func agoOf(now time.Time, last int64) *int64 {
	if last <= 0 {
		return nil
	}
	d := now.UnixMilli() - last
	if d < 0 {
		d = 0
	}
	return &d
}

// Build assembles the rows: live ones first (blocked, working, idle), then by recency.
func Build(in Input) []Row {
	livePID := map[int]Live{}
	for _, l := range in.Live {
		livePID[l.PID] = l
	}
	managedPID := map[int]bool{}
	seen := map[string]bool{}
	var rows []Row

	for _, s := range in.Sessions {
		seen[s.ID] = true
		st := in.Stats[s.ID]
		l, running := livePID[s.RootPID]
		alive := s.EndedAt == 0 && (running || (s.RootPID == 0 && in.Now.UnixMilli()-s.StartedAt < 60_000) ||
			in.Now.Sub(time.UnixMilli(s.StartedAt)) < startGrace)
		if s.RootPID > 0 {
			managedPID[s.RootPID] = true
		}
		last := st.LastTS
		if last == 0 {
			last = s.StartedAt // a session that just started has been "active" since then
		}
		ago := agoOf(in.Now, last)
		pend := in.Pending[s.ID]
		rows = append(rows, Row{ID: s.ID, Agent: s.Agent, Kind: KindManaged, CWD: s.CWD, RootPID: s.RootPID,
			StartedAt: s.StartedAt, EndedAt: s.EndedAt, Alive: alive, Status: status(alive, pend, ago), AgoMs: ago,
			LastTS: last, Events: st.Events, Blocked: st.Blocked, Pending: pend, Children: l.Children})
	}

	// Agents running on the host that X-Monitor did not start.
	for _, l := range in.Live {
		if managedPID[l.PID] {
			continue
		}
		st := in.Agents[l.Agent]
		ago := agoOf(in.Now, st.LastTS)
		rows = append(rows, Row{ID: "proc:" + strconv.Itoa(l.PID), Agent: l.Agent, Kind: KindProcess, RootPID: l.PID,
			Cmdline: l.Cmdline, Alive: true, Status: status(true, 0, ago), AgoMs: ago, LastTS: st.LastTS,
			Events: st.Events, Blocked: st.Blocked, Children: l.Children})
	}

	// Sessions that only exist as events. Imported ones (CC-Monitor) are history.
	// A hook-reported session has no process id to check, so it counts as alive
	// while the agent has a live process on the host or was active a moment ago.
	liveAgent := map[string]bool{}
	for _, l := range in.Live {
		liveAgent[l.Agent] = true
	}
	for id, st := range in.Stats {
		if seen[id] || st.Agent == "" {
			continue
		}
		ago := agoOf(in.Now, st.LastTS)
		row := Row{ID: id, Agent: st.Agent, Kind: KindImported, CWD: st.CWD, StartedAt: st.FirstTS, EndedAt: st.LastTS,
			AgoMs: ago, LastTS: st.LastTS, Events: st.Events, Blocked: st.Blocked, Pending: in.Pending[id]}
		if !st.Imported {
			row.Kind = KindHook
			row.EndedAt = 0
			row.Alive = liveAgent[st.Agent] || (ago != nil && time.Duration(*ago)*time.Millisecond < WorkingWindow)
		}
		row.Status = status(row.Alive, row.Pending, ago)
		rows = append(rows, row)
	}

	rank := map[string]int{Blocked: 0, Working: 1, Idle: 2, Dead: 3}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].Status] != rank[rows[j].Status] {
			return rank[rows[i].Status] < rank[rows[j].Status]
		}
		return rows[i].LastTS > rows[j].LastTS
	})
	if rows == nil {
		rows = []Row{}
	}
	return rows
}
