package proctree

import (
	"testing"
	"time"

	"xmonitor/internal/event"
)

func TestPropagation(t *testing.T) {
	tr := New(nil, time.Second)
	tr.Register(100, "claude-code", "s1")
	var execs []*event.Event
	tr.OnExec(func(e *event.Event) { execs = append(execs, e) })
	// first scan establishes baseline (no exec events)
	tr.scan([]Proc{{PID: 100, PPID: 1, Comm: "claude"}}, true)
	// child bash under agent, grandchild curl under bash
	tr.scan([]Proc{
		{PID: 100, PPID: 1, Comm: "claude"},
		{PID: 200, PPID: 100, Comm: "bash", Cmdline: "bash -c curl"},
		{PID: 300, PPID: 200, Comm: "curl", Cmdline: "curl http://x"},
	}, false)
	if info, ok := tr.Lookup(300); !ok || info.RootPID != 100 || info.Agent != "claude-code" || info.Session != "s1" {
		t.Fatalf("grandchild not attributed: %+v ok=%v", info, ok)
	}
	if len(execs) != 2 {
		t.Fatalf("expected 2 exec events, got %d", len(execs))
	}
	// unrelated process must not be tracked
	tr.scan([]Proc{{PID: 100, PPID: 1, Comm: "claude"}, {PID: 999, PPID: 1, Comm: "gnome-shell"}}, false)
	if _, ok := tr.Lookup(999); ok {
		t.Fatal("unrelated process tracked")
	}
	// dead PIDs pruned
	if _, ok := tr.Lookup(300); ok {
		t.Fatal("dead pid 300 not pruned")
	}
}

func TestPSListerReal(t *testing.T) {
	procs, err := PSLister()
	if err != nil {
		t.Skip("ps unavailable:", err)
	}
	if len(procs) < 2 {
		t.Fatalf("expected processes, got %d", len(procs))
	}
	self := false
	for _, p := range procs {
		if p.PID == 1 {
			self = true
		}
	}
	if !self {
		t.Error("pid 1 not listed")
	}
}

// The daemon may be started from inside an agent's shell. Its own subtree (the
// once-a-second `ps` poll above all) must never be attributed to that agent.
func TestDaemonNeverTracksItself(t *testing.T) {
	tr := New(nil, time.Second)
	tr.self = 500 // pretend xmond is pid 500
	tr.Register(100, "claude-code", "s1")
	var execs []*event.Event
	tr.OnExec(func(e *event.Event) { execs = append(execs, e) })

	agent := Proc{PID: 100, PPID: 1, Comm: "claude"}
	tr.scan([]Proc{agent}, true)
	tr.scan([]Proc{
		agent,
		{PID: 200, PPID: 100, Comm: "bash"},             // ordinary agent child: tracked
		{PID: 500, PPID: 100, Comm: "xmond"},            // the daemon, launched by the agent
		{PID: 600, PPID: 500, Comm: "ps"},               // its poll
		{PID: 700, PPID: 600, Comm: "grandchild-of-ps"}, // anything below that
	}, false)

	if _, ok := tr.Lookup(200); !ok {
		t.Error("a normal agent child must still be tracked")
	}
	for _, pid := range []int{500, 600, 700} {
		if _, ok := tr.Lookup(pid); ok {
			t.Errorf("pid %d belongs to the daemon's own subtree and must not be tracked", pid)
		}
	}
	if len(execs) != 1 || execs[0].PID != 200 {
		t.Errorf("only the bash child should be reported, got %d events", len(execs))
	}
}

func TestAlreadyRunningAgentIsReportedAndSnapshotted(t *testing.T) {
	tr := New(nil, 0)
	type hit struct {
		agent   string
		already bool
	}
	var hits []hit
	tr.OnAgentSpawn(func(a, _ string, _ int, already bool) { hits = append(hits, hit{a, already}) })
	procs := []Proc{
		{PID: 200, PPID: 1, Comm: "opencode"},
		{PID: 201, PPID: 200, Comm: "opencode.exe", Exe: "/opt/homebrew/lib/node_modules/@opencode/cli/bin/opencode.exe", Cmdline: "opencode.exe serve --service"},
		{PID: 300, PPID: 1, Comm: "CursorUIViewService"},
	}
	tr.scan(procs, true)
	if len(hits) != 1 || hits[0] != (hit{"opencode", true}) {
		t.Fatalf("first scan must report the running agent once, got %+v", hits)
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Agent != "opencode" || snap[0].PID != 200 || snap[0].Children != 1 || snap[0].Managed {
		t.Fatalf("snapshot: %+v", snap)
	}
	tr.scan(procs, false)
	if len(hits) != 1 {
		t.Fatalf("an agent must be reported once, got %+v", hits)
	}
}
