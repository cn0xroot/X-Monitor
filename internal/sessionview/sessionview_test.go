package sessionview

import (
	"testing"
	"time"

	"xmonitor/internal/store"
)

var now = time.UnixMilli(1_000_000_000)

func ms(d time.Duration) int64 { return now.Add(-d).UnixMilli() }

func byID(rows []Row, id string) Row {
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	return Row{}
}

func TestHeartbeatStatesForAnyAgent(t *testing.T) {
	in := Input{
		Now: now,
		Sessions: []*store.Session{
			{ID: "zs_work", Agent: "codex", RootPID: 10, StartedAt: ms(time.Hour)},
			{ID: "zs_idle", Agent: "gemini-cli", RootPID: 11, StartedAt: ms(2 * time.Hour)},
			{ID: "zs_wait", Agent: "claude-code", RootPID: 12, StartedAt: ms(time.Hour)},
			{ID: "zs_gone", Agent: "aider", RootPID: 13, StartedAt: ms(time.Hour)},                           // process vanished
			{ID: "zs_done", Agent: "codex", RootPID: 14, StartedAt: ms(time.Hour), EndedAt: ms(time.Minute)}, // ended cleanly
		},
		Stats: map[string]store.ActivityStat{
			"zs_work": {Events: 5, LastTS: ms(20 * time.Second)},
			"zs_idle": {Events: 3, LastTS: ms(40 * time.Minute)},
			"zs_wait": {Events: 9, LastTS: ms(10 * time.Second)},
			"zs_gone": {Events: 1, LastTS: ms(30 * time.Minute)},
			"ext:1":   {Agent: "claude-code", Events: 4, Blocked: 1, FirstTS: ms(48 * time.Hour), LastTS: ms(47 * time.Hour), Imported: true},
			"ext:oc":  {Agent: "opencode", Events: 3, FirstTS: ms(time.Hour), LastTS: ms(20 * time.Minute)}, // native hook, agent still running
			"ext:old": {Agent: "aider", Events: 2, FirstTS: ms(5 * time.Hour), LastTS: ms(4 * time.Hour)},   // native hook, agent gone
		},
		Pending: map[string]int{"zs_wait": 1},
		Agents:  map[string]store.ActivityStat{"opencode": {Events: 2, LastTS: ms(90 * time.Second)}},
		Live: []Live{{Agent: "codex", PID: 10}, {Agent: "gemini-cli", PID: 11}, {Agent: "claude-code", PID: 12},
			{Agent: "opencode", PID: 99, Children: 1}},
	}
	rows := Build(in)
	want := map[string]string{"zs_work": Working, "zs_idle": Idle, "zs_wait": Blocked, "zs_gone": Dead, "zs_done": Dead,
		"proc:99": Working, "ext:1": Dead, "ext:oc": Idle, "ext:old": Dead}
	for id, st := range want {
		if got := byID(rows, id).Status; got != st {
			t.Errorf("%s: status %q want %q", id, got, st)
		}
	}
	if k := byID(rows, "proc:99").Kind; k != KindProcess {
		t.Errorf("unmanaged opencode must be a process row, got %q", k)
	}
	if k := byID(rows, "ext:1").Kind; k != KindImported {
		t.Errorf("imported kind: %q", k)
	}
	if k := byID(rows, "ext:oc").Kind; k != KindHook {
		t.Errorf("a live hook session must not be labelled imported: %q", k)
	}
	if len(rows) != 9 {
		t.Errorf("a managed root must not also appear as a process row: got %d rows", len(rows))
	}
	// blocked first, then working, then idle, dead last
	order := []string{rows[0].Status, rows[1].Status, rows[2].Status}
	if order[0] != Blocked || order[1] != Working || order[2] != Working {
		t.Errorf("sort order: %v", order)
	}
	if rows[len(rows)-1].Status != Dead {
		t.Errorf("dead rows go last")
	}
}

func TestWorkingWindowEdge(t *testing.T) {
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{{4*time.Minute + 59*time.Second, Working}, {5*time.Minute + time.Second, Idle}} {
		rows := Build(Input{Now: now, Live: []Live{{Agent: "opencode", PID: 1}},
			Agents: map[string]store.ActivityStat{"opencode": {LastTS: ms(c.ago)}}})
		if rows[0].Status != c.want {
			t.Errorf("ago %v: %q want %q", c.ago, rows[0].Status, c.want)
		}
	}
	// a process never seen doing anything is idle, with no timestamp
	r := Build(Input{Now: now, Live: []Live{{Agent: "cursor-agent", PID: 5}}})[0]
	if r.Status != Idle || r.AgoMs != nil {
		t.Errorf("never active: %+v", r)
	}
}

func TestJustStartedSessionIsNotDead(t *testing.T) {
	rows := Build(Input{Now: now, Sessions: []*store.Session{{ID: "zs_new", Agent: "codex", RootPID: 77, StartedAt: ms(3 * time.Second)}}})
	if rows[0].Status == Dead {
		t.Fatal("a session registered 3s ago may not be in the process scan yet")
	}
}

func TestEmptyIsAnArray(t *testing.T) {
	if Build(Input{Now: now}) == nil {
		t.Fatal("must be [] not null")
	}
}
