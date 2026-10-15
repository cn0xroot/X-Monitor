package flow

import (
	"fmt"
	"testing"

	"xmonitor/internal/event"
)

const minute = int64(60_000)

func op(id string, ts int64, layer, class string, dec event.Action, rule string, f map[string]any) *event.Event {
	return &event.Event{ID: id, TS: ts, Layer: layer, Kind: event.KindIntent, Type: "tool_use", Session: "zs_1",
		Agent: "claude-code", CWD: "/p/app", Risk: event.RiskLow, Decision: dec, Rule: rule, Fields: f,
		Tool: &event.Tool{Raw: "Bash", Class: class, Args: map[string]any{"command": "ls"}}}
}

func obs(id string, ts int64, typ string) *event.Event {
	return &event.Event{ID: id, TS: ts, Layer: "L3", Kind: event.KindIntent, Type: typ, Session: "zs_1",
		Fields: map[string]any{"cmdline": "ps -A"}, Risk: event.RiskInfo, Title: "proc"}
}

func TestStatuses(t *testing.T) {
	evs := []*event.Event{
		op("a", 1, "L4", "exec.shell", event.ActionAllow, "", nil),
		op("b", 2, "L4", "exec.shell", event.ActionBlock, "dangerous_delete", nil),
		op("c", 3, "L4", "exec.shell", event.ActionAllow, "sudo_usage", map[string]any{"approval": "allowed", "confirm": true}),
		op("d", 4, "L4", "exec.shell", event.ActionBlock, "sudo_usage", map[string]any{"approval": "denied"}),
		op("e", 5, "L4", "exec.shell", event.ActionBlock, "sudo_usage", map[string]any{"approval": "expired"}),
	}
	f := Build(evs, false)
	want := []string{StatusOK, StatusBlocked, StatusApproved, StatusDenied, StatusDenied}
	if len(f.Turns) != 1 || len(f.Turns[0].Nodes) != 5 {
		t.Fatalf("turns: %+v", f.Turns)
	}
	for i, n := range f.Turns[0].Nodes {
		if n.Status != want[i] || n.Type != TypeOp {
			t.Errorf("node %d: status=%s type=%s want %s", i, n.Status, n.Type, want[i])
		}
	}
	if f.SessionID != "zs_1" || f.Agent != "claude-code" || f.CWD != "/p/app" || f.EventCount != 5 {
		t.Errorf("header: %+v", f)
	}
}

// A call audited by the proxy and again by the hook is one card, not two.
func TestHookReuseFoldsIntoOneNode(t *testing.T) {
	first := op("ev1", 10, "L4", "exec.shell", event.ActionAllow, "", nil)
	again := op("ev2", 11, "hook", "exec.shell", event.ActionAllow, "", map[string]any{"reused_from": "ev1"})
	f := Build([]*event.Event{first, again}, false)
	nodes := f.Turns[0].Nodes
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if len(nodes[0].EventIDs) != 2 || len(nodes[0].Layers) != 2 {
		t.Errorf("both audits must be attached: %+v", nodes[0])
	}
	// If the original is outside the window, the re-audit stands on its own.
	f = Build([]*event.Event{again}, false)
	if len(f.Turns[0].Nodes) != 1 || f.Turns[0].Nodes[0].ID != "ev2" {
		t.Errorf("orphaned reuse must still be shown: %+v", f.Turns[0].Nodes)
	}
}

func TestObservationGrouping(t *testing.T) {
	var evs []*event.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, obs(fmt.Sprintf("p%d", i), int64(i), "proc_spawn"))
	}
	evs = append(evs, op("x", 100, "L4", "exec.shell", event.ActionAllow, "", nil))
	evs = append(evs, obs("q1", 200, "proc_spawn"), obs("q2", 201, "proc_spawn")) // only 2: stays separate
	n := Build(evs, false).Turns[0].Nodes
	if len(n) != 4 {
		t.Fatalf("want group + op + 2 loose observations, got %d: %+v", len(n), n)
	}
	if n[0].Type != TypeGroup || n[0].Count != 5 || n[0].StartTS != 0 || n[0].EndTS != 4 {
		t.Errorf("group: %+v", n[0])
	}
	if n[1].Type != TypeOp || n[2].Type != TypeObserve || n[3].Type != TypeObserve {
		t.Errorf("rest: %+v", n[1:])
	}
}

func TestGroupKeepsWorstRiskAndWarn(t *testing.T) {
	evs := []*event.Event{obs("a", 1, "connect"), obs("b", 2, "connect"), obs("c", 3, "connect")}
	evs[1].Risk = event.RiskHigh
	g := Build(evs, false).Turns[0].Nodes[0]
	if g.Type != TypeGroup || g.Risk != "high" || g.Status != StatusWarn {
		t.Errorf("a high-risk member must not be averaged away: %+v", g)
	}
}

func TestTurnsSplitOnIdleGap(t *testing.T) {
	evs := []*event.Event{
		op("a", 0, "L4", "exec.shell", event.ActionAllow, "", nil),
		op("b", 2*minute, "L4", "exec.shell", event.ActionAllow, "", nil),
		op("c", 2*minute+TurnGapMs+1, "L4", "exec.shell", event.ActionAllow, "", nil),   // after a long idle gap
		op("d", 2*minute+2*TurnGapMs+2, "L4", "exec.shell", event.ActionAllow, "", nil), // again > TurnGapMs after c
	}
	f := Build(evs, false)
	if len(f.Turns) != 3 {
		t.Fatalf("turns=%d want 3", len(f.Turns))
	}
	if f.Turns[0].Index != 1 || f.Turns[2].Index != 3 || len(f.Turns[0].Nodes) != 2 {
		t.Errorf("turns: %+v", f.Turns)
	}
	if f.Turns[0].StartTS != 0 || f.Turns[0].EndTS != 2*minute {
		t.Errorf("turn bounds: %+v", f.Turns[0])
	}
	// exactly TurnGapMs apart is still the same turn (the rule is "longer than")
	same := Build([]*event.Event{
		op("x", 0, "L4", "exec.shell", event.ActionAllow, "", nil),
		op("y", TurnGapMs, "L4", "exec.shell", event.ActionAllow, "", nil),
	}, false)
	if len(same.Turns) != 1 {
		t.Errorf("a gap of exactly %dms must not split the turn", TurnGapMs)
	}
}

func TestAlertsAndSubagentBranch(t *testing.T) {
	spawn := op("s", 1, "L4", "agent.spawn", event.ActionAllow, "", nil)
	al := &event.Event{ID: "al", TS: 2, Layer: "L1", Kind: event.KindAlert, Type: "exec_denied", Decision: event.ActionBlock,
		Risk: event.RiskHigh, Title: "killed", Fields: map[string]any{"command": "nc -l 4444"}}
	soft := &event.Event{ID: "so", TS: 3, Layer: "L4", Kind: event.KindAlert, Type: "secret_egress", Risk: event.RiskHigh}
	n := Build([]*event.Event{spawn, al, soft}, true).Turns[0].Nodes
	if !n[0].Branch {
		t.Error("agent.spawn must be a branch")
	}
	if n[1].Type != TypeAlert || n[1].Status != StatusBlocked || n[1].Summary != "nc -l 4444" {
		t.Errorf("blocking alert: %+v", n[1])
	}
	if n[2].Status != StatusWarn {
		t.Errorf("non-blocking alert is a warning: %+v", n[2])
	}
	if !Build(nil, true).Truncated || len(Build(nil, false).Turns) != 0 {
		t.Error("empty input must give no turns and keep the truncated flag")
	}
}

func TestSummaryDoesNotRepeatTheTitle(t *testing.T) {
	seen := &event.Event{ID: "s", TS: 1, Layer: "L4", Kind: event.KindSession, Type: "agent_seen", Title: "AI client detected", Risk: event.RiskInfo}
	n := Build([]*event.Event{seen}, false).Turns[0].Nodes[0]
	if n.Title != "AI client detected" || n.Summary != "" {
		t.Errorf("title=%q summary=%q: the summary must stay empty when there is nothing more to say", n.Title, n.Summary)
	}
	withPath := Build([]*event.Event{{ID: "p", TS: 1, Layer: "L2", Kind: event.KindIntent, Type: "write", Title: "file change",
		Fields: map[string]any{"path": "/etc/hosts"}}}, false).Turns[0].Nodes[0]
	if withPath.Summary != "/etc/hosts" {
		t.Errorf("a real detail must still be shown: %q", withPath.Summary)
	}
}
