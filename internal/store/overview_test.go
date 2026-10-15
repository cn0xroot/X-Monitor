package store

import (
	"testing"

	"xmonitor/internal/event"
)

func add(t *testing.T, s *Store, e *event.Event) {
	t.Helper()
	if err := s.Append(e); err != nil {
		t.Fatal(err)
	}
}

func toolEv(ts int64, layer, class, rule string, dec event.Action, risk event.Risk, extra map[string]any) *event.Event {
	return &event.Event{TS: ts, Layer: layer, Kind: event.KindIntent, Type: "tool_use", Agent: "claude-code",
		Tool: &event.Tool{Raw: "Bash", Class: class}, Rule: rule, Decision: dec, Risk: risk, Fields: extra}
}

func TestOverviewCounts(t *testing.T) {
	s := open(t)
	const now = int64(1_760_000_000_000) // a realistic unix-ms timestamp (since must be positive)
	since := now - 24*3600*1000

	// before the window: must be ignored everywhere
	add(t, s, toolEv(since-1, "L4", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, nil))

	add(t, s, toolEv(since+1000, "L4", "exec.shell", "", event.ActionAllow, event.RiskLow, nil))
	add(t, s, toolEv(since+2000, "L4", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, nil))
	add(t, s, toolEv(since+3000, "L4", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, nil))
	add(t, s, toolEv(since+4000, "L4", "exec.shell", "sudo_usage", event.ActionAllow, event.RiskMedium,
		map[string]any{"confirm": true}))
	add(t, s, toolEv(since+5000, "L4", "fs.write", "", event.ActionAllow, event.RiskLow, nil))
	// the same write seen again by the hook layer: audited, but not a new call
	add(t, s, toolEv(since+5100, "hook", "fs.write", "", event.ActionAllow, event.RiskLow,
		map[string]any{"reused_from": "ev_x"}))
	add(t, s, &event.Event{TS: since + 6000, Layer: "L4", Kind: event.KindAlert, Type: "secret_egress", Risk: event.RiskHigh})
	add(t, s, &event.Event{TS: since + 7000, Layer: "L1", Kind: event.KindAlert, Type: "hook_bypass", Risk: event.RiskHigh})

	_ = s.PutSession(&Session{ID: "a", Agent: "claude-code", StartedAt: since + 10})
	_ = s.PutSession(&Session{ID: "b", Agent: "claude-code", StartedAt: since + 20, EndedAt: since + 30})
	_, _ = s.CreateApproval(&Approval{Session: "a", Rule: "sudo_usage"})

	o, err := s.Overview(since, now, 24)
	if err != nil {
		t.Fatal(err)
	}
	if o.Events != 8 { // 8 events in the window; the pre-window one is excluded
		t.Errorf("events=%d want 8", o.Events)
	}
	if o.ToolCalls != 5 { // 6 tool_use records minus the reused one
		t.Errorf("tool_calls=%d want 5 (reused_from must not double count)", o.ToolCalls)
	}
	if o.Alerts != 2 || o.ByAlert["secret_egress"] != 1 || o.ByAlert["hook_bypass"] != 1 {
		t.Errorf("alerts: %d %v", o.Alerts, o.ByAlert)
	}
	if o.ByDecision["block"] != 2 || o.ByDecision["allow"] != 4 {
		t.Errorf("by_decision=%v", o.ByDecision)
	}
	if o.ByToolClass["exec.shell"] != 4 || o.ByToolClass["fs.write"] != 1 {
		t.Errorf("by_tool_class=%v", o.ByToolClass)
	}
	if o.ByLayer["L4"] != 6 || o.ByLayer["hook"] != 1 || o.ByLayer["L1"] != 1 {
		t.Errorf("by_layer=%v", o.ByLayer)
	}
	if o.ByRisk["high"] != 4 {
		t.Errorf("by_risk=%v", o.ByRisk)
	}
	if o.ByAgent["claude-code"] != 6 {
		t.Errorf("by_agent=%v", o.ByAgent)
	}
	if len(o.ByRule) == 0 || o.ByRule[0].Rule != "dangerous_delete" || o.ByRule[0].Total != 2 || o.ByRule[0].Blocked != 2 {
		t.Errorf("by_rule[0]=%+v", o.ByRule)
	}
	if o.SessionsAll != 2 || o.SessionsRun != 1 || o.Pending != 1 {
		t.Errorf("sessions all=%d run=%d pending=%d", o.SessionsAll, o.SessionsRun, o.Pending)
	}
	if len(o.RecentBlocks) != 2 || o.RecentBlocks[0].TS < o.RecentBlocks[1].TS {
		t.Errorf("recent_blocked must be the 2 blocks, newest first: %+v", o.RecentBlocks)
	}

	// timeline: exactly 24 zero-filled slots whose totals add up to the intent events
	if len(o.Timeline) != 24 {
		t.Fatalf("timeline slots=%d", len(o.Timeline))
	}
	var tot, blk int64
	for i, b := range o.Timeline {
		tot += b.Total
		blk += b.Blocked
		if i > 0 && b.TS <= o.Timeline[i-1].TS {
			t.Error("timeline must be strictly increasing")
		}
	}
	if tot != 6 || blk != 2 {
		t.Errorf("timeline totals=%d blocked=%d, want 6 and 2", tot, blk)
	}
}

func TestOverviewEmptyIsWellFormed(t *testing.T) {
	s := open(t)
	o, err := s.Overview(0, 1_000_000, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Timeline) != 12 || o.ByRule == nil || o.RecentBlocks == nil || o.ByLayer == nil {
		t.Errorf("empty overview must have non-nil collections: %+v", o)
	}
}

func TestQueryFilters(t *testing.T) {
	s := open(t)
	add(t, s, toolEv(100, "L4", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, nil))
	add(t, s, toolEv(200, "L4", "exec.shell", "sudo_usage", event.ActionAllow, event.RiskMedium, nil))
	add(t, s, &event.Event{TS: 300, Layer: "L4", Kind: event.KindAlert, Type: "secret_egress", Risk: event.RiskHigh})
	add(t, s, toolEv(400, "L4", "exec.shell", "", event.ActionAllow, event.RiskLow, nil))

	n := func(q Query) int { l, _ := s.ListEvents(q); return len(l) }
	if n(Query{Decision: "block"}) != 1 {
		t.Error("decision filter")
	}
	if n(Query{Rules: []string{"dangerous_delete", "sudo_usage"}}) != 2 {
		t.Error("rules filter")
	}
	if n(Query{Types: []string{"secret_egress"}}) != 1 {
		t.Error("types filter")
	}
	if n(Query{Rules: []string{"dangerous_delete"}, Types: []string{"secret_egress"}}) != 2 {
		t.Error("rules and types must combine with OR (a category = its rules + its alert types)")
	}
	if n(Query{Since: 250}) != 2 || n(Query{Kind: "alert"}) != 1 {
		t.Error("since/kind filter")
	}
}

func TestTimelineLanesAndBuckets(t *testing.T) {
	s := open(t)
	const now = int64(1_760_000_000_000)
	const min = int64(60_000)
	mk := func(ts int64, sess, agent, agentSess, typ string, risk event.Risk, dec event.Action, cwd string) *event.Event {
		return &event.Event{TS: ts, Layer: "L4", Kind: event.KindIntent, Type: typ, Session: sess, Agent: agent,
			AgentSession: agentSess, CWD: cwd, Risk: risk, Decision: dec}
	}
	// managed session lane: 3 events in the same 15-minute bucket, one of them high + blocked
	base := (now - 30*min) / (15 * min) * (15 * min)
	add(t, s, mk(base+1000, "zs_1", "claude-code", "", "tool_use", event.RiskLow, event.ActionAllow, "/p/app"))
	add(t, s, mk(base+2000, "zs_1", "claude-code", "", "tool_use", event.RiskLow, event.ActionAllow, "/p/app"))
	add(t, s, mk(base+3000, "zs_1", "claude-code", "", "tool_use", event.RiskHigh, event.ActionBlock, "/p/app"))
	// imported session lane
	add(t, s, mk(base+4000, "", "claude-code", "cc9", "tool_use", event.RiskMedium, event.ActionAllow, "/work/tesla"))
	// unmanaged agent lane
	add(t, s, mk(base+5000, "", "gemini-cli", "", "connect", event.RiskInfo, "", ""))
	// bookkeeping noise must not create or inflate lanes
	add(t, s, mk(base+6000, "zs_1", "claude-code", "", "proc_spawn", event.RiskInfo, "", ""))
	// outside the window
	add(t, s, mk(now-3*24*3600*1000, "zs_old", "x", "", "tool_use", event.RiskLow, event.ActionAllow, ""))
	_ = s.PutSession(&Session{ID: "zs_1", Agent: "claude-code", CWD: "/p/app", StartedAt: base})

	tl, err := s.Timeline(1440, now, 50)
	if err != nil {
		t.Fatal(err)
	}
	if tl.BucketMs != 15*min || tl.RangeMinutes != 1440 || tl.Now != now {
		t.Errorf("header: %+v", tl)
	}
	lanes := map[string]TLLane{}
	for _, l := range tl.Lanes {
		lanes[l.SessionID] = l
	}
	if len(lanes) != 3 {
		t.Fatalf("lanes=%v (zs_old is outside the window)", keys(lanes))
	}
	m := lanes["zs_1"]
	if !m.Managed || m.Label != "app" || m.EventCount != 3 || m.BlockedCount != 1 {
		t.Errorf("managed lane: %+v", m)
	}
	if len(m.Buckets) != 1 {
		t.Fatalf("buckets=%+v", m.Buckets)
	}
	b := m.Buckets[0]
	if b.StartMs != base || b.N != 3 || b.NHigh != 1 || b.NLow != 2 || b.NBlocked != 1 || b.NInfo != 0 {
		t.Errorf("bucket composition (a high event must stay visible): %+v", b)
	}
	if e := lanes["ext:cc9"]; e.Managed || e.Label != "tesla" || e.Buckets[0].NMedium != 1 {
		t.Errorf("imported lane: %+v", e)
	}
	if a := lanes["agent:gemini-cli"]; a.Label != "gemini-cli" || a.Agent != "gemini-cli" {
		t.Errorf("agent lane: %+v", a)
	}
	// newest activity first
	if tl.Lanes[0].LastTS < tl.Lanes[len(tl.Lanes)-1].LastTS {
		t.Error("lanes must be ordered by most recent activity")
	}

	evs, trunc, err := s.LaneEvents("zs_1", 10)
	if err != nil || trunc {
		t.Fatalf("LaneEvents: %v trunc=%v", err, trunc)
	}
	if len(evs) != 4 || evs[0].TS > evs[len(evs)-1].TS { // includes proc_spawn: the flow shows it
		t.Errorf("lane events must be chronological and include bookkeeping: %d", len(evs))
	}
	if _, trunc, _ := s.LaneEvents("zs_1", 2); !trunc {
		t.Error("limit below the lane size must report truncation")
	}
}

func keys(m map[string]TLLane) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestActivityKeysImportedSessionsAndKeepsThemOutOfAgentTotals(t *testing.T) {
	st := open(t)
	put := func(e *event.Event) { add(t, st, e) }
	put(&event.Event{ID: "a1", TS: 1000, Layer: "hook", Kind: event.KindIntent, Type: "tool_use", Agent: "claude-code", AgentSession: "cc9", CWD: "/w/app", Decision: event.ActionBlock})
	put(&event.Event{ID: "a2", TS: 2000, Layer: "hook", Kind: event.KindIntent, Type: "tool_use", Agent: "claude-code", AgentSession: "cc9", CWD: "/w/app"})
	put(&event.Event{ID: "b1", TS: 3000, Layer: "L3", Kind: event.KindSession, Type: "agent_discovered", Agent: "claude-code"})
	put(&event.Event{ID: "c1", TS: 4000, Layer: "L4", Kind: event.KindIntent, Type: "tool_use", Agent: "codex", Session: "zs_1"})
	bySes, err := st.ActivityBySession()
	if err != nil {
		t.Fatal(err)
	}
	if e := bySes["ext:cc9"]; e.Events != 2 || e.Blocked != 1 || e.LastTS != 2000 || e.CWD != "/w/app" || e.Agent != "claude-code" {
		t.Errorf("imported: %+v", e)
	}
	if e := bySes["zs_1"]; e.Events != 1 || e.Agent != "codex" {
		t.Errorf("managed: %+v", e)
	}
	byAg, _ := st.ActivityByAgent()
	if e := byAg["claude-code"]; e.Events != 1 || e.LastTS != 3000 {
		t.Errorf("imported events must not count as the live process's activity: %+v", e)
	}
}
