package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/event"
	"xmonitor/internal/rules"
	"xmonitor/internal/store"
	"xmonitor/internal/usage"
)

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	re, err := rules.New("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	srv := New(&Server{
		Store: st, Rules: re, Cfg: func() *config.Config { return cfg }, Token: "tok", Version: "test",
		Broker: approval.New(st, func() time.Duration { return time.Second }, nil),
	})
	ts := httptest.NewServer(srv.Handler(nil))
	t.Cleanup(ts.Close)
	return ts, st
}

func get(t *testing.T, ts *httptest.Server, path string, out any) int {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
	}
	return resp.StatusCode
}

func seed(t *testing.T, st *store.Store) {
	t.Helper()
	now := time.Now().UnixMilli()
	mk := func(ago int64, sess, rule string, dec event.Action, risk event.Risk) *event.Event {
		return &event.Event{TS: now - ago, Layer: "L4", Kind: event.KindIntent, Type: "tool_use", Session: sess,
			Agent: "claude-code", CWD: "/p/app", Rule: rule, Decision: dec, Risk: risk,
			Tool: &event.Tool{Raw: "Bash", Class: "exec.shell", Args: map[string]any{"command": "x"}}}
	}
	for _, e := range []*event.Event{
		mk(50_000, "zs_1", "dangerous_delete", event.ActionBlock, event.RiskHigh),
		mk(40_000, "zs_1", "curl_pipe_shell", event.ActionBlock, event.RiskHigh),
		mk(30_000, "zs_1", "sudo_usage", event.ActionAllow, event.RiskMedium),
		mk(20_000, "zs_1", "", event.ActionAllow, event.RiskLow),
		{TS: now - 10_000, Layer: "L4", Kind: event.KindAlert, Type: "secret_egress", Session: "zs_1", Risk: event.RiskHigh},
		{TS: now - 5_000, Layer: "L1", Kind: event.KindAlert, Type: "hook_bypass", Session: "zs_1", Risk: event.RiskHigh},
	} {
		if err := st.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.PutSession(&store.Session{ID: "zs_1", Agent: "claude-code", CWD: "/p/app", StartedAt: now - 60_000})
}

func TestOverviewEndpoint(t *testing.T) {
	ts, st := newTestServer(t)
	seed(t, st)
	var o OverviewResponse
	if c := get(t, ts, "/api/overview?range=24h", &o); c != 200 {
		t.Fatalf("status %d", c)
	}
	if o.Mode != "active" || o.Blocked != 2 || o.Bypass != 1 || o.Events != 6 || o.ToolCalls != 4 {
		t.Errorf("headline: mode=%s blocked=%d bypass=%d events=%d calls=%d", o.Mode, o.Blocked, o.Bypass, o.Events, o.ToolCalls)
	}
	cats := map[string]CatStat{}
	for _, c := range o.Categories {
		cats[c.Key] = c
	}
	if len(o.Categories) != len(rules.Categories) {
		t.Errorf("every category must be present even when 0: %d", len(o.Categories))
	}
	if c := cats[rules.CatDestruction]; c.Total != 1 || c.Blocked != 1 {
		t.Errorf("destruction: %+v", c)
	}
	if c := cats[rules.CatSupplyChain]; c.Total != 1 || c.Blocked != 1 { // curl | bash
		t.Errorf("supply_chain: %+v", c)
	}
	if c := cats[rules.CatPrivilege]; c.Total != 1 || c.Blocked != 0 {
		t.Errorf("privilege: %+v", c)
	}
	if c := cats[rules.CatExfil]; c.Total != 1 { // the secret_egress alert
		t.Errorf("exfiltration must count the alert: %+v", c)
	}
	if c := cats[rules.CatEvasion]; c.Total != 1 { // the hook_bypass alert
		t.Errorf("evasion must count the bypass alert: %+v", c)
	}
	if len(o.Timeline) != 24 || o.SessionsRun != 1 {
		t.Errorf("timeline=%d sessions_running=%d", len(o.Timeline), o.SessionsRun)
	}
	if o.Sandbox.Tier == "" {
		t.Error("sandbox tier must be reported")
	}
}

func TestOverviewEmptyHasNoNulls(t *testing.T) {
	ts, _ := newTestServer(t)
	var raw map[string]json.RawMessage
	if get(t, ts, "/api/overview", &raw) != 200 {
		t.Fatal("status")
	}
	for _, k := range []string{"timeline", "by_rule", "recent_blocked", "categories", "by_layer", "by_risk", "by_decision"} {
		if string(raw[k]) == "null" || len(raw[k]) == 0 {
			t.Errorf("%s must not be null on an empty store (clients iterate it): %s", k, raw[k])
		}
	}
}

func TestEventsByCategory(t *testing.T) {
	ts, st := newTestServer(t)
	seed(t, st)
	var evs []event.Event
	get(t, ts, "/api/events?category=destruction", &evs)
	if len(evs) != 1 || evs[0].Rule != "dangerous_delete" {
		t.Errorf("destruction: %+v", evs)
	}
	evs = nil
	get(t, ts, "/api/events?category=exfiltration", &evs)
	if len(evs) != 1 || evs[0].Type != "secret_egress" {
		t.Errorf("exfiltration must return the alert: %+v", evs)
	}
	evs = nil
	get(t, ts, "/api/events?decision=block&kind=intent", &evs)
	if len(evs) != 2 {
		t.Errorf("decision filter: %d", len(evs))
	}
	var none []event.Event
	if get(t, ts, "/api/events?category=no_such_category", &none); len(none) != 0 {
		t.Errorf("unknown category must be empty: %+v", none)
	}
}

func TestTimelineAndFlowEndpoints(t *testing.T) {
	ts, st := newTestServer(t)
	seed(t, st)
	var raw struct {
		RangeMinutes int `json:"rangeMinutes"`
		BucketMs     int64
		Lanes        []map[string]any `json:"lanes"`
	}
	get(t, ts, "/api/timeline?range=1h", &raw)
	if raw.RangeMinutes != 60 || raw.BucketMs != 60_000 || len(raw.Lanes) != 1 {
		t.Fatalf("timeline: %+v", raw)
	}
	lane := raw.Lanes[0]
	for _, k := range []string{"sessionId", "label", "agent", "cwd", "managed", "eventCount", "blockedCount", "bypassCount", "firstTs", "lastTs", "buckets"} {
		if _, ok := lane[k]; !ok {
			t.Errorf("lane is missing %q (the front end relies on it)", k)
		}
	}
	if lane["sessionId"] != "zs_1" || lane["label"] != "app" || lane["managed"] != true {
		t.Errorf("lane: %+v", lane)
	}
	b := lane["buckets"].([]any)[0].(map[string]any)
	for _, k := range []string{"startMs", "n", "nHigh", "nMedium", "nLow", "nInfo", "nBlocked"} {
		if _, ok := b[k]; !ok {
			t.Errorf("bucket is missing %q", k)
		}
	}

	var fl struct {
		SessionID string `json:"sessionId"`
		Agent     string
		Turns     []struct {
			Index int
			Nodes []map[string]any
		}
	}
	if get(t, ts, "/api/session-flow?session_id=zs_1", &fl) != 200 {
		t.Fatal("flow status")
	}
	if fl.SessionID != "zs_1" || fl.Agent != "claude-code" || len(fl.Turns) != 1 || len(fl.Turns[0].Nodes) != 6 {
		t.Errorf("flow: %+v", fl)
	}
	if n := fl.Turns[0].Nodes[0]; n["status"] != "blocked" || n["rule"] != "dangerous_delete" {
		t.Errorf("first node: %+v", n)
	}
	if get(t, ts, "/api/session-flow", nil) != 400 {
		t.Error("missing session_id must be a 400")
	}
}

func TestNewEndpointsRequireToken(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/api/overview", "/api/timeline", "/api/session-flow?session_id=x"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s without a token: %d, want 401", p, resp.StatusCode)
		}
	}
}

// Every number on the overview is clickable and opens a list. The list must be
// exactly the set of events the number counted — if they ever disagree the
// dashboard is lying to whoever clicked.
func TestEveryOverviewNumberMatchesItsDrillDown(t *testing.T) {
	ts, st := newTestServer(t)
	now := time.Now().UnixMilli()
	mk := func(ago int64, layer, agent, class, rule string, dec event.Action, risk event.Risk, f map[string]any) *event.Event {
		e := &event.Event{TS: now - ago, Layer: layer, Kind: event.KindIntent, Type: "tool_use", Agent: agent, Session: "zs_1",
			Rule: rule, Decision: dec, Risk: risk, Fields: f}
		if class != "" {
			e.Tool = &event.Tool{Raw: "x", Class: class, Args: map[string]any{"command": "c"}}
		}
		return e
	}
	for _, e := range []*event.Event{
		mk(900, "L4", "claude-code", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, nil),
		mk(800, "hook", "claude-code", "exec.shell", "dangerous_delete", event.ActionBlock, event.RiskHigh, map[string]any{"reused_from": "ev_a"}), // re-audit: not a new call
		mk(700, "L4", "codex", "fs.write", "", event.ActionAllow, event.RiskLow, nil),
		mk(600, "L4", "gemini-cli", "exec.shell", "sudo_usage", event.ActionAllow, event.RiskMedium, nil),
		{TS: now - 500, Layer: "L3", Kind: event.KindIntent, Type: "proc_spawn", Agent: "claude-code", Risk: event.RiskInfo},
		{TS: now - 400, Layer: "L1", Kind: event.KindIntent, Type: "execve", Agent: "codex", Risk: event.RiskInfo},
		{TS: now - 300, Layer: "L2", Kind: event.KindAlert, Type: "silent_sensitive_write", Risk: event.RiskHigh},
		{TS: now - 200, Layer: "L4", Kind: event.KindAlert, Type: "secret_egress", Agent: "codex", Risk: event.RiskHigh},
	} {
		if err := st.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	since := "&since_ms=" + strconv.FormatInt(now-24*3600*1000, 10)
	count := func(query string) int {
		var evs []event.Event
		if c := get(t, ts, "/api/events?limit=5000"+since+"&"+query, &evs); c != 200 {
			t.Fatalf("%s: status %d", query, c)
		}
		return len(evs)
	}
	var o OverviewResponse
	get(t, ts, "/api/overview?range=24h", &o)

	checks := []struct {
		name  string
		shown int64
		query string
	}{
		{"audit events", o.Events, ""},
		{"tool calls", o.ToolCalls, "kind=intent&type=tool_use&no_reused=1"},
		{"alerts", o.Alerts, "kind=alert"},
		{"system-layer observations", o.ByLayer["L1"] + o.ByLayer["L2"] + o.ByLayer["L3"], "layer=L1,L2,L3"},
		{"blocked", o.Blocked, "kind=intent&decision=block"},
	}
	for class, n := range o.ByToolClass {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"tool class " + class, n, "kind=intent&type=tool_use&no_reused=1&tool_class=" + class})
	}
	for layer, n := range o.ByLayer {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"layer " + layer, n, "layer=" + layer})
	}
	for agent, n := range o.ByAgent {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"agent " + agent, n, "agent=" + agent})
	}
	for risk, n := range o.ByRisk {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"risk " + risk, n, "risk_eq=" + risk})
	}
	for dec, n := range o.ByDecision {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"decision " + dec, n, "kind=intent&decision=" + dec})
	}
	for _, rs := range o.ByRule {
		checks = append(checks, struct {
			name  string
			shown int64
			query string
		}{"rule " + rs.Rule, rs.Total, "kind=intent&rule=" + rs.Rule})
	}
	if len(checks) < 15 {
		t.Fatalf("expected a rich set of checks, got %d", len(checks))
	}
	for _, c := range checks {
		if got := count(c.query); int64(got) != c.shown {
			t.Errorf("%s: the card shows %d but clicking it lists %d (query %q)", c.name, c.shown, got, c.query)
		}
	}
	if o.ToolCalls != 3 { // 4 tool_use records minus the hook re-audit
		t.Errorf("tool_calls=%d want 3", o.ToolCalls)
	}
}

func TestSessionListCoversEveryKindAndDrillsDownByLane(t *testing.T) {
	ts, st := newTestServer(t)
	now := time.Now().UnixMilli()
	add := func(e *event.Event) {
		if err := st.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	// a hook-reported OpenCode session (no xmon run), an imported CC-Monitor one, and a bare process
	add(&event.Event{TS: now - 1000, Layer: "hook", Kind: event.KindIntent, Type: "tool_use", Agent: "opencode", AgentSession: "oc1"})
	add(&event.Event{TS: now - 3600e3, Layer: "hook", Kind: event.KindIntent, Type: "tool_use", Agent: "claude-code", AgentSession: "cc1",
		Fields: map[string]any{"imported_from": "cc-monitor"}})
	var rows []struct {
		ID, Kind, Status, Agent string
		Alive                   bool
	}
	if c := get(t, ts, "/api/sessions", &rows); c != 200 {
		t.Fatalf("status %d", c)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.ID] = r.Kind + "/" + r.Status
	}
	if got["ext:oc1"] != "hook/working" {
		t.Errorf("a hook session that just acted is working, not imported: %v", got)
	}
	if got["ext:cc1"] != "imported/dead" {
		t.Errorf("imported history: %v", got)
	}
	var evs []*event.Event
	if get(t, ts, "/api/events?lane=ext:oc1", &evs); len(evs) != 1 || evs[0].Agent != "opencode" {
		t.Errorf("lane drill-down: %+v", evs)
	}
}

type fakeQuota struct{ calls int }

func (f *fakeQuota) Get(context.Context) usage.Result {
	f.calls++
	p := 42.0
	return usage.Result{Enabled: true, Quota: &usage.Quota{Session: &usage.Bucket{Utilization: &p}}}
}

func TestUsageEndpointIsOptIn(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	re, _ := rules.New("")
	cfg := config.Default()
	fq := &fakeQuota{}
	srv := New(&Server{Store: st, Rules: re, Cfg: func() *config.Config { return cfg }, Token: "tok", Anthropic: fq,
		Broker: approval.New(st, func() time.Duration { return time.Second }, nil)})
	ts := httptest.NewServer(srv.Handler(nil))
	defer ts.Close()

	if !cfg.Usage.AnthropicEnabled {
		t.Fatal("quota lookup should be on by default")
	}
	cfg.Usage.AnthropicEnabled = false
	var r usage.Result
	if get(t, ts, "/api/usage", &r); r.Enabled || r.Quota != nil || fq.calls != 0 {
		t.Fatalf("disabled: nothing may be read or fetched: %+v calls=%d", r, fq.calls)
	}
	cfg.Usage.AnthropicEnabled = true
	if get(t, ts, "/api/usage", &r); !r.Enabled || r.Quota == nil || *r.Quota.Session.Utilization != 42 || fq.calls != 1 {
		t.Fatalf("enabled: %+v calls=%d", r, fq.calls)
	}
}

func TestModelUsageCountsCallsPerModelOnce(t *testing.T) {
	ts, st := newTestServer(t)
	now := time.Now().UnixMilli()
	mk := func(id, model, agent, ses string, dec event.Action, extra map[string]any) {
		f := map[string]any{"model": model}
		for k, v := range extra {
			f[k] = v
		}
		if err := st.Append(&event.Event{TS: now - 1000, Layer: "L4", Kind: event.KindIntent, Type: "tool_use", Agent: agent, Session: ses, Decision: dec, Fields: f}); err != nil {
			t.Fatal(err)
		}
	}
	mk("1", "claude-sonnet", "claude-code", "zs_a", event.ActionAllow, nil)
	mk("2", "claude-sonnet", "claude-code", "zs_a", event.ActionBlock, nil)
	mk("3", "claude-sonnet", "claude-code", "zs_b", event.ActionAllow, map[string]any{"reused_from": "x"}) // hook re-audit: not a second call
	mk("4", "gemini-2.5-pro", "gemini-cli", "zs_c", event.ActionAllow, nil)
	var rows []store.ModelUse
	if get(t, ts, "/api/model-usage?range=24h", &rows); len(rows) != 2 {
		t.Fatalf("%+v", rows)
	}
	if rows[0].Model != "claude-sonnet" || rows[0].Calls != 2 || rows[0].Blocked != 1 || rows[0].Sessions != 1 {
		t.Errorf("sonnet: %+v", rows[0])
	}
	if rows[1].Model != "gemini-2.5-pro" || rows[1].Calls != 1 {
		t.Errorf("gemini: %+v", rows[1])
	}
}

func TestGitBranch(t *testing.T) {
	d := t.TempDir()
	_ = os.MkdirAll(filepath.Join(d, ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(d, "sub", "deep"), 0o755)
	_ = os.WriteFile(filepath.Join(d, ".git", "HEAD"), []byte("ref: refs/heads/feature/x\n"), 0o644)
	if got := gitBranch(filepath.Join(d, "sub", "deep")); got != "feature/x" {
		t.Errorf("branch from a subdirectory: %q", got)
	}
	_ = os.WriteFile(filepath.Join(d, ".git", "HEAD"), []byte("0123456789abcdef\n"), 0o644)
	if got := gitBranch(d); got != "0123456 (detached)" {
		t.Errorf("detached: %q", got)
	}
	if gitBranch(t.TempDir()) != "" || gitBranch("") != "" {
		t.Error("not a repository must be empty")
	}
}
