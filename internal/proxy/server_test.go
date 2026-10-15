package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"time"
	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/decide"
	"xmonitor/internal/gate"
	"xmonitor/internal/rules"

	"xmonitor/internal/store"
)

func newGate(t *testing.T) *gate.Gate {
	t.Helper()
	re, err := rules.New("")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	d := decide.New(re, nil, st, func() *config.Config { return cfg })
	b := approval.New(st, func() time.Duration { return time.Second }, nil)
	return gate.New(d, b, st, func() *config.Config { return cfg })
}

const dangerSSE = `event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"cleaning up"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_9","name":"Bash"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf $HOME\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}

`

func TestProxyEndToEndBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, dangerSSE)
	}))
	defer upstream.Close()

	g := newGate(t)
	cfg := config.Default()
	cfg.Proxy.Routes["anthropic"] = upstream.URL
	px := New(g, func() *config.Config { return cfg })
	px.Resolve = func(string) (string, string, bool) { return "claude-code", "s1", true }

	ps := httptest.NewServer(px.Handler())
	defer ps.Close()

	resp, err := http.Post(ps.URL+"/p/anthropic/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude","messages":[{"role":"user","content":"clean"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	out := string(body)

	// The command may appear inside the human-readable block message; what must
	// NOT survive is an executable tool_use block or its argument delta.
	if strings.Contains(out, `"type":"tool_use"`) || strings.Contains(out, "input_json_delta") {
		t.Errorf("dangerous tool_use reached the agent:\n%s", out)
	}
	if !strings.Contains(out, "X-Monitor") || !strings.Contains(out, "dangerous_delete") {
		t.Errorf("expected block message with rule:\n%s", out)
	}
	if !strings.Contains(out, "cleaning up") {
		t.Errorf("leading text should pass through:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Errorf("stop_reason should be end_turn:\n%s", out)
	}

	// The block must be audited.
	evs, _ := g.St.ListEvents(store.Query{Limit: 10})
	found := false
	for _, e := range evs {
		if e.Rule == "dangerous_delete" && e.Decision == "block" {
			found = true
			if e.Fields["model"] != "claude" {
				t.Errorf("the audited call must record the model the agent asked for: %v", e.Fields)
			}
		}
	}
	if !found {
		t.Errorf("block not found in audit log: %+v", evs)
	}
}

func TestProxyAllowsSafeCall(t *testing.T) {
	safe := strings.ReplaceAll(dangerSSE, "Bash", "Read")
	safe = strings.ReplaceAll(safe, `rm -rf $HOME`, "")
	safe = strings.ReplaceAll(safe, `\"command\":\"\"`, `\"path\":\"README.md\"`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, safe)
	}))
	defer upstream.Close()
	g := newGate(t)
	cfg := config.Default()
	cfg.Proxy.Routes["anthropic"] = upstream.URL
	px := New(g, func() *config.Config { return cfg })
	px.Resolve = func(string) (string, string, bool) { return "claude-code", "s2", true }
	ps := httptest.NewServer(px.Handler())
	defer ps.Close()
	resp, _ := http.Post(ps.URL+"/p/anthropic/v1/messages", "application/json", strings.NewReader(`{"messages":[]}`))
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"type":"tool_use"`) {
		t.Errorf("safe Read tool_use should pass through:\n%s", string(body))
	}
}

func TestModelFromPath(t *testing.T) {
	for in, want := range map[string]string{
		"v1beta/models/gemini-2.5-pro:streamGenerateContent": "gemini-2.5-pro",
		"v1/models/gemini-flash:generateContent?alt=sse":     "gemini-flash",
		"v1/messages": "",
	} {
		if got := modelFromPath(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
