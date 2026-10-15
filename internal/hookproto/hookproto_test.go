package hookproto

import (
	"encoding/json"
	"testing"
)

func TestClaudeCodePayload(t *testing.T) {
	raw := `{"session_id":"s1","transcript_path":"/t","cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"toolu_1"}`
	var in AgentInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	r := Build(in, "", "", "zs_9")
	if r.Agent != "claude-code" || r.Tool != "Bash" || r.ToolCallID != "toolu_1" || r.Phase != "pre" ||
		r.AgentSession != "s1" || r.Session != "zs_9" || r.CWD != "/p" || r.Args["command"] != "ls" {
		t.Errorf("claude request: %+v", r)
	}
	in.HookEventName = "PostToolUse"
	if Build(in, "", "", "").Phase != "post" {
		t.Error("PostToolUse must be the post phase")
	}
}

// The payload the OpenCode plugin writes (adapted from CC-Monitor's plugin).
func TestOpenCodePayload(t *testing.T) {
	raw := `{"hook_event_name":"tool.execute.before","session_id":"ses_1","call_id":"call_7","tool_name":"bash","tool_input":{"command":"rm -rf /"},"cwd":"/work"}`
	var in AgentInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	r := Build(in, "opencode", "pre", "")
	if r.Agent != "opencode" || r.Tool != "bash" || r.ToolCallID != "call_7" || r.Phase != "pre" || r.AgentSession != "ses_1" {
		t.Errorf("opencode request: %+v", r)
	}
	in.HookEventName = "tool.execute.after"
	if got := Build(in, "opencode", "", "").Phase; got != "post" {
		t.Errorf("tool.execute.after without an explicit mode must be post, got %s", got)
	}
}

func TestExplicitModeBeatsEventName(t *testing.T) {
	if Phase("post", "PreToolUse") != "post" || Phase("pre", "tool.execute.after") != "pre" {
		t.Error("the explicit mode argument must win")
	}
	if Phase("", "") != "pre" {
		t.Error("unknown events default to pre (the blocking phase)")
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		args        []string
		mode, agent string
	}{
		{nil, "", ""},
		{[]string{"pre", "--agent", "opencode"}, "pre", "opencode"},
		{[]string{"--agent=codex", "post"}, "post", "codex"},
		{[]string{"--agent"}, "", ""}, // dangling flag: ignored, never a crash
	}
	for _, c := range cases {
		if m, a := ParseArgs(c.args); m != c.mode || a != c.agent {
			t.Errorf("%v -> (%q,%q) want (%q,%q)", c.args, m, a, c.mode, c.agent)
		}
	}
}

// The same JSON must decode identically on both sides of the socket.
func TestRequestRoundTrip(t *testing.T) {
	in := Request{Agent: "opencode", Session: "zs_1", AgentSession: "a", ToolCallID: "c", Tool: "bash", Args: map[string]any{"x": 1.0}, CWD: "/p", Phase: "pre"}
	b, _ := json.Marshal(in)
	var out Request
	if err := json.Unmarshal(b, &out); err != nil || out.ToolCallID != "c" || out.Phase != "pre" || out.Agent != "opencode" {
		t.Errorf("round trip: %+v %v", out, err)
	}
}
