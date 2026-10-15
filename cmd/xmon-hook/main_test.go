//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xmonitor/internal/hookproto"
)

// gateway starts a fake hook gateway on a Unix socket and returns the requests it
// receives. The socket lives in a short temp dir (Unix socket paths are length-limited).
func gateway(t *testing.T, reply hookproto.Response) (home string, got chan hookproto.Request) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "hook.sock"))
	if err != nil {
		t.Skip("cannot listen on a unix socket:", err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan hookproto.Request, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var r hookproto.Request
			_ = json.NewDecoder(c).Decode(&r)
			got <- r
			_ = json.NewEncoder(c).Encode(reply)
			c.Close()
		}
	}()
	return dir, got
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const opencodePre = `{"hook_event_name":"tool.execute.before","session_id":"ses_1","call_id":"call_7","tool_name":"bash","tool_input":{"command":"rm -rf /"},"cwd":"/work"}`

func TestOpenCodeBlockedCallExitsWithTwo(t *testing.T) {
	home, got := gateway(t, hookproto.Response{Allowed: false, Message: "[X-Monitor] blocked: dangerous_delete"})
	var stderr bytes.Buffer
	code := run([]string{"pre", "--agent", "opencode"}, strings.NewReader(opencodePre), &stderr, env(map[string]string{"XMON_HOME": home, "XMON_SESSION": "zs_5"}))
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (the opencode plugin throws on 2)", code)
	}
	if !strings.Contains(stderr.String(), "dangerous_delete") {
		t.Errorf("the reason must reach stderr (it becomes the thrown error shown to the model): %q", stderr.String())
	}
	r := <-got
	if r.Agent != "opencode" || r.Tool != "bash" || r.ToolCallID != "call_7" || r.Session != "zs_5" || r.Phase != "pre" || r.Args["command"] != "rm -rf /" {
		t.Errorf("what the gateway received: %+v", r)
	}
}

func TestAllowedCallExitsZero(t *testing.T) {
	home, _ := gateway(t, hookproto.Response{Allowed: true})
	var stderr bytes.Buffer
	if code := run([]string{"pre", "--agent", "opencode"}, strings.NewReader(opencodePre), &stderr, env(map[string]string{"XMON_HOME": home})); code != 0 || stderr.Len() != 0 {
		t.Errorf("exit=%d stderr=%q", code, stderr.String())
	}
}

func TestPostPhaseNeverBlocks(t *testing.T) {
	home, got := gateway(t, hookproto.Response{Allowed: false, Message: "ignored"})
	post := strings.Replace(opencodePre, "tool.execute.before", "tool.execute.after", 1)
	if code := run([]string{"--agent", "opencode"}, strings.NewReader(post), &bytes.Buffer{}, env(map[string]string{"XMON_HOME": home})); code != 0 {
		t.Errorf("a post-phase call must never block, exit=%d", code)
	}
	if r := <-got; r.Phase != "post" {
		t.Errorf("phase=%s", r.Phase)
	}
}

func TestClaudeCodeStillWorksWithoutFlags(t *testing.T) {
	home, got := gateway(t, hookproto.Response{Allowed: true})
	claude := `{"session_id":"s","cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"toolu_1"}`
	if code := run(nil, strings.NewReader(claude), &bytes.Buffer{}, env(map[string]string{"XMON_HOME": home})); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if r := <-got; r.Agent != "claude-code" || r.ToolCallID != "toolu_1" {
		t.Errorf("claude request: %+v", r)
	}
}

func TestDaemonDownFailsOpenUnlessStrict(t *testing.T) {
	dir := t.TempDir() // no socket in it
	var stderr bytes.Buffer
	if code := run([]string{"pre"}, strings.NewReader(opencodePre), &stderr, env(map[string]string{"XMON_HOME": dir})); code != 0 {
		t.Errorf("an unreachable daemon must not break the agent, exit=%d", code)
	}
	if code := run([]string{"pre"}, strings.NewReader(opencodePre), &stderr, env(map[string]string{"XMON_HOME": dir, "XMON_STRICT": "1"})); code != 2 {
		t.Errorf("strict mode must deny when the daemon is down, exit=%d", code)
	}
	if code := run([]string{"post"}, strings.NewReader(opencodePre), &stderr, env(map[string]string{"XMON_HOME": dir, "XMON_STRICT": "1"})); code != 0 {
		t.Errorf("strict mode applies to the pre phase only, exit=%d", code)
	}
}

func TestGarbageInputNeverBreaksTheAgent(t *testing.T) {
	if code := run([]string{"pre"}, strings.NewReader("not json at all"), &bytes.Buffer{}, env(nil)); code != 0 {
		t.Errorf("exit=%d", code)
	}
}
