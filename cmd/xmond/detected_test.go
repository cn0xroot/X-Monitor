package main

import (
	"os"
	"testing"

	"xmonitor/internal/agentcfg"
	"xmonitor/internal/proctree"
)

func TestBuildDetected(t *testing.T) {
	home := t.TempDir()
	snap := []proctree.Running{
		{Agent: "opencode", PID: 10, Comm: "opencode", Children: 1},
		{Agent: "codex", PID: 20, Comm: "codex"},
		{Agent: "claude-code", PID: 30, Comm: "claude", Managed: true, Session: "zs_1"},
	}
	got := buildDetected(snap, home, func(a string) int { return map[string]int{"opencode": 7}[a] }, nil)
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	oc := got[0]
	if oc.Managed || !oc.HookCapable || oc.HookReady || oc.Action != "xmon install --agent opencode" || oc.Events != 7 || oc.Status != "experimental" {
		t.Fatalf("opencode before install: %+v", oc)
	}
	if got[1].HookCapable || got[1].Action != "xmon run --agent codex -- <command>" {
		t.Fatalf("codex has no native hook, must be told to use xmon run: %+v", got[1])
	}
	if got[2].Action != "" || !got[2].Managed {
		t.Fatalf("a managed agent needs no action: %+v", got[2])
	}

	if _, _, err := agentcfg.InstallOpencode(home, "/b/xmon-hook"); err != nil {
		t.Fatal(err)
	}
	_ = os.Stdout
	oc = buildDetected(snap[:1], home, nil, func(string) bool { return false })[0]
	if !oc.HookReady || oc.HookSeen || oc.Action != "" {
		t.Fatalf("installed but never seen: the plugin is not loaded yet: %+v", oc)
	}
	oc = buildDetected(snap[:1], home, nil, func(a string) bool { return a == "opencode" })[0]
	if !oc.HookSeen {
		t.Fatalf("a hook event proves the agent loaded the plugin: %+v", oc)
	}
	if got := buildDetected(snap[1:2], home, nil, func(string) bool { return true })[0]; got.HookSeen {
		t.Fatalf("an agent without a hook can never be hook-guarded: %+v", got)
	}
}
