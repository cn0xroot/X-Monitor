//go:build !windows

package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/ctlproto"
	"xmonitor/internal/proctree"
	"xmonitor/internal/rules"
	"xmonitor/internal/store"
)

// call sends one control request through handleControl exactly as the CLI would
// (a JSON line over a stream) and returns the decoded reply.
func call(t *testing.T, st *store.Store, tr *proctree.Tracker, cmd string, args any) map[string]any {
	t.Helper()
	re, err := rules.New("")
	if err != nil {
		t.Fatal(err)
	}
	b := approval.New(st, func() time.Duration { return time.Second }, nil)
	d := &daemon{cfg: config.Default(), following: map[string]bool{}}
	client, server := net.Pipe()
	go handleControl(server, d, st, b, re, tr)
	raw, _ := json.Marshal(args)
	if err := json.NewEncoder(client).Encode(map[string]any{"cmd": cmd, "args": json.RawMessage(raw)}); err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	if err := json.NewDecoder(client).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	client.Close()
	return reply
}

// Regression: the root pid sent by `xmon run` must reach the session table and
// the process-tree tracker. It used to be silently dropped (key spelling), which
// left every event unattributed to its session.
func TestRegisterSessionBindsRootPID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XMON_HOME", dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tr := proctree.New(proctree.DefaultLister(), time.Second)

	reg := ctlproto.RegisterSession{ID: "zs_test", Agent: "codex", CWD: "/p/app", Argv: []string{"sh"}, StartedAt: 1000}
	if r := call(t, st, tr, "register_session", reg); r["ok"] != true {
		t.Fatalf("first registration: %v", r)
	}
	reg.RootPID = 31337
	if r := call(t, st, tr, "register_session", reg); r["ok"] != true {
		t.Fatalf("second registration: %v", r)
	}

	ss, err := st.GetSession("zs_test")
	if err != nil || ss == nil {
		t.Fatalf("session not stored: %v", err)
	}
	if ss.RootPID != 31337 {
		t.Fatalf("root_pid=%d, want 31337 (it was being dropped)", ss.RootPID)
	}
	if ss.Agent != "codex" || ss.CWD != "/p/app" || ss.StartedAt != 1000 {
		t.Errorf("session fields: %+v", ss)
	}
	if info, ok := tr.Lookup(31337); !ok || info.Session != "zs_test" || info.Agent != "codex" {
		t.Errorf("tracker was not told about the root pid: %+v ok=%v", info, ok)
	}
}

func TestRegisterSessionRejectsMisspelledFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XMON_HOME", dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tr := proctree.New(proctree.DefaultLister(), time.Second)

	// the exact shape the CLI used to send
	old := map[string]any{"ID": "zs_old", "Agent": "x", "RootPID": 99}
	r := call(t, st, tr, "register_session", old)
	if r["ok"] != false || r["error"] == "" {
		t.Fatalf("a request with unknown fields must be rejected with an error, got %v", r)
	}
	if ss, _ := st.GetSession("zs_old"); ss != nil {
		t.Error("a rejected request must not create a session")
	}
}
