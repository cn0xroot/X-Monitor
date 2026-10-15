//go:build darwin

package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// run executes argv under the sandbox for policy p and returns combined output.
func runSandboxed(t *testing.T, p *Policy, proj string, argv ...string) (string, error) {
	t.Helper()
	w, err := Wrap(p, proj, argv)
	if err != nil {
		t.Skip(err)
	}
	out, err := exec.Command(w[0], w[1:]...).CombinedOutput()
	return string(out), err
}

// These tests run the real kernel sandbox (sandbox-exec), so they prove the
// profile actually enforces, not just that it renders.
func TestSandboxEnforcesOnDarwin(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	proj := filepath.Join(base, "proj")
	xm := filepath.Join(home, ".xmon")
	for _, d := range []string{xm, proj, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(xm, "token"), []byte("SECRET"), 0o600)
	p := &Policy{
		DenyWrite: []string{xm, filepath.Join(home, ".ssh")},
		DenyRead:  []string{xm},
		DenyExec:  []string{"/usr/bin/nc"},
	}

	if out, err := runSandboxed(t, p, proj, "/bin/sh", "-c", "echo hi > "+filepath.Join(proj, "ok.txt")); err != nil {
		t.Errorf("write inside project must work: %v\n%s", err, out)
	}
	if out, err := runSandboxed(t, p, proj, "/bin/sh", "-c", "echo x > "+filepath.Join(home, ".ssh", "authorized_keys")); err == nil || !strings.Contains(out, "not permitted") {
		t.Errorf("write into a denied dir must be denied by the sandbox, got err=%v out=%q", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "authorized_keys")); err == nil {
		t.Error("denied write left a file behind")
	}
	if out, err := runSandboxed(t, p, proj, "/bin/cat", filepath.Join(xm, "token")); err == nil || !strings.Contains(out, "not permitted") {
		t.Errorf("reading the token must be denied by the sandbox, got err=%v out=%q", err, out)
	}
	if _, err := runSandboxed(t, p, proj, "/bin/rm", "-rf", xm); err == nil {
		if _, serr := os.Stat(filepath.Join(xm, "token")); serr != nil {
			t.Error("rm -rf of the monitor dir succeeded inside the sandbox")
		}
	}
	if _, err := os.Stat(filepath.Join(xm, "token")); err != nil {
		t.Error("token was deleted despite the sandbox")
	}
	// `nc -h` exits non-zero even unsandboxed, so assert the sandbox's own error.
	if out, err := runSandboxed(t, p, proj, "/usr/bin/nc", "-h"); err == nil || !strings.Contains(out, "not permitted") {
		t.Errorf("denied executable must be refused by the sandbox, got err=%v out=%q", err, out)
	}
}
