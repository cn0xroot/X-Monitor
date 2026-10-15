//go:build linux

package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The helper process applies Landlock to itself, then tries two writes. The
// parent can't apply Landlock to the test binary without restricting later
// tests, so the check runs in a child (the standard Go helper-process pattern).
func TestLandlockHelper(t *testing.T) {
	if os.Getenv("XMON_LL_HELPER") != "1" {
		t.Skip("helper process only")
	}
	allowed, denied := os.Getenv("LL_ALLOWED"), os.Getenv("LL_DENIED")
	if err := Apply([]string{allowed}); err != nil {
		os.Stdout.WriteString("APPLY_ERR " + err.Error() + "\n")
		os.Exit(3)
	}
	if err := os.WriteFile(filepath.Join(allowed, "ok"), []byte("x"), 0o600); err != nil {
		os.Stdout.WriteString("ALLOWED_FAILED " + err.Error() + "\n")
		os.Exit(4)
	}
	if err := os.WriteFile(filepath.Join(denied, "no"), []byte("x"), 0o600); err == nil {
		os.Stdout.WriteString("DENIED_SUCCEEDED\n")
		os.Exit(5)
	}
	os.Stdout.WriteString("OK\n")
	os.Exit(0)
}

func TestLandlockRestrictsWrites(t *testing.T) {
	if ok, why := Available(); !ok {
		t.Skip(why)
	}
	allowed, denied := t.TempDir(), t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestLandlockHelper")
	cmd.Env = append(os.Environ(), "XMON_LL_HELPER=1", "LL_ALLOWED="+allowed, "LL_DENIED="+denied)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(denied, "no")); err == nil {
		t.Fatal("write outside the allowed root succeeded")
	}
}
