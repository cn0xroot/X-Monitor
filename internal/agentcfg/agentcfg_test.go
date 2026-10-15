package agentcfg

import (
	"os"
	"strings"
	"testing"
)

func TestInstallOpencodeIsIdempotentAndDetected(t *testing.T) {
	home := t.TempDir()
	if HookInstalled("opencode", home) {
		t.Fatal("nothing installed yet")
	}
	p, changed, err := InstallOpencode(home, "/opt/x mon/xmon-hook")
	if err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"/opt/x mon/xmon-hook"`) || strings.Contains(string(b), hookPlaceholder) {
		t.Fatalf("hook path not rendered:\n%s", b)
	}
	if !HookInstalled("opencode", home) {
		t.Fatal("must be detected after install")
	}
	if _, changed, _ := InstallOpencode(home, "/opt/x mon/xmon-hook"); changed {
		t.Fatal("second install must not rewrite")
	}
	if _, changed, _ := InstallOpencode(home, "/other/xmon-hook"); !changed {
		t.Fatal("a moved binary must update the plugin")
	}
}

func TestWindowsPathIsEscaped(t *testing.T) {
	if !strings.Contains(OpencodePluginSource(`C:\x\xmon-hook.exe`), `"C:\\x\\xmon-hook.exe"`) {
		t.Fatal("backslashes must be escaped inside the JS string")
	}
}

func TestClaudeDetection(t *testing.T) {
	home := t.TempDir()
	if HookInstalled("claude-code", home) {
		t.Fatal("no settings yet")
	}
	_ = os.MkdirAll(home+"/.claude", 0o755)
	_ = os.WriteFile(ClaudeSettingsPath(home), []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"/b/xmon-hook"}]}]}}`), 0o644)
	if !HookInstalled("claude-code", home) || HookInstalled("aider", home) {
		t.Fatal("detection wrong")
	}
}

func TestPluginParses(t *testing.T) {
	// the template must at least be valid for the placeholder replacement
	if strings.Count(opencodePlugin, hookPlaceholder) != 1 {
		t.Fatal("exactly one placeholder expected")
	}
}
