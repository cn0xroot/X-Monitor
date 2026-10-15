package config

import (
	"os"
	"strings"
	"testing"
)

func TestSaveModeKeepsOtherKeysAndDefaults(t *testing.T) {
	t.Setenv("XMON_HOME", t.TempDir())

	// No file yet: only the mode is written, nothing else gets frozen.
	if err := SaveMode(ModePaused); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(ConfigPath())
	if got := strings.TrimSpace(string(b)); got != "mode: paused" {
		t.Fatalf("new file = %q", got)
	}
	c, err := Load()
	if err != nil || c.Mode != ModePaused || !c.Usage.AnthropicEnabled {
		t.Fatalf("load: %+v err=%v", c, err)
	}

	// Existing file: the user's keys and comments survive, the mode is replaced.
	src := "# mine\nmode: active\nusage:\n  anthropic_enabled: false # off on purpose\n"
	if err := os.WriteFile(ConfigPath(), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveMode(ModeStopped); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(ConfigPath())
	for _, want := range []string{"# mine", "mode: stopped", "anthropic_enabled: false", "# off on purpose"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in:\n%s", want, b)
		}
	}
	if c, _ := Load(); c.Mode != ModeStopped || c.Usage.AnthropicEnabled {
		t.Fatalf("load after update: %+v", c)
	}
}
