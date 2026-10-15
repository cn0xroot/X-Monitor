package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"xmonitor/internal/agentcfg"
)

// cmdInstall registers the native hook for an agent (currently Claude Code) and
// prints the environment for proxy interception. It never runs the agent; use
// `xmon run` for that, or source the printed env for global interception.
func cmdInstall(args []string) error {
	agent := "claude-code"
	for i := 0; i < len(args); i++ {
		if args[i] == "--agent" && i+1 < len(args) {
			agent = args[i+1]
		}
	}
	switch agent {
	case "claude-code", "claude":
		return installClaudeHook()
	case "opencode":
		return installOpencodeHook()
	default:
		fmt.Printf("No hook integration for %q yet; use `xmon run --agent %s -- <cmd>` for proxy-based monitoring.\n", agent, agent)
		return nil
	}
}

// installClaudeHook adds PreToolUse/PostToolUse hooks to ~/.claude/settings.json
// pointing at the xmon-hook binary, merging with any existing hooks.
func installClaudeHook() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	hookBin := filepath.Join(filepath.Dir(self), "xmon-hook")
	if _, err := os.Stat(hookBin); err != nil {
		return fmt.Errorf("xmon-hook not found next to xmon (build it first)")
	}
	home, _ := os.UserHomeDir()
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	settings := map[string]any{}
	if b, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(b, &settings)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	entry := func() []any {
		return []any{map[string]any{
			"matcher": "*",
			"hooks":   []any{map[string]any{"type": "command", "command": hookBin}},
		}}
	}
	for _, ev := range []string{"PreToolUse", "PostToolUse"} {
		if !hasZmonHook(hooks[ev], hookBin) {
			existing, _ := hooks[ev].([]any)
			hooks[ev] = append(existing, entry()...)
		}
	}
	settings["hooks"] = hooks

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(settings, "", "  ")
	if err := os.WriteFile(settingsPath, out, 0o644); err != nil {
		return err
	}
	fmt.Printf("Installed Claude Code hooks in %s\n", settingsPath)
	fmt.Println("Start the daemon with `xmon start`. Hooks take effect on the next Claude Code session.")
	fmt.Println("For proxy-based LLM interception too, run Claude Code via `xmon run -- claude`.")
	return nil
}

func hasZmonHook(v any, bin string) bool {
	arr, _ := v.([]any)
	for _, item := range arr {
		m, _ := item.(map[string]any)
		hs, _ := m["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if c, _ := hm["command"].(string); c == bin {
				return true
			}
		}
	}
	return false
}

// installOpencodeHook writes the X-Monitor plugin into ~/.config/opencode/plugins.
func installOpencodeHook() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	hookBin := filepath.Join(filepath.Dir(self), "xmon-hook")
	if _, err := os.Stat(hookBin); err != nil {
		return fmt.Errorf("xmon-hook not found next to xmon (build it first)")
	}
	home, _ := os.UserHomeDir()
	path, changed, err := agentcfg.InstallOpencode(home, hookBin)
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("Installed OpenCode plugin: %s\n", path)
	} else {
		fmt.Printf("OpenCode plugin already up to date: %s\n", path)
	}
	fmt.Println("OpenCode loads plugins at startup: restart any running opencode for it to take effect.")
	return nil
}
