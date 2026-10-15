// Package agentcfg installs and detects X-Monitor's native hooks in the
// configuration of the AI agents it knows how to hook.
package agentcfg

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed opencode_plugin.js
var opencodePlugin string

const hookPlaceholder = "__XMON_HOOK_BIN__"

// OpencodePluginPath is where the plugin lives for a given home directory.
func OpencodePluginPath(home string) string {
	return filepath.Join(home, ".config", "opencode", "plugins", "xmon.js")
}

// ClaudeSettingsPath is Claude Code's user settings file.
func ClaudeSettingsPath(home string) string {
	return filepath.Join(home, ".claude", "settings.json")
}

// OpencodePluginSource renders the plugin for a hook binary path.
func OpencodePluginSource(hookBin string) string {
	// The path is embedded as a JS string literal: escape backslashes (Windows) and quotes.
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(hookBin)
	return strings.Replace(opencodePlugin, hookPlaceholder, esc, 1)
}

// InstallOpencode writes the plugin. It is idempotent: it reports whether the
// file changed. OpenCode loads plugins at startup, so a running instance must
// be restarted.
func InstallOpencode(home, hookBin string) (path string, changed bool, err error) {
	path = OpencodePluginPath(home)
	want := OpencodePluginSource(hookBin)
	if cur, e := os.ReadFile(path); e == nil && string(cur) == want {
		return path, false, nil
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	if err = os.WriteFile(path, []byte(want), 0o644); err != nil {
		return
	}
	return path, true, nil
}

// HookInstalled reports whether X-Monitor's hook is configured for an agent.
// Agents without a hook integration always report false.
func HookInstalled(agentID, home string) bool {
	switch agentID {
	case "claude-code":
		b, err := os.ReadFile(ClaudeSettingsPath(home))
		return err == nil && strings.Contains(string(b), "xmon-hook")
	case "opencode":
		b, err := os.ReadFile(OpencodePluginPath(home))
		return err == nil && strings.Contains(string(b), "XmonPlugin")
	}
	return false
}

// InstallHint tells a user how to get coverage for an agent.
func InstallHint(agentID string) string {
	switch agentID {
	case "claude-code", "opencode":
		return fmt.Sprintf("xmon install --agent %s", agentID)
	}
	return ""
}
