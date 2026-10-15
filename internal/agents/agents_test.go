package agents

import (
	"strings"
	"testing"
)

func TestMatchCLIAndGUI(t *testing.T) {
	cases := []struct {
		name, comm, exe, argv, want string
	}{
		{"claude cli", "claude", "/usr/local/bin/claude", "claude", "claude-code"},
		{"codex host", "node", "/usr/bin/node", "node /usr/lib/node_modules/@openai/codex/bin/codex.js", "codex"},
		{"cursor helper", "Cursor Helper (Renderer)", "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Renderer).app/Contents/MacOS/Cursor Helper (Renderer)", "", "cursor-app"},
		{"vscode helper", "Code Helper", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper", "", "vscode"},
		{"windsurf ls", "language_server", "/Applications/Windsurf.app/Contents/Resources/app/bin/language_server_macos_arm", "", "windsurf"},
		{"unknown", "firefox", "/usr/bin/firefox", "firefox", ""},
	}
	for _, c := range cases {
		got := ""
		if a := Match(c.comm, c.exe, c.argv); a != nil {
			got = a.ID
		}
		if got != c.want {
			t.Errorf("%s: Match=%q want %q", c.name, got, c.want)
		}
	}
}

func TestMatchBundle(t *testing.T) {
	if a := MatchBundle("com.todesktop.230313mzl4w4u92"); a == nil || a.ID != "cursor-app" {
		t.Errorf("cursor bundle: %v", a)
	}
	if a := MatchBundle("com.anthropic.claudefordesktop"); a == nil || a.ID != "claude-desktop" {
		t.Errorf("claude desktop bundle: %v", a)
	}
	if a := MatchBundle("com.unknown.app"); a != nil {
		t.Errorf("unknown bundle matched: %v", a)
	}
}

func TestMatchByHost(t *testing.T) {
	cases := map[string]string{
		"api.anthropic.com":                 "claude-code", // first sig owning the host
		"api.githubcopilot.com":             "copilot-cli", // host shared by CLI+IDE: first match wins, PID disambiguates
		"server.codeium.com":                "windsurf",
		"generativelanguage.googleapis.com": "gemini-cli",
		"example.com":                       "",
	}
	for host, want := range cases {
		got := ""
		if a := MatchByHost(host); a != nil {
			got = a.ID
		}
		if got != want {
			t.Errorf("host %s: got %q want %q", host, got, want)
		}
	}
}

func TestCapabilityDegradation(t *testing.T) {
	// CLI with env base url → full interception.
	if c := CapabilityOf("claude-code"); c.Intercept != InterceptEnv || !c.Hooks {
		t.Errorf("claude-code cap: %+v", c)
	}
	// GUI cert-pinned → observe only, no request-level block.
	if c := CapabilityOf("windsurf"); c.Intercept != InterceptObserve || c.Kind != KindGUI {
		t.Errorf("windsurf cap: %+v", c)
	}
	// Cursor IDE → config injection possible.
	if c := CapabilityOf("cursor-app"); c.Intercept != InterceptConfig {
		t.Errorf("cursor-app cap: %+v", c)
	}
	// Unknown → observe, with a note.
	if c := CapabilityOf("nope"); c.Intercept != InterceptObserve || c.Note == "" {
		t.Errorf("unknown cap: %+v", c)
	}
	if len(AllCapabilities()) < 10 {
		t.Error("expected capability list for all agents")
	}
}

func TestCapabilityNoteEn(t *testing.T) {
	for _, c := range AllCapabilities() {
		if c.Note == "" || c.NoteEn == "" {
			t.Errorf("%s: Note/NoteEn must be non-empty (intercept=%s)", c.Agent, c.Intercept)
		}
	}
	if CapabilityOf("nope").NoteEn == "" {
		t.Error("unknown agent NoteEn empty")
	}
	if c := CapabilityOf("claude-code"); c.Hooks && !strings.Contains(c.NoteEn, "hooks") {
		t.Errorf("hook suffix missing: %s", c.NoteEn)
	}
}

// Process shapes taken from a real host that was running OpenCode and Claude Code.
func TestRealHostProcessShapes(t *testing.T) {
	cases := []struct{ name, comm, exe, argv, want string }{
		{"opencode TUI", "opencode", "opencode", "opencode", "opencode"},
		{"opencode npm wrapper service", "opencode.exe", "/opt/homebrew/lib/node_modules/@opencode/cli/bin/opencode.exe", "/opt/homebrew/lib/node_modules/@opencode/cli/bin/opencode.exe serve --service", "opencode"},
		{"claude", "claude", "claude", "claude", "claude-code"},
		// node / python / ruby hosted CLIs are found by their command line
		{"gemini via node", "node", "/usr/local/bin/node", "node /opt/homebrew/lib/node_modules/@google/gemini-cli/dist/index.js", "gemini-cli"},
		{"codex via node", "node", "/usr/local/bin/node", "node /usr/lib/node_modules/@openai/codex/bin/codex.js", "codex"},
		{"opencode via node", "node", "/usr/local/bin/node", "node /usr/lib/node_modules/opencode-ai/bin/opencode", "opencode"},
		{"aider via python", "python3", "/usr/bin/python3", "python3 -m aider --model sonnet", "aider"},
		{"openclacky via ruby", "ruby", "/usr/bin/ruby", "ruby /gems/openclacky-0.9.1/exe/openclacky", "openclacky"},
		{"codex native binary", "codex-aarch64-apple-darwin", "/x/codex-aarch64-apple-darwin", "/x/codex-aarch64-apple-darwin", "codex"},
		{"zcode app", "ZCode", "/Applications/ZCode.app/Contents/MacOS/ZCode", "/Applications/ZCode.app/Contents/MacOS/ZCode", "zcode"},
	}
	for _, c := range cases {
		a := Match(c.comm, c.exe, c.argv)
		if a == nil || a.ID != c.want {
			t.Errorf("%s: got %v want %s", c.name, a, c.want)
		}
	}
}

// Things that merely look like an AI agent must not be reported as one. A false
// positive here means an unrelated process tree gets monitored and labeled.
func TestLookalikesAreNotAgents(t *testing.T) {
	cases := []struct{ name, comm, exe, argv string }{
		{"macOS input UI service named Cursor…", "CursorUIViewService", "/System/Library/PrivateFrameworks/TextInputUIMacHelper.framework/Versions/A/XPCServices/CursorUIViewService.xpc/Contents/MacOS/CursorUIViewService", "CursorUIViewService"},
		{"grep for the word", "grep", "/usr/bin/grep", "grep -r claude /tmp"},
		{"cat of a path ending in /claude", "cat", "/bin/cat", "cat /home/u/.config/claude"},
		{"a script in a folder called ideas", "run.sh", "/Users/x/ideas/run.sh", "/Users/x/ideas/run.sh"},
		{"node running something unrelated", "node", "/usr/local/bin/node", "node server.js --port 3000"},
		{"python running a module whose name merely contains aider", "python3", "/usr/bin/python3", "python3 -m raider --scan"},
		{"vim editing opencode.json", "vim", "/usr/bin/vim", "vim /work/opencode.json"},
		{"tail of a log in a codex dir", "tail", "/usr/bin/tail", "tail -f /var/log/codex/app.log"},
		{"browser helper", "SunBrowser", "/Users/x/SunBrowser.app/Contents/MacOS/SunBrowser", "SunBrowser --force-color-profile=srgb"},
	}
	for _, c := range cases {
		if a := Match(c.comm, c.exe, c.argv); a != nil {
			t.Errorf("%s was reported as %s", c.name, a.ID)
		}
	}
}

func TestStatusAndHookKinds(t *testing.T) {
	if a := ByID("claude-code"); a.Status != StatusVerified || a.HookKind != HookClaude || !a.Hooks {
		t.Errorf("claude-code: %+v", a)
	}
	if a := ByID("opencode"); a.HookKind != HookOpenCode || !a.Hooks || a.Status != StatusExperimental {
		t.Errorf("opencode: %+v", a)
	}
	for _, id := range []string{"codex", "gemini-cli", "grok-cli", "aider", "antigravity-cli", "openclacky", "zcode"} {
		if a := ByID(id); a == nil {
			t.Errorf("%s (defined by CC-Monitor) is missing", id)
		} else if a.Hooks {
			t.Errorf("%s claims native hook support that X-Monitor has not implemented", id)
		}
	}
	for _, c := range AllCapabilities() {
		if c.Hooks && ByID(c.Agent).HookKind == HookNone {
			t.Errorf("%s: Hooks=true requires a HookKind", c.Agent)
		}
	}
}
