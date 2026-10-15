package rules

// Regression tests ported from cc-monitor tests/test_rules.py and
// tests/test_workdir.py (MIT License), plus X-Monitor additions.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"xmonitor/internal/shellparse"
	"xmonitor/internal/toolclass"
	"xmonitor/internal/workdir"
)

// macOS resolves /home through an autofs symlink into /System, so the
// fixtures use /Users there (the real home parent on macOS).
func fix(s string) string {
	if runtime.GOOS == "darwin" {
		return strings.ReplaceAll(s, "/home/", "/Users/")
	}
	return s
}

var cwd = fix("/home/alice/proj")

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func call(tool string, cwd string, kv ...string) toolclass.Call {
	args := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		args[kv[i]] = fix(kv[i+1])
	}
	c := toolclass.Normalize("t1", tool, args)[0]
	c.CWD = cwd
	return c
}

func ruleID(e *Engine, tool string, kv ...string) string {
	m := e.Evaluate(call(tool, "", kv...))
	if m == nil {
		return ""
	}
	return m.Rule.ID
}

func ruleIDCwd(e *Engine, tool string, kv ...string) string {
	m := e.Evaluate(call(tool, cwd, kv...))
	if m == nil {
		return ""
	}
	return m.Rule.ID
}

func TestAllDefaultRulesCompile(t *testing.T) {
	var raw []map[string]any
	e := engine(t)
	_ = raw
	if n := len(e.Rules()); n < 90 {
		t.Fatalf("expected >=90 rules to compile, got %d", n)
	}
	for _, r := range e.Rules() {
		if r.Title == "" || r.Desc == "" || r.TitleEn == "" || r.DescEn == "" {
			t.Errorf("%s missing title/desc", r.ID)
		}
	}
}

func TestSystemPackageInstall(t *testing.T) {
	e := engine(t)
	hits := []string{
		"sudo port install wget", "port install wget", "sudo port -N install python312",
		"sudo port -v -N install git +universal", "sudo port -D /opt/local install foo",
		"sudo port --debug install foo", "sudo /opt/local/bin/port install wget",
		"sudo port selfupdate && sudo port upgrade outdated", "sudo port sync", "sudo -H port install git",
		"port -f uninstall foo", "echo wget | xargs sudo port install",
		`osascript -e 'do shell script "port install wget" with administrator privileges'`,
		"brew install wget", "sudo apt-get install -y curl", "sudo pacman -Syu",
	}
	for _, c := range hits {
		if got := ruleID(e, "Bash", "command", c); got != "system_package_install" {
			t.Errorf("%q: got %q", c, got)
		}
	}
	misses := []string{"port installed", "port search wget", "port info wget", "which port",
		"lsof -i :8080 | grep port", "python3 report.py --port 8080"}
	for _, c := range misses {
		if got := ruleID(e, "Bash", "command", c); got == "system_package_install" {
			t.Errorf("%q: unexpected hit", c)
		}
	}
}

func TestSegmentMatch(t *testing.T) {
	e := engine(t)
	install := map[string]bool{"system_package_install": true, "package_install_other": true, "npm_global_install": true,
		"npm_local_install": true, "sudo_usage": true, "sudo_pip_install": true, "pip_install_no_venv": true,
		"su_pkexec_privilege_escalation": true}
	fps := []string{
		`grep -n "port install" cc_monitor/default_rules.json`,
		`grep -rn "apt-get install" docs/ | head`,
		`echo "brew install wget"`,
		`echo "run: sudo apt install curl" >> README.md`,
		"python3 - <<'EOF'\nprint(\"sudo apt install foo\")\nx = \"a && sudo rm\"\nEOF",
		`git commit -m "docs: mention brew install step"`,
		`sqlite3 db "SELECT * FROM events WHERE detail LIKE '%port install%'"`,
		"cat <<EOF > notes.txt\nnpm install -g foo\nEOF",
		`grep "npm install" package.json`,
		"git commit -m 'sudo pip install docs'",
		"echo 'sudo' | cat",
		"ls | grep su",
	}
	for _, c := range fps {
		if got := ruleID(e, "Bash", "command", c); install[got] {
			t.Errorf("false positive %q -> %s", c, got)
		}
	}
	tps := map[string]string{
		"sudo apt install -y curl":                                   "system_package_install",
		"sudo apt-get update && sudo apt-get install -y curl":        "system_package_install",
		"brew install wget":                                          "system_package_install",
		"HOMEBREW_NO_AUTO_UPDATE=1 brew install wget":                "system_package_install",
		"(cd /tmp && brew install wget)":                             "system_package_install",
		"bash -c 'sudo apt-get install -y curl'":                     "system_package_install",
		`sudo sh -c "apt-get install -y curl"`:                       "system_package_install",
		"bash -lc 'apt-get install -y curl'":                         "system_package_install", // Codex style
		"echo wget | xargs sudo port install":                        "system_package_install",
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y curl": "system_package_install",
		"/usr/bin/apt-get install -y curl":                           "system_package_install",
		"time sudo port -N install python312":                        "system_package_install",
		"sudo -H port install git":                                   "system_package_install",
		"npm install -g cowsay":                                      "npm_global_install",
		"cd proj && npm install":                                     "npm_local_install",
		"cargo install ripgrep":                                      "package_install_other",
		"gem install bundler":                                        "package_install_other",
		"cd /tmp; sudo make install":                                 "sudo_usage",
		"sudo pip install x":                                         "sudo_pip_install",
		"sudo python3 -m pip install x":                              "sudo_pip_install",
		"pip install uv":                                             "pip_install_no_venv",
		"source .venv/bin/activate && pip install x":                 "pip_install_venv_context",
		"su -":      "su_pkexec_privilege_escalation",
		"pkexec ls": "su_pkexec_privilege_escalation",
	}
	for c, want := range tps {
		if got := ruleID(e, "Bash", "command", c); got != want {
			t.Errorf("%q: got %q want %q", c, got, want)
		}
	}
	m := e.Evaluate(call("Bash", "", "command", "cd /tmp && sudo apt-get install -y curl | tail -1"))
	if m == nil || m.Rule.ID != "system_package_install" || m.Value != "apt-get install -y curl" {
		t.Errorf("matched value: %+v", m)
	}
}

func TestSplitRespectsQuotesAndHeredocs(t *testing.T) {
	segs := shellparse.SplitSegments("echo 'a; b' && cat <<EOF\nx | y\nEOF\n; ls")
	var got []string
	for _, s := range segs {
		if s = trim(s); s != "" {
			got = append(got, s)
		}
	}
	want := []string{"echo 'a; b'", "cat <<EOF\nx | y\nEOF", "ls"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q", got)
		}
	}
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func TestHistoryRead(t *testing.T) {
	e := engine(t)
	for _, c := range []string{
		"cat ~/.zsh_history", "tail -n 50 ~/.zsh_history | grep AWS",
		`python3 -c "open('/Users/me/.zsh_history').read()"`, "wc -l < ~/.zsh_history",
		"grep -i token $HISTFILE", "cat ~/.zsh_sessions/*.history", "cat ~/.claude/history.jsonl",
		"history | tail -20", "cd /tmp && history", "fc -l -50", "fc -ln 1",
	} {
		if got := ruleID(e, "Bash", "command", c); got != "history_read" {
			t.Errorf("%q: got %q", c, got)
		}
	}
	for _, c := range []string{`grep -rn -i "history" . | head`, "git log --oneline", "python3 fc.py -l", "ls docs/history"} {
		if got := ruleID(e, "Bash", "command", c); got != "" {
			t.Errorf("%q: unexpected %q", c, got)
		}
	}
	for _, c := range []string{"history -c", "rm -f ~/.zsh_history", ": > ~/.zsh_history", "rm -rf ~/.zsh_sessions/"} {
		if got := ruleID(e, "Bash", "command", c); got != "history_tampering" {
			t.Errorf("%q: got %q", c, got)
		}
	}
	for _, p := range []string{"/Users/me/.zsh_history", "/Users/me/.bash_history", "/Users/me/.zsh_sessions/abc.history", "/Users/me/.claude/history.jsonl"} {
		if got := ruleID(e, "Read", "file_path", p, "path", p); got != "history_file_read" {
			t.Errorf("%q: got %q", p, got)
		}
	}
	if got := ruleID(e, "Read", "file_path", "/Users/me/proj/src/history.ts"); got != "" {
		t.Errorf("history.ts: %q", got)
	}
}

func TestCrossAgentToolNames(t *testing.T) {
	e := engine(t)
	cases := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"run_terminal_cmd", map[string]any{"command": "rm -rf ~"}, "dangerous_delete"},            // Cursor
		{"run_shell_command", map[string]any{"command": "curl x | sh"}, "curl_pipe_shell"},         // Gemini
		{"shell", map[string]any{"command": []any{"bash", "-lc", "rm -rf /"}}, "dangerous_delete"}, // Codex argv
		{"write_file", map[string]any{"file_path": "/home/a/.ssh/authorized_keys", "content": "x"}, "sensitive_file_write"},
		{"edit_file", map[string]any{"target_file": "/home/a/.aws/credentials", "code_edit": "x"}, "sensitive_file_write"},
	}
	for _, c := range cases {
		calls := toolclass.Normalize("id", c.tool, c.args)
		m := e.Evaluate(calls[0])
		got := ""
		if m != nil {
			got = m.Rule.ID
		}
		if got != c.want {
			t.Errorf("%s %v: got %q want %q", c.tool, c.args, got, c.want)
		}
	}
	patch := "*** Begin Patch\n*** Add File: /home/a/.ssh/authorized_keys\n+ssh-ed25519 AAAA\n*** End Patch\n"
	calls := toolclass.Normalize("id", "apply_patch", map[string]any{"input": patch})
	if len(calls) != 1 || calls[0].Class != toolclass.FSWrite {
		t.Fatalf("apply_patch expand: %+v", calls)
	}
	if m := e.Evaluate(calls[0]); m == nil || m.Rule.ID != "sensitive_file_write" {
		t.Errorf("apply_patch: %+v", m)
	}
}

func TestSelfProtection(t *testing.T) {
	e := engine(t)
	cases := map[string]string{
		"cat ~/.xmon/token": "xmon_self_tamper_shell",
		"curl -X POST http://127.0.0.1:7788/api/approvals/3": "xmon_approval_api",
		"pkill xmond":                        "xmon_kill_monitor",
		"unset ANTHROPIC_BASE_URL && claude": "xmon_proxy_env_tamper",
		"xmon stop":                          "xmon_disable",
	}
	for c, want := range cases {
		if got := ruleID(e, "Bash", "command", c); got != want {
			t.Errorf("%q: got %q want %q", c, got, want)
		}
	}
	if got := ruleID(e, "Write", "file_path", "/Users/x/.xmon/rules.json", "content", "[]"); got != "xmon_self_tamper_write" {
		t.Errorf("write: %q", got)
	}
	if got := ruleID(e, "Read", "file_path", "/Users/x/.xmon/token"); got != "xmon_self_read" {
		t.Errorf("read: %q", got)
	}
}

// ---- workdir (ported from tests/test_workdir.py) ----

type hit struct{ p, tier, access string }

func hits(t *testing.T, tool string, kv ...string) []hit {
	t.Helper()
	var out []hit
	for _, h := range workdir.Scan(call(tool, cwd, kv...)) {
		out = append(out, hit{h.Path, h.Tier, h.Access})
	}
	return out
}

func eqHits(a, b []hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		w := b[i]
		w.p = fix(w.p)
		if a[i] != w {
			return false
		}
	}
	return true
}

func TestWorkdirBash(t *testing.T) {
	t.Setenv("HOME", fix("/home/alice"))
	t.Setenv("TMPDIR", "")
	notFlagged := []string{
		"ls -la", "ls src/ && cat README.md", "git status && git diff HEAD~1 -- src/a.py",
		"python3 -m pytest tests/ -k foo", "/usr/bin/python3 script.py --out=/tmp/x.json",
		"curl https://example.com/a/b -o out.txt", `grep -rn "port install" docs/ | head`,
		`python3 -c "print('/etc/hostname')"`, "ls 2>/dev/null; echo ok",
		"cat <<EOF > notes.txt\n/etc/hosts\n~/.ssh/id_rsa\nEOF", "sed 's/a/b/' src/x.txt", "echo $FOO/bar",
		"cd src && ls ../tests",
		`echo "##### /service 与 /etc/sv 的关系"; ls -la service/drmlog | head -2`,
		"SP=/tmp/scratch; ./scripts/run.sh > $SP/out.txt 2>&1 <<'EOF'\ncat /var/log/x\nEOF",
		"ls /usr/lib/x86_64-linux-gnu | grep libxcb", "cat /usr/include/xcb/xcb.h", "ls ~/.cache/puppeteer", "file /bin/ls",
		"ln -sf /usr/lib/libxcb.so.0 /tmp/build/usr/lib/libxcb.so",
		"cd /tmp/build && ln -sf /usr/lib/libxcb.so.0 usr/lib/libxcb.so",
	}
	for _, c := range notFlagged {
		if h := hits(t, "Bash", "command", c); len(h) != 0 {
			t.Errorf("%q flagged: %v", c, h)
		}
	}
	cases := map[string][]hit{
		"cp x.so /usr/lib/x86_64-linux-gnu/x.so":      {{"/usr/lib/x86_64-linux-gnu/x.so", "system", "write"}},
		"echo x > ~/.cache/foo":                       {{"/home/alice/.cache/foo", "homeDotfile", "write"}},
		"cat /etc/hosts":                              {{"/etc/hosts", "system", "read"}},
		"cat ~/.npmrc":                                {{"/home/alice/.npmrc", "homeDotfile", "read"}},
		"cat $HOME/.npmrc":                            {{"/home/alice/.npmrc", "homeDotfile", "read"}},
		"git -C ../sibling status":                    {{"/home/alice/sibling", "otherProject", "read"}},
		"diff a.txt ../sibling/a.txt":                 {{"/home/alice/sibling/a.txt", "otherProject", "read"}},
		"cat /home/bob/notes.txt":                     {{"/home/bob/notes.txt", "otherUserHome", "read"}},
		"echo x > ~/.config/foo/bar.toml":             {{"/home/alice/.config/foo/bar.toml", "homeDotfile", "write"}},
		"echo x >> /etc/hosts":                        {{"/etc/hosts", "system", "write"}},
		"sudo tee /etc/hosts <<EOF\n127.0.0.1 x\nEOF": {{"/etc/hosts", "system", "write"}},
		"cp build/a.tgz /home/bob/a.tgz":              {{"/home/bob/a.tgz", "otherUserHome", "write"}},
		"cp ../other/a.txt ./a.txt":                   {{"/home/alice/other/a.txt", "otherProject", "read"}},
		"cp /etc/hosts hosts.bak":                     {{"/etc/hosts", "system", "read"}},
		"bash -c 'rm -rf ~/.cache/foo'":               {{"/home/alice/.cache/foo", "homeDotfile", "write"}},
		"sed -i 's/a/b/' /opt/app/conf.ini":           {{"/opt/app/conf.ini", "system", "write"}},
		"tar -xzf a.tgz -C /opt/app":                  {{"/opt/app", "system", "write"}},
		"mkdir -p /root/.ssh":                         {{"/root/.ssh", "otherUserHome", "write"}},
		"git clone https://x/y.git ../y":              {{"/home/alice/y", "otherProject", "write"}},
		"rsync -a dist/ /data/www/":                   {{"/data/www", "otherProject", "write"}},
		"cat ~/.npmrc; echo x > ~/.npmrc":             {{"/home/alice/.npmrc", "homeDotfile", "write"}},
		"cd .. && rm -rf other-proj/dist": {
			{"/home/alice", "otherProject", "read"},
			{"/home/alice/other-proj/dist", "otherProject", "write"},
		},
	}
	for c, want := range cases {
		if got := hits(t, "Bash", "command", c); !eqHits(got, want) {
			t.Errorf("%q: got %v want %v", c, got, want)
		}
	}
	if got := hits(t, "Read", "file_path", "/home/alice/.claude/projects/-x/memory/MEMORY.md"); len(got) != 0 {
		t.Errorf("claude state: %v", got)
	}
	if got := hits(t, "Write", "file_path", "~/.config/foo.toml", "content", "x"); !eqHits(got, []hit{{"/home/alice/.config/foo.toml", "homeDotfile", "write"}}) {
		t.Errorf("write ~: %v", got)
	}
}

func TestWorkdirRules(t *testing.T) {
	t.Setenv("HOME", fix("/home/alice"))
	t.Setenv("TMPDIR", "")
	e := engine(t)
	cases := []struct {
		tool string
		kv   []string
		want string
	}{
		{"Bash", []string{"command", "echo x > ~/.config/foo.toml"}, "workdir_escape_write_sensitive"},
		{"Bash", []string{"command", "mkdir -p /root/.ssh"}, "workdir_escape_write_sensitive"},
		{"Write", []string{"file_path", "/home/alice/other/x.py", "content", "x"}, "workdir_escape_write_other"},
		{"Bash", []string{"command", "cat ~/.npmrc"}, "workdir_escape_read_sensitive"},
		{"Bash", []string{"command", "cat /etc/os-release"}, "workdir_escape_read_other"},
		{"Read", []string{"file_path", "/home/alice/other/README.md"}, "workdir_escape_read_other"},
		{"Read", []string{"file_path", "/home/alice/proj/README.md"}, ""},
		{"Bash", []string{"command", "ls -la"}, ""},
		{"Bash", []string{"command", "cat ~/.ssh/config"}, "sensitive_file_read_bash"},
		{"Write", []string{"file_path", "/home/alice/.ssh/authorized_keys", "content", "x"}, "sensitive_file_write"},
	}
	for _, c := range cases {
		if got := ruleIDCwd(e, c.tool, c.kv...); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.tool, c.kv, got, c.want)
		}
	}
	m := e.Evaluate(call("Bash", cwd, "command", "cp a.txt ~/other/a.txt; cp b.txt ~/other/b.txt"))
	if m == nil || m.Rule.ID != "workdir_escape_write_other" || m.Value != "~/other/a.txt, ~/other/b.txt" {
		t.Errorf("value: %+v", m)
	}
	if got := ruleID(e, "Bash", "command", "cat /etc/os-release"); got != "" {
		t.Errorf("no cwd: %q", got)
	}
}

func TestProjectRootFromSubdir(t *testing.T) {
	base := t.TempDir()
	proj := filepath.Join(base, "proj")
	os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	os.MkdirAll(filepath.Join(proj, "webui", "public"), 0o755)
	t.Setenv("HOME", base)
	if got := workdir.ProjectRoot(filepath.Join(proj, "webui", "public")); got != proj {
		t.Errorf("got %s", got)
	}
}

func TestUserRulesMergeAndHotReload(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rules.json")); err != nil {
		t.Fatal("rules.json not created")
	}
	if got := ruleID(e, "Bash", "command", "rm -rf ~"); got != "dangerous_delete" {
		t.Fatalf("got %q", got)
	}
	// User replaces everything with a single custom rule; defaults deleted by
	// the user must not come back on the next merge (they are in the snapshot).
	custom := `[{"id":"only","risk":"low","action":"log","title":"t","desc":"d","title_en":"t","desc_en":"d","classes":["exec.shell"],"field":"command","pattern":"^echo"}]`
	os.WriteFile(filepath.Join(dir, "rules.json"), []byte(custom), 0o600)
	e2, _ := New(dir)
	if got := ruleID(e2, "Bash", "command", "echo hi"); got != "only" {
		t.Errorf("custom rule: %q", got)
	}
	if got := ruleID(e2, "Bash", "command", "rm -rf ~"); got != "" {
		t.Errorf("deleted default came back: %q", got)
	}
}

func TestOpencodeConfigTamper(t *testing.T) {
	e := engine(t)
	for _, p := range []string{
		"/home/a/proj/opencode.json", "/home/a/proj/opencode.jsonc",
		"/home/a/proj/.opencode/plugins/x.js", "/home/a/.config/opencode/plugins/xmon.js",
	} {
		if got := ruleID(e, "write", "filePath", p, "content", "x"); got != "claude_config_tamper" {
			t.Errorf("write %s: got %q", p, got)
		}
	}
	for _, p := range []string{"/home/a/proj/docs/opencode.md", "/home/a/proj/my-opencode.json.txt"} {
		if got := ruleID(e, "write", "filePath", p, "content", "x"); got == "claude_config_tamper" {
			t.Errorf("write %s must not be flagged as config tampering", p)
		}
	}
}
