// Package agents recognizes AI coding agents by process name / exe / argv,
// macOS bundle id, Electron helper-process family, and LLM API host. It covers
// CLIs, GUI desktop clients (IDEs, Electron apps) and IDE plugins, and reports
// how deeply each can be intercepted (DESIGN.md §9.1, §16/§7 degradation).
package agents

import (
	"regexp"
	"strings"
)

// Kind classifies how the agent runs — this drives interception strategy.
type Kind string

const (
	KindCLI    Kind = "cli"    // terminal program; env-var base URL + optional hooks
	KindGUI    Kind = "gui"    // desktop/Electron app; usually config-file or proxy only
	KindPlugin Kind = "plugin" // IDE extension hosted by an editor process
)

// Intercept is the best interception mode expected for this agent.
type Intercept string

const (
	// InterceptEnv: honors *_BASE_URL env vars → full L4 via `xmon run` (mode A).
	InterceptEnv Intercept = "env"
	// InterceptConfig: no env var, but a config file can point it at the proxy.
	InterceptConfig Intercept = "config"
	// InterceptProxy: only reachable via system proxy + selective MITM (mode B/C).
	InterceptProxy Intercept = "proxy"
	// InterceptObserve: cert-pinned or private protocol — L4 unavailable; rely on
	// L1/L2/L3 observation only (no request-level block).
	InterceptObserve Intercept = "observe"
)

// Status says how far interception support for an agent has been verified.
type Status string

const (
	// StatusVerified: interception has been exercised against the real agent.
	StatusVerified Status = "verified"
	// StatusExperimental: signatures and protocol handling follow the agent's
	// documented behavior (and CC-Monitor's definitions) but are not verified
	// against the real client end to end.
	StatusExperimental Status = "experimental"
)

// HookKind names the native per-tool-call hook mechanism X-Monitor can install.
type HookKind string

const (
	HookNone     HookKind = ""
	HookClaude   HookKind = "claude-hooks"    // ~/.claude/settings.json PreToolUse / PostToolUse
	HookOpenCode HookKind = "opencode-plugin" // ~/.config/opencode/plugins/xmon.js
)

// Agent is one recognized AI coding agent.
type Agent struct {
	ID        string
	Display   string
	Kind      Kind
	Hooks     bool      // native per-tool-call hook support (L4b)
	Intercept Intercept // best achievable L4 interception
	Status    Status
	HookKind  HookKind
}

// signature is how one agent is recognized. Written with named fields so adding
// a signature can't silently shift a value into the wrong column.
type signature struct {
	Agent
	comms      []string         // exact short process names (case-insensitive)
	commPrefix []string         // process-name prefixes (e.g. codex-x86_64-…)
	exes       []string         // exact executable basenames
	exeSubstr  []string         // substrings of the executable path (Electron helpers, npm wrappers)
	bundleIDs  []string         // macOS bundle identifiers
	argvRE     []*regexp.Regexp // command-line patterns, tried only for interpreter-hosted processes
	apiHosts   []string         // LLM API hosts for reverse attribution
}

func res(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

var sigs = []signature{
	// ---- CLIs (env-var base URL, best interception) ----
	// Process names, exe basenames and argv patterns follow CC-Monitor's agent
	// definitions (MIT; see NOTICE), checked against processes on a real host.
	{Agent: Agent{ID: "claude-code", Display: "Claude Code", Kind: KindCLI, Hooks: true, Intercept: InterceptEnv, Status: StatusVerified, HookKind: HookClaude},
		comms: []string{"claude", "claude-code"}, exes: []string{"claude"},
		apiHosts: []string{"api.anthropic.com", "api.z.ai"}},
	{Agent: Agent{ID: "opencode", Display: "OpenCode", Kind: KindCLI, Hooks: true, Intercept: InterceptConfig, Status: StatusExperimental, HookKind: HookOpenCode},
		// `opencode` is the TUI; the npm wrapper also leaves a long-running
		// `…/@opencode/cli/bin/opencode.exe serve` service process.
		comms: []string{"opencode"}, exes: []string{"opencode", "opencode.exe"}, exeSubstr: []string{"@opencode/cli"},
		argvRE: res(`(^|/)opencode( |$)`, `opencode-ai`)},
	{Agent: Agent{ID: "codex", Display: "Codex CLI", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"codex"}, commPrefix: []string{"codex-x86_64", "codex-aarch64"},
		exes:     []string{"codex", "codex-x86_64-unknown-linux-musl", "codex-aarch64-unknown-linux-musl", "codex-aarch64-apple-darwin", "codex-x86_64-apple-darwin"},
		argvRE:   res(`@openai/codex`, `(^|/)codex( |$)`, `codex-(x86_64|aarch64)-(unknown-linux|apple-darwin)`),
		apiHosts: []string{"api.openai.com"}},
	{Agent: Agent{ID: "cursor-agent", Display: "Cursor Agent (CLI)", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"cursor-agent"}, exes: []string{"cursor-agent"}, argvRE: res(`(^|/)cursor-agent( |$)`),
		apiHosts: []string{"api.cursor.sh", "api2.cursor.sh"}},
	{Agent: Agent{ID: "gemini-cli", Display: "Gemini CLI", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"gemini"}, exes: []string{"gemini"}, argvRE: res(`@google/gemini-cli`, `(^|/)gemini(\.js)?( |$)`),
		apiHosts: []string{"generativelanguage.googleapis.com", "api.z.ai"}},
	{Agent: Agent{ID: "grok-cli", Display: "Grok CLI", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"grok"}, exes: []string{"grok"}, argvRE: res(`(^|/)grok( |$)`, `grok-dev`, `grok-cli/dist`),
		apiHosts: []string{"api.x.ai"}},
	{Agent: Agent{ID: "aider", Display: "Aider", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		exes: []string{"aider"}, argvRE: res(`(^|/)aider( |$)`, `aider/main\.py`, `-m aider`),
		apiHosts: []string{"api.openai.com", "api.anthropic.com", "api.z.ai"}},
	{Agent: Agent{ID: "antigravity-cli", Display: "Antigravity CLI", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"agy"}, exes: []string{"agy", "antigravity-cli"}, argvRE: res(`(^|/)agy( |$)`, `antigravity-cli`)},
	{Agent: Agent{ID: "openclacky", Display: "OpenClacky", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"OpenClacky", "openclacky", "clacky"}, exes: []string{"OpenClacky", "openclacky", "clacky"},
		exeSubstr: []string{"OpenClacky.app/Contents/MacOS/OpenClacky"},
		argvRE:    res(`(^|/)openclacky( |$)`, `(^|/)clacky( |$)`, `gems/openclacky-[0-9]`)},
	{Agent: Agent{ID: "zcode", Display: "ZCode", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"zcode", "ZCode"}, exes: []string{"zcode", "ZCode", "zcode-cli"}, exeSubstr: []string{"/ZCode.app/"},
		argvRE:   res(`(^|/)ZCode(\.app|-[^ ]*\.AppImage)?( |$)`, `/resources/glm/`, `@zcode/`, `(^|/)zcode( |$)`),
		apiHosts: []string{"api.z.ai"}},
	{Agent: Agent{ID: "glm-cli", Display: "GLM CLI", Kind: KindCLI, Intercept: InterceptEnv, Status: StatusExperimental},
		comms: []string{"glm-cli", "glm"}, exes: []string{"glm-cli"}, apiHosts: []string{"api.z.ai", "open.bigmodel.cn"}},
	{Agent: Agent{ID: "copilot-cli", Display: "GitHub Copilot CLI", Kind: KindCLI, Intercept: InterceptObserve, Status: StatusExperimental},
		comms: []string{"copilot", "gh-copilot"}, exes: []string{"copilot"}, apiHosts: []string{"api.githubcopilot.com"}},

	// ---- GUI desktop clients (Electron / native IDE) ----
	// Cursor IDE: has a user-configurable OpenAI base URL → config injection.
	{Agent: Agent{ID: "cursor-app", Display: "Cursor (IDE)", Kind: KindGUI, Intercept: InterceptConfig, Status: StatusExperimental},
		comms: []string{"Cursor"}, exeSubstr: []string{"/Cursor.app/", "Cursor Helper"}, bundleIDs: []string{"com.todesktop.230313mzl4w4u92"},
		apiHosts: []string{"api.cursor.sh", "api2.cursor.sh", "api.anthropic.com", "api.openai.com"}},
	{Agent: Agent{ID: "windsurf", Display: "Windsurf", Kind: KindGUI, Intercept: InterceptObserve, Status: StatusExperimental},
		comms: []string{"Windsurf"}, exeSubstr: []string{"/Windsurf.app/", "Windsurf Helper"}, bundleIDs: []string{"com.exafunction.windsurf"},
		apiHosts: []string{"server.codeium.com", "inference.codeium.com"}},
	// VS Code + Copilot/other AI extensions (Electron). The editor hosts plugins.
	{Agent: Agent{ID: "vscode", Display: "VS Code (AI 扩展)", Kind: KindGUI, Intercept: InterceptProxy, Status: StatusExperimental},
		comms: []string{"Code", "Code - Insiders"}, exeSubstr: []string{"/Visual Studio Code.app/", "Code Helper"}, bundleIDs: []string{"com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"},
		apiHosts: []string{"api.githubcopilot.com", "api.individual.githubcopilot.com", "api.enterprise.githubcopilot.com"}},
	{Agent: Agent{ID: "trae", Display: "Trae", Kind: KindGUI, Intercept: InterceptObserve, Status: StatusExperimental},
		comms: []string{"Trae"}, exeSubstr: []string{"/Trae.app/", "Trae Helper"}, bundleIDs: []string{"com.trae.app"}},
	// Claude Desktop (Electron). The bare process name "Claude" collides with
	// the "claude" CLI once lower-cased, so it is identified by bundle id and
	// app-path fragment only, never by comm.
	{Agent: Agent{ID: "claude-desktop", Display: "Claude Desktop", Kind: KindGUI, Intercept: InterceptProxy, Status: StatusExperimental},
		exeSubstr: []string{"/Claude.app/", "Claude Helper"}, bundleIDs: []string{"com.anthropic.claudefordesktop", "com.anthropic.claude"}},
	// JetBrains IDEs with AI Assistant / Junie (JVM).
	{Agent: Agent{ID: "jetbrains-ai", Display: "JetBrains AI", Kind: KindGUI, Intercept: InterceptProxy, Status: StatusExperimental},
		comms:     []string{"idea", "pycharm", "goland", "webstorm", "clion", "rider", "phpstorm", "rubymine"},
		exeSubstr: []string{"/IntelliJ IDEA.app/", "/PyCharm.app/", "/GoLand.app/", "/WebStorm.app/", "/CLion.app/", "/PhpStorm.app/", "/Rider.app/", "/RubyMine.app/"}, bundleIDs: []string{"com.jetbrains.intellij", "com.jetbrains.pycharm"},
		apiHosts: []string{"api.jetbrains.ai", "api.anthropic.com", "api.openai.com"}},

	// ---- IDE plugins (hosted inside an editor; identified via host + argv) ----
	// CodeGeeX ships both a CLI/server and IDE plugins.
	{Agent: Agent{ID: "codegeex", Display: "CodeGeeX", Kind: KindPlugin, Intercept: InterceptConfig, Status: StatusExperimental},
		comms: []string{"codegeex", "codegeex-server"}, exes: []string{"codegeex"}, exeSubstr: []string{"codegeex"},
		argvRE: res(`codegeex.*(agent|server)\.js`), apiHosts: []string{"codegeex.cn", "api.z.ai"}},
}

// interpreters host CLIs written in scripting languages: for these, the process
// name says nothing about the agent, so the command line is consulted.
var interpreters = map[string]bool{
	"node": true, "nodejs": true, "bun": true, "deno": true, "python": true, "python3": true,
	"uv": true, "ruby": true, "java": true,
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

var byComm = func() map[string]*Agent {
	m := map[string]*Agent{}
	for i := range sigs {
		for _, c := range sigs[i].comms {
			m[lower(c)] = &sigs[i].Agent
		}
		for _, e := range sigs[i].exes {
			m[lower(e)] = &sigs[i].Agent
		}
	}
	return m
}()

var byID = func() map[string]*Agent {
	m := map[string]*Agent{}
	for i := range sigs {
		m[sigs[i].ID] = &sigs[i].Agent
	}
	return m
}()

func basename(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// Match returns the recognized agent for a process, or nil. comm is the short
// process name, exe the executable path, argv the full command line. Order:
// exact name → executable basename → name prefix → path fragment (Electron
// helpers, npm wrappers) → command-line pattern (interpreter-hosted CLIs only,
// so that a command merely mentioning ".../claude" is never mistaken for one).
func Match(comm, exe, argv string) *Agent {
	if a, ok := byComm[lower(comm)]; ok {
		return a
	}
	if exe != "" {
		if a, ok := byComm[lower(basename(exe))]; ok {
			return a
		}
	}
	lc := lower(basename(comm))
	for i := range sigs {
		for _, p := range sigs[i].commPrefix {
			if p != "" && strings.HasPrefix(lc, lower(p)) {
				return &sigs[i].Agent
			}
		}
	}
	// Executable-path fragments: Electron helpers ("Cursor Helper (Renderer)"),
	// npm wrappers (".../@opencode/cli/bin/opencode.exe"). Matched against the
	// executable path and the first word of the command line, not the whole
	// argv: an argument that merely names a path must not identify the process.
	hay := lower(exe + " " + firstWord(argv) + " " + comm)
	for i := range sigs {
		for _, frag := range sigs[i].exeSubstr {
			if frag != "" && strings.Contains(hay, lower(frag)) {
				return &sigs[i].Agent
			}
		}
	}
	if interpreters[lc] || interpreters[lower(basename(firstWord(argv)))] {
		for i := range sigs {
			for _, re := range sigs[i].argvRE {
				if re.MatchString(argv) {
					return &sigs[i].Agent
				}
			}
		}
	}
	return nil
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// MatchBundle returns the agent for a macOS bundle identifier, or nil.
func MatchBundle(bundleID string) *Agent {
	b := lower(bundleID)
	if b == "" {
		return nil
	}
	for i := range sigs {
		for _, id := range sigs[i].bundleIDs {
			if lower(id) == b {
				return &sigs[i].Agent
			}
		}
	}
	return nil
}

// MatchByHost returns the agent whose API hosts include host (reverse lookup
// from an observed LLM connection). This is the primary passive-discovery path
// for GUI clients that we did not launch via `xmon run` (DESIGN.md §9.1).
func MatchByHost(host string) *Agent {
	host = lower(host)
	if host == "" {
		return nil
	}
	for i := range sigs {
		for _, h := range sigs[i].apiHosts {
			if strings.Contains(host, h) {
				return &sigs[i].Agent
			}
		}
	}
	return nil
}

// ByID returns the agent definition for an id, or nil.
func ByID(id string) *Agent { return byID[id] }

// Display returns a human label for an agent id.
func Display(id string) string {
	if a := byID[id]; a != nil {
		return a.Display
	}
	return id
}

// Capability describes the best interception for an agent and why it may be
// degraded, for the dashboard's per-target labeling (DESIGN.md §16, §7).
type Capability struct {
	Agent     string    `json:"agent"`
	Display   string    `json:"display"`
	Kind      Kind      `json:"kind"`
	Intercept Intercept `json:"intercept"`
	Hooks     bool      `json:"hooks"`
	Status    Status    `json:"status"` // verified / experimental
	// Layers that apply regardless of L4 availability.
	Observe bool   `json:"observe"` // L1/L2/L3 always available
	Note    string `json:"note"`
	NoteEn  string `json:"note_en"`
}

// CapabilityOf reports the interception capability for an agent id.
func CapabilityOf(id string) Capability {
	a := byID[id]
	if a == nil {
		return Capability{Agent: id, Display: id, Kind: KindCLI, Intercept: InterceptObserve, Observe: true, Status: StatusExperimental,
			Note:   "未知 Agent:仅进程树/文件/内核层观测,无语义级拦截",
			NoteEn: "Unknown agent: observed only via process tree / file / kernel layers; no semantic-level blocking"}
	}
	c := Capability{Agent: a.ID, Display: a.Display, Kind: a.Kind, Intercept: a.Intercept, Hooks: a.Hooks, Status: a.Status, Observe: true}
	if a.HookKind == HookOpenCode {
		// OpenCode picks its API endpoint from provider settings in opencode.json, not from a
		// BASE_URL variable, so xmon run cannot redirect it on its own. The plugin is the way in.
		c.Note = "可事前拦截每次工具调用:xmon install --agent opencode 装原生 Hook 插件(装完需重启 opencode)。经代理需在 opencode.json 的 provider 里把 baseURL 指向本机代理,未经验证"
		c.NoteEn = "Every tool call can be blocked beforehand: xmon install --agent opencode installs the native hook plugin (restart opencode afterwards). Going through the proxy needs the provider baseURL in opencode.json pointed at the local proxy, which is unverified"
		return c
	}
	switch a.Intercept {
	case InterceptEnv:
		c.Note = "完整拦截:xmon run 注入 BASE_URL,代理可事前阻断每次工具调用"
		c.NoteEn = "Full interception: xmon run injects BASE_URL, so the proxy can block every tool call before it runs"
		if a.Hooks {
			c.Note += ";并支持原生 Hook"
			c.NoteEn += "; native hooks are also supported"
		}
	case InterceptConfig:
		c.Note = "可拦截:需用 xmon install 改应用配置指向本机代理,然后可事前阻断"
		c.NoteEn = "Interceptable: run xmon install to point the app's config at the local proxy, after which calls can be blocked before they run"
	case InterceptProxy:
		c.Note = "有限拦截:仅能经系统代理+MITM;若该客户端固定证书或忽略代理则退为观测"
		c.NoteEn = "Limited interception: only via system proxy + MITM; falls back to observe-only if the client pins certificates or ignores the proxy"
	case InterceptObserve:
		c.Note = "观测为主:证书固定/私有协议,L4 不可用,依赖进程树/文件/内核层事件,无请求级事前阻断"
		c.NoteEn = "Observe-only: certificate pinning / private protocol makes L4 unavailable; relies on process tree / file / kernel-layer events, with no request-level pre-execution blocking"
	}
	return c
}

// AllCapabilities lists capability for every known agent (dashboard reference).
func AllCapabilities() []Capability {
	out := make([]Capability, 0, len(sigs))
	for i := range sigs {
		out = append(out, CapabilityOf(sigs[i].ID))
	}
	return out
}
