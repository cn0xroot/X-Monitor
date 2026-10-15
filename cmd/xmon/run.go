package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"xmonitor/internal/config"
	"xmonitor/internal/ctlproto"
	"xmonitor/internal/enforce"
)

// agentProfile describes how to launch and intercept one agent.
type agentProfile struct {
	id       string
	provider string            // proxy route for its LLM traffic
	envBase  string            // the BASE_URL env var it honors
	extra    map[string]string // additional env
}

var profiles = map[string]agentProfile{
	"claude-code": {"claude-code", "anthropic", "ANTHROPIC_BASE_URL", nil},
	"claude":      {"claude-code", "anthropic", "ANTHROPIC_BASE_URL", nil},
	"codex":       {"codex", "openai", "OPENAI_BASE_URL", nil},
	"cursor":      {"cursor", "openai", "OPENAI_BASE_URL", nil},
	// Gemini CLI (and the Z.ai CLI, which is Gemini CLI) speaks Google's
	// generateContent protocol; it honors GOOGLE_GEMINI_BASE_URL.
	"gemini":   {"gemini-cli", "zai-gemini", "GOOGLE_GEMINI_BASE_URL", map[string]string{"GEMINI_BASE_URL": ""}},
	"zai":      {"gemini-cli", "zai-gemini", "GOOGLE_GEMINI_BASE_URL", map[string]string{"GEMINI_BASE_URL": ""}},
	"glm":      {"glm-cli", "zai", "OPENAI_BASE_URL", nil},
	"codegeex": {"codegeex", "zai", "OPENAI_BASE_URL", nil},
	"aider":    {"aider", "openai", "OPENAI_BASE_URL", nil},
}

// cmdRun launches an agent with the proxy/hook environment injected.
func cmdRun(args []string) error {
	agentID := ""
	sandbox := false
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--sandbox":
			sandbox = true
			i++
		case "--agent":
			if i+1 >= len(args) {
				return fmt.Errorf("--agent needs a value")
			}
			agentID = args[i+1]
			i += 2
		case "--":
			i++
			goto rest
		default:
			goto rest
		}
	}
rest:
	cmdv := args[i:]
	if len(cmdv) == 0 {
		return fmt.Errorf("usage: xmon run [--agent X] [--sandbox] -- <command...>")
	}
	if agentID == "" {
		agentID = filepath.Base(cmdv[0])
	}
	prof, ok := profiles[agentID]
	if !ok {
		prof = agentProfile{id: agentID, provider: "openai", envBase: "OPENAI_BASE_URL"}
		fmt.Fprintf(os.Stderr, "xmon: unknown agent %q, assuming OpenAI-compatible; override with --agent\n", agentID)
	}

	if !daemonRunning() {
		if err := cmdStart(nil); err != nil {
			return fmt.Errorf("could not start daemon: %w", err)
		}
	}

	cfg, _ := config.Load()
	session := "zs_" + randID()

	// Register the session; root PID is filled in after exec.
	startedAt := time.Now().UnixMilli()
	reg := ctlproto.RegisterSession{ID: session, Agent: prof.id, CWD: mustGetwd(), Argv: cmdv, StartedAt: startedAt}
	if err := registerSession(reg); err != nil {
		return fmt.Errorf("could not register the session with xmond: %w", err)
	}

	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) }
	proxyBase := fmt.Sprintf("http://%s/p/%s", cfg.ProxyAddr, prof.provider)
	set(prof.envBase, proxyBase)
	set("XMON_SESSION", session)
	set("XMON_AGENT", prof.id)
	for k, v := range prof.extra {
		if v == "" { // empty means "same proxy base" (secondary env var alias)
			v = proxyBase
		}
		set(k, v)
	}

	bin, err := exec.LookPath(cmdv[0])
	if err != nil {
		return fmt.Errorf("agent not found: %s", cmdv[0])
	}
	argv := append([]string{bin}, cmdv[1:]...)
	if sandbox {
		// Fail closed: asking for a sandbox and silently running without one
		// would be worse than not starting.
		wrapped, err := wrapSandbox(argv)
		if err != nil {
			return fmt.Errorf("--sandbox: %w", err)
		}
		argv = wrapped
		fmt.Fprintf(os.Stderr, "xmon: kernel sandbox active (%s); edit %s to adjust\n",
			enforce.Tier, enforce.Path(config.Home()))
	}
	runBin, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(runBin, argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	fmt.Fprintf(os.Stderr, "xmon: monitoring %s (session %s) via %s\n", prof.id, session, proxyBase)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Now that we have the PID, update the session's root PID for proxy
	// attribution (DESIGN.md §7.2).
	reg.RootPID = cmd.Process.Pid
	if err := registerSession(reg); err != nil {
		// The agent is already running; without its root pid events can't be
		// attributed to this session. Say so rather than pretend all is well.
		fmt.Fprintf(os.Stderr, "xmon: warning: events will not be attributed to this session: %v\n", err)
	}

	// Forward signals to the child.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigc {
			_ = cmd.Process.Signal(s)
		}
	}()

	code := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	_ = ctl("end_session", map[string]any{"ID": session, "Code": code}, nil)
	os.Exit(code)
	return nil
}

func randID() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func mustGetwd() string {
	d, _ := os.Getwd()
	return d
}

var _ = strings.TrimSpace

// registerSession sends the session to xmond and surfaces a rejection.
func registerSession(r ctlproto.RegisterSession) error {
	var reply struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := ctl("register_session", r, &reply); err != nil {
		return err
	}
	if !reply.OK {
		if reply.Error == "" {
			reply.Error = "rejected"
		}
		return fmt.Errorf("%s", reply.Error)
	}
	return nil
}
