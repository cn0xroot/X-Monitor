package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xmonitor/internal/config"
	"xmonitor/internal/enforce"
)

func cmdStart(args []string) error {
	foreground := false
	for _, a := range args {
		if a == "--foreground" || a == "-f" {
			foreground = true
		}
	}
	if daemonRunning() {
		fmt.Println("daemon already running")
		return nil
	}
	if err := config.EnsureHome(); err != nil {
		return err
	}
	bin, err := daemonBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(bin)
	if foreground {
		cmd.Args = append(cmd.Args, "--foreground")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	logf, _ := os.OpenFile(config.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if logf != nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	for i := 0; i < 50; i++ {
		if daemonRunning() {
			fmt.Println("daemon started")
			return cmdStatus()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not become ready; see %s", config.LogPath())
}

// daemonBinary finds xmond next to this executable, else on PATH.
func daemonBinary() (string, error) {
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "xmond")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if p, err := exec.LookPath("xmond"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("xmond binary not found (build it or put it on PATH)")
}

func cmdStop() error {
	b, err := os.ReadFile(config.PIDPath())
	if err != nil {
		return fmt.Errorf("daemon not running")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 0 {
		return fmt.Errorf("bad pid file")
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := signalStop(proc); err != nil {
		return err
	}
	fmt.Println("daemon stopping")
	return nil
}

func cmdStatus() error {
	var r struct {
		OK    bool   `json:"ok"`
		Mode  string `json:"mode"`
		Proxy string `json:"proxy"`
		UI    string `json:"ui"`
		Rules int    `json:"rules"`
		PID   int    `json:"pid"`
	}
	if err := ctl("status", nil, &r); err != nil {
		return err
	}
	fmt.Printf("daemon   running (pid %d)\n", r.PID)
	fmt.Printf("mode     %s\n", r.Mode)
	fmt.Printf("proxy    %s\n", r.Proxy)
	fmt.Printf("ui       http://%s   (运行 xmon ui 获取带令牌的完整地址)\n", r.UI)
	fmt.Printf("rules    %d\n", r.Rules)
	return nil
}

func cmdMode(args []string) error {
	if len(args) == 0 {
		var r map[string]any
		if err := ctl("status", nil, &r); err != nil {
			return err
		}
		fmt.Println("mode:", r["mode"])
		return nil
	}
	m := args[0]
	if m != "active" && m != "paused" && m != "stopped" {
		return fmt.Errorf("mode must be active|paused|stopped")
	}
	return ctl("mode", map[string]string{"Mode": m}, nil)
}

func cmdPending() error {
	var r struct {
		Pending []struct {
			ID      int64  `json:"id"`
			Agent   string `json:"agent"`
			Risk    string `json:"risk"`
			Rule    string `json:"rule"`
			Summary string `json:"summary"`
		} `json:"pending"`
	}
	if err := ctl("pending", nil, &r); err != nil {
		return err
	}
	if len(r.Pending) == 0 {
		fmt.Println("no pending approvals")
		return nil
	}
	for _, a := range r.Pending {
		fmt.Printf("#%d [%s] %s %s\n    %s\n", a.ID, a.Risk, a.Agent, a.Rule, a.Summary)
	}
	return nil
}

func cmdResolve(kind string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xmon %s <id>", kind)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("bad id")
	}
	decision := "allow_once"
	if kind == "deny" {
		decision = "deny"
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := ctl(kind, map[string]any{"ID": id, "Decision": decision}, &r); err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("%s", r.Error)
	}
	fmt.Printf("#%d %sd\n", id, kind)
	return nil
}

func cmdRules(args []string) error {
	if len(args) >= 2 && args[0] == "test" {
		cwd, _ := os.Getwd()
		var r struct {
			Results []map[string]any `json:"results"`
		}
		in := map[string]any{"Tool": "Bash", "Args": map[string]any{"command": args[1]}, "CWD": cwd}
		if err := ctl("test", in, &r); err != nil {
			return err
		}
		for _, res := range r.Results {
			if res["rule"] == nil {
				fmt.Printf("no rule matched (class %v)\n", res["class"])
				continue
			}
			fmt.Printf("rule=%v risk=%v action=%v\n  matched: %v\n", res["rule"], res["risk"], res["action"], res["matched"])
		}
		return nil
	}
	return fmt.Errorf("usage: xmon rules test \"<command>\"")
}

func cmdVerify() error {
	var r struct {
		Verify struct {
			Checked  int64  `json:"checked"`
			OK       bool   `json:"ok"`
			BrokenAt int64  `json:"broken_at"`
			Problem  string `json:"problem"`
		} `json:"verify"`
	}
	if err := ctl("verify", nil, &r); err != nil {
		return err
	}
	v := r.Verify
	if v.Problem != "" {
		return fmt.Errorf("chain broken at seq %d: %s (checked %d)", v.BrokenAt, v.Problem, v.Checked)
	}
	fmt.Printf("audit chain OK (%d events)\n", v.Checked)
	return nil
}

func cmdTail(args []string) error {
	follow := false
	minRisk := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--follow":
			follow = true
		case "--risk":
			if i+1 < len(args) {
				minRisk = args[i+1]
				i++
			}
		}
	}
	return tailEvents(follow, minRisk)
}

func cmdDoctor() error {
	fmt.Println("X-Monitor doctor")
	ok := daemonRunning()
	mark(ok, "daemon reachable")
	if tok, err := config.Token(); err == nil && len(tok) >= 32 {
		mark(true, "UI token present")
	} else {
		mark(false, "UI token missing")
	}
	cfg, _ := config.Load()
	mark(true, fmt.Sprintf("proxy configured at %s", cfg.ProxyAddr))
	if cfg.GLM.Enabled {
		if os.Getenv(cfg.GLM.APIKeyEnv) != "" {
			mark(true, "GLM enabled, API key present")
		} else {
			mark(false, fmt.Sprintf("GLM enabled but %s not set", cfg.GLM.APIKeyEnv))
		}
	} else {
		fmt.Println("  -  GLM disabled (rules-only)")
	}
	for _, a := range []string{"claude", "codex", "cursor-agent", "gemini"} {
		if p, err := exec.LookPath(a); err == nil {
			fmt.Printf("  •  PATH 上发现 CLI：%s (%s)\n", a, p)
		}
	}
	fmt.Println("\n主机上正在运行的 AI：")
	var det struct {
		Detected []struct {
			Display   string `json:"display"`
			PID       int    `json:"pid"`
			Managed   bool   `json:"managed"`
			HookReady bool   `json:"hook_ready"`
			HookCap   bool   `json:"hook_capable"`
			Action    string `json:"action"`
		} `json:"detected"`
	}
	if err := ctl("detected", nil, &det); err != nil {
		fmt.Println("  (守护进程未运行，无法检测)")
	} else if len(det.Detected) == 0 {
		fmt.Println("  -  未发现正在运行的 AI Agent")
	}
	for _, d := range det.Detected {
		state := "未受管：仅进程树观测"
		if d.Managed {
			state = "受管：代理可事前拦截"
		}
		hook := ""
		if d.HookCap {
			hook = "，Hook 未安装"
			if d.HookReady {
				hook = "，Hook 已安装"
			}
		}
		fmt.Printf("  %s  %-18s pid %-7d %s%s\n", map[bool]string{true: "✓", false: "▲"}[d.Managed], d.Display, d.PID, state, hook)
		if d.Action != "" && !d.Managed {
			fmt.Printf("       建议：%s\n", d.Action)
		}
	}
	fmt.Println("\n内核级阻断：")
	if ok, why := enforce.Available(); ok {
		fmt.Printf("  ✓  托管沙箱可用（%s）：xmon run --sandbox -- <agent>\n", enforce.Tier)
	} else {
		fmt.Printf("  ✗  托管沙箱不可用：%s\n", why)
	}
	if _, err := os.Stat(enforce.Path(config.Home())); err == nil {
		fmt.Printf("  ✓  策略文件：%s\n", enforce.Path(config.Home()))
	} else {
		fmt.Println("  -  未生成策略文件，将使用内置默认策略（xmon policy init 可生成并编辑）")
	}
	if cfg.Probe.Enforce {
		fmt.Println("  ✓  exec 后即杀已开启（probe.enforce: true，需 L1 探针运行）")
	} else {
		fmt.Println("  -  exec 后即杀未开启（probe.enforce: false）")
	}
	fmt.Println("\n各客户端可拦截程度（GUI 桌面端普遍低于 CLI）：")
	var reply struct {
		OK           bool `json:"ok"`
		Capabilities []struct {
			Display   string `json:"display"`
			Kind      string `json:"kind"`
			Intercept string `json:"intercept"`
			Note      string `json:"note"`
		} `json:"capabilities"`
	}
	if err := ctl("capabilities", nil, &reply); err == nil && len(reply.Capabilities) > 0 {
		for _, c := range reply.Capabilities {
			fmt.Printf("  [%-6s] %-18s %-8s %s\n", c.Kind, c.Display, c.Intercept, c.Note)
		}
	} else {
		fmt.Println("  (守护进程未运行，无法列出)")
	}
	return nil
}

func mark(ok bool, msg string) {
	if ok {
		fmt.Printf("  ✓  %s\n", msg)
	} else {
		fmt.Printf("  ✗  %s\n", msg)
	}
}

var _ = json.Marshal
