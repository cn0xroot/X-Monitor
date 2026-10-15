// Command xmond is the X-Monitor daemon: it runs the LLM proxy (L4),
// the native-hook gateway (L4b), the decision engine (rules + GLM), the
// approval broker, the audit store, and the dashboard API/WS server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"xmonitor/internal/agents"
	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/correlate"
	"xmonitor/internal/ctlproto"
	"xmonitor/internal/decide"
	"xmonitor/internal/event"
	"xmonitor/internal/fswatch"
	"xmonitor/internal/gate"
	"xmonitor/internal/glm"
	"xmonitor/internal/hookgw"
	"xmonitor/internal/notify"
	"xmonitor/internal/proctree"
	"xmonitor/internal/proxy"
	"xmonitor/internal/rules"
	"xmonitor/internal/server"
	"xmonitor/internal/sessionview"
	"xmonitor/internal/store"
	"xmonitor/internal/toolclass"
	"xmonitor/internal/usage"
)

var version = "0.1.0-dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("xmond: ")
	fg := flag.Bool("foreground", false, "run in foreground (don't detach)")
	flag.Parse()
	_ = fg

	if err := config.EnsureHome(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type daemon struct {
	mu  sync.RWMutex
	cfg *config.Config

	// selfWrite announces a file the daemon is about to modify to the L2 watcher.
	selfWrite func(path string)
	rootCtx   context.Context
	gate      *gate.Gate
	store     *store.Store
	following map[string]bool // cc-monitor DB paths with an active follow goroutine
}

func (d *daemon) get() *config.Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg
}

func (d *daemon) setMode(m config.Mode) {
	d.mu.Lock()
	d.cfg.Mode = m
	if d.selfWrite != nil {
		d.selfWrite(config.ConfigPath())
	}
	_ = d.cfg.Save()
	d.mu.Unlock()
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("config: %v (using defaults)", err)
	}
	d := &daemon{cfg: cfg, following: map[string]bool{}}

	st, err := store.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	_ = st.ExpireStalePending()

	re, err := rules.New(config.Home())
	if err != nil {
		return fmt.Errorf("rules: %w", err)
	}

	glmClient := glm.New(cfg.GLM)
	var analyzer glm.Analyzer = glmClient

	dec := decide.New(re, analyzer, st, d.get)

	timeout := func() time.Duration { return time.Duration(d.get().Approval.TimeoutS) * time.Second }
	var dash *server.Server
	broker := approval.New(st, timeout, func(a *store.Approval) {
		if d.get().Approval.DesktopNotify {
			notify.Desktop("X-Monitor 需要确认", a.Summary)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- L3 process tree + L2 files + L1 probe + cross-verification ---
	tracker := proctree.New(proctree.DefaultLister(), time.Second)
	corr := correlate.New(nil)
	fsw, fsErr := fswatch.New(nil, 3*time.Second)
	if fsErr != nil {
		log.Printf("fswatch disabled: %v", fsErr)
	}

	g := gate.New(dec, broker, st, d.get)
	d.rootCtx, d.gate, d.store = ctx, g, st
	g.OnEvent = func(ev *event.Event) {
		if ev.Kind == event.KindIntent && ev.Tool != nil {
			corr.NoteIntent(ev)
			if fsw != nil && isFileClass(ev.Tool.Class) {
				fsw.NoteIntent(fswatch.Intent{When: time.Now(), Session: ev.Session, Agent: ev.Agent, Summary: ev.Matched})
			}
		}
		if dash != nil {
			dash.Broadcast(ev)
		}
	}
	// L3 exec events: persist + feed temporal attribution.
	tracker.OnExec(func(ev *event.Event) { g.Emit(ev) })
	corr.SetEmit(func(ev *event.Event) { g.Emit(ev) })
	if fsw != nil {
		fsw.SetEmit(func(ev *event.Event) { g.Emit(ev) })
	}

	token, _ := config.Token()
	dash = server.New(&server.Server{
		Store: st, Rules: re, Broker: broker, Cfg: d.get, SetMode: d.setMode,
		GLM: glmClient, Token: token, Version: version,
		Live: func() []sessionview.Live {
			var out []sessionview.Live
			for _, r := range tracker.Snapshot() {
				out = append(out, sessionview.Live{Agent: r.Agent, PID: r.PID, Comm: r.Comm, Cmdline: r.Cmdline, Children: r.Children})
			}
			return out
		},
		Anthropic: usage.NewAnthropic(),
		Detected: func() any {
			home, _ := os.UserHomeDir()
			return buildDetected(tracker.Snapshot(), home, st.AgentEventCount, st.HookSeen)
		},
	})

	// --- control socket (xmon CLI talks to the daemon over this UDS) ---
	ctlPath := config.SocketPath()
	ctl, err := listenControl(ctlPath, d, st, broker, re, tracker)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer ctl.Close()

	// --- hook gateway ---
	hookPath := config.Home() + "/hook.sock"
	gw, err := hookgw.Listen(hookPath, g)
	if err != nil {
		return fmt.Errorf("hook gateway: %w", err)
	}
	defer gw.Close()
	go gw.Serve()

	// --- LLM proxy (L4) ---
	px := proxy.New(g, d.get)
	px.Resolve = makeResolver(st)
	proxyLn, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return fmt.Errorf("proxy listen %s: %w", cfg.ProxyAddr, err)
	}
	proxySrv := &http.Server{Handler: px.Handler()}
	go proxySrv.Serve(proxyLn)

	// --- dashboard (optionally with embedded UI) ---
	uiLn, err := server.Listen(cfg.UIAddr, nil, token != "")
	if err != nil {
		return fmt.Errorf("ui listen: %w", err)
	}
	uiSrv := &http.Server{Handler: dash.Handler(uiHandler())}
	go uiSrv.Serve(uiLn)

	// --- start L3 / L2 / L1 collectors ---
	go tracker.Start(ctx)
	tracker.OnAgentSpawn(func(a, session string, pid int, already bool) {
		g.Emit(&event.Event{Layer: event.LayerL3, Kind: event.KindSession, Type: "agent_discovered",
			Agent: a, PID: pid, Risk: event.RiskInfo, Title: "发现未受管的 AI Agent",
			Fields: map[string]any{"already_running": already}})
	})
	if fsw != nil {
		fsw.SetSelfDir(config.Home())
		d.selfWrite = func(p string) { fsw.ExpectWrite(p, 2*time.Second) }
		if home, err := os.UserHomeDir(); err == nil {
			fsw.WatchSensitive(home)
		}
		if wd, err := os.Getwd(); err == nil {
			fsw.WatchProject(wd)
		}
		go fsw.Start(ctx)
	}
	startProbe(ctx, d, g, tracker, corr)

	// --- retention sweeper ---
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			c := d.get()
			if n, err := st.Prune(time.Duration(c.Storage.RetentionDays)*24*time.Hour, c.Storage.MaxEvents); err == nil && n > 0 {
				log.Printf("pruned %d old events", n)
			}
		}
	}()

	writePID()
	defer os.Remove(config.PIDPath())
	log.Printf("ready: proxy=%s ui=http://%s/?token=%s glm=%s rules=%d",
		cfg.ProxyAddr, cfg.UIAddr, token[:8]+"…", glmClient.Status(), len(re.Rules()))

	<-ctx.Done()
	log.Printf("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(sctx)
	_ = uiSrv.Shutdown(sctx)
	return nil
}

func writePID() {
	_ = os.WriteFile(config.PIDPath(), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600)
}

// makeResolver maps a proxy client's remote addr to (agent, session) by PID.
// For clients we did not launch via `xmon run` (GUI apps, IDE plugins), it
// still identifies the agent from the client process's name/exe/bundle so the
// traffic is attributed and labeled (DESIGN.md §9.1).
func makeResolver(st *store.Store) func(string) (string, string, bool) {
	return func(remoteAddr string) (string, string, bool) {
		pid := proxy.LookupPID(remoteAddr)
		if pid == 0 {
			return "", "", false
		}
		if ss := sessionForPID(st, pid); ss != nil {
			return ss.Agent, ss.ID, true
		}
		// Unmanaged client: identify by walking the process tree's names.
		if a := identifyPIDTree(pid); a != "" {
			return a, "", true
		}
		return "", "", true
	}
}

// identifyPIDTree walks up from pid matching each process against the agent
// signatures (handles Electron helpers whose parent is the app bundle).
func identifyPIDTree(pid int) string {
	for p, depth := pid, 0; p > 1 && depth < 40; depth++ {
		comm, exe, argv := procInfo(p)
		if a := agents.Match(comm, exe, argv); a != nil {
			return a.ID
		}
		pp := parentPID(p)
		if pp == 0 || pp == p {
			break
		}
		p = pp
	}
	return ""
}

// sessionForPID walks the process tree upward to find a monitored root PID.
func sessionForPID(st *store.Store, pid int) *store.Session {
	sessions, err := st.ListSessions(200)
	if err != nil {
		return nil
	}
	byRoot := map[int]*store.Session{}
	for _, s := range sessions {
		if s.EndedAt == 0 && s.RootPID != 0 {
			byRoot[s.RootPID] = s
		}
	}
	for p, depth := pid, 0; p > 1 && depth < 40; depth++ {
		if s, ok := byRoot[p]; ok {
			return s
		}
		p = parentPID(p)
		if p == 0 {
			break
		}
	}
	return nil
}

// ---- control protocol (CLI <-> daemon) ----

type ctlReq struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args"`
}

func listenControl(path string, d *daemon, st *store.Store, broker *approval.Broker, re *rules.Engine, tracker *proctree.Tracker) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleControl(conn, d, st, broker, re, tracker)
		}
	}()
	return ln, nil
}

func handleControl(conn net.Conn, d *daemon, st *store.Store, broker *approval.Broker, re *rules.Engine, tracker *proctree.Tracker) {
	defer conn.Close()
	var req ctlReq
	if json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&req) != nil {
		return
	}
	enc := json.NewEncoder(conn)
	switch req.Cmd {
	case "status":
		c := d.get()
		enc.Encode(map[string]any{"ok": true, "mode": c.Mode, "proxy": c.ProxyAddr, "ui": c.UIAddr, "rules": len(re.Rules()), "pid": os.Getpid()})
	case "mode":
		var a struct{ Mode string }
		_ = json.Unmarshal(req.Args, &a)
		d.setMode(config.Mode(a.Mode))
		enc.Encode(map[string]any{"ok": true, "mode": a.Mode})
	case "register_session":
		var rs ctlproto.RegisterSession
		if err := ctlproto.Decode(req.Args, &rs); err != nil {
			enc.Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		ss := store.Session{ID: rs.ID, Agent: rs.Agent, CWD: rs.CWD, Argv: rs.Argv, RootPID: rs.RootPID, StartedAt: rs.StartedAt}
		if ss.StartedAt == 0 {
			ss.StartedAt = event.Now()
		}
		if ss.RootPID != 0 {
			tracker.Register(ss.RootPID, ss.Agent, ss.ID)
		}
		err := st.PutSession(&ss)
		writeTrackedRoots(st)
		enc.Encode(map[string]any{"ok": err == nil, "error": errStr(err)})
	case "end_session":
		var a struct {
			ID   string
			Code int
		}
		_ = json.Unmarshal(req.Args, &a)
		if ss, _ := st.GetSession(a.ID); ss != nil {
			ss.EndedAt = event.Now()
			ss.ExitCode = &a.Code
			_ = st.PutSession(ss)
		}
		writeTrackedRoots(st)
		enc.Encode(map[string]any{"ok": true})
	case "approve", "deny":
		var a struct {
			ID       int64
			Decision string
		}
		_ = json.Unmarshal(req.Args, &a)
		dec := a.Decision
		if req.Cmd == "deny" {
			dec = approval.Deny
		} else if dec == "" {
			dec = approval.AllowOnce
		}
		err := broker.Resolve(a.ID, dec, "cli")
		enc.Encode(map[string]any{"ok": err == nil, "error": errStr(err)})
	case "pending":
		list, _ := st.ListApprovals("pending", 100)
		enc.Encode(map[string]any{"ok": true, "pending": list})
	case "test":
		var a struct {
			Tool string
			Args map[string]any
			CWD  string
		}
		_ = json.Unmarshal(req.Args, &a)
		calls := toolclass.Normalize("test", a.Tool, a.Args)
		var results []any
		for i := range calls {
			calls[i].CWD = a.CWD
			m := re.Evaluate(calls[i])
			r := map[string]any{"class": calls[i].Class}
			if m != nil {
				r["rule"], r["risk"], r["action"], r["matched"] = m.Rule.ID, m.Rule.Risk, m.Rule.Action, m.Value
			}
			results = append(results, r)
		}
		enc.Encode(map[string]any{"ok": true, "results": results})
	case "verify":
		res, _ := st.VerifyChain()
		enc.Encode(map[string]any{"ok": true, "verify": res})
	case "capabilities":
		enc.Encode(map[string]any{"ok": true, "capabilities": agents.AllCapabilities()})
	case "detected":
		home, _ := os.UserHomeDir()
		enc.Encode(map[string]any{"ok": true, "detected": buildDetected(tracker.Snapshot(), home, st.AgentEventCount, st.HookSeen)})
	case "import":
		var a struct {
			Path   string
			Follow bool
		}
		_ = json.Unmarshal(req.Args, &a)
		if a.Path == "" {
			enc.Encode(map[string]any{"ok": false, "error": "missing path"})
			return
		}
		n, err := runImport(st, d.gate, a.Path)
		if err != nil {
			enc.Encode(map[string]any{"ok": false, "error": err.Error(), "imported": n})
			return
		}
		followed := false
		if a.Follow {
			d.mu.Lock()
			if !d.following[a.Path] {
				d.following[a.Path] = true
				followed = true
				go followImport(d.rootCtx, st, d.gate, a.Path)
			}
			d.mu.Unlock()
		}
		enc.Encode(map[string]any{"ok": true, "imported": n, "following": followed || a.Follow})
	default:
		enc.Encode(map[string]any{"ok": false, "error": "unknown command"})
	}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
