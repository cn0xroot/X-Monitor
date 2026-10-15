package main

import (
	"context"
	"log"
	"os"
	"time"

	"xmonitor/internal/agents"
	"xmonitor/internal/config"
	"xmonitor/internal/correlate"
	"xmonitor/internal/enforce"
	"xmonitor/internal/event"
	"xmonitor/internal/gate"
	"xmonitor/internal/probe"
	"xmonitor/internal/proctree"
	"xmonitor/internal/toolclass"
)

func isFileClass(class string) bool {
	switch class {
	case toolclass.FSWrite, toolclass.FSEdit, toolclass.FSDelete, toolclass.FSRead:
		return true
	}
	return false
}

// startProbe launches the L1 backend when available and feeds its exec/connect
// events into persistence and the cross-verifier (DESIGN.md §11, §13).
func startProbe(ctx context.Context, d *daemon, g *gate.Gate, tracker *proctree.Tracker, corr *correlate.Correlator) {
	if d.get().Probe.Enabled == "off" {
		return
	}
	be := probe.New()
	ok, reason := be.Available()
	if !ok {
		log.Printf("L1 probe (%s) unavailable: %s — core layers (L2/L3/L4) still active", be.Name(), reason)
		return
	}
	// Kill-after-exec tier (DESIGN.md §11): opt-in via probe.enforce, and only ever
	// applied to processes verified to be inside a monitored agent tree.
	home, _ := os.UserHomeDir()
	pol := &enforce.Cache{File: enforce.Path(config.Home()), Home: home}
	killer := &enforce.Killer{Policy: pol.Get}
	execs := make(chan probe.Exec, 256)
	conns := make(chan probe.Connect, 256)
	go func() {
		if err := be.Start(ctx, execs, conns); err != nil && ctx.Err() == nil {
			log.Printf("L1 probe stopped: %v", err)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-execs:
				info, tracked := tracker.Lookup(e.PID)
				if !tracked {
					info, tracked = tracker.Lookup(e.PPID)
				}
				session := ""
				if tracked {
					session = info.Session
				}
				// Cross-verify against the application layer.
				if alert := corr.NoteExec(session, e.Command); alert != nil {
					alert.PID = e.PID
				}
				if d.get().Probe.Enforce {
					if act, hit := killer.OnExec(e.PID, e.Command, tracked); hit {
						title := "已终止策略禁止的程序"
						if !act.Killed {
							title = "策略禁止的程序执行，但终止失败"
						}
						g.Emit(&event.Event{
							Layer: event.LayerL1, Kind: event.KindAlert, Type: "exec_denied",
							Session: session, PID: e.PID, Risk: event.RiskHigh, Decision: event.ActionBlock,
							Rule: "enforce.deny_exec", Title: title,
							Fields: map[string]any{
								"command": e.Command, "matched": act.Matched, "killed": act.Killed,
								"enforcement": "kill_after_exec", "error": errString(act.Err),
							},
						})
					}
				}
				g.Emit(&event.Event{
					Layer: event.LayerL1, Kind: event.KindIntent, Type: "execve",
					Session: session, PID: e.PID, Risk: event.RiskInfo, Title: "内核层进程执行",
					Fields: map[string]any{"comm": e.Comm, "ppid": e.PPID, "command": e.Command},
				})
			case c := <-conns:
				info, _ := tracker.Lookup(c.PID)
				session, agent := "", ""
				if info != nil {
					session, agent = info.Session, info.Agent
				}
				// Reverse-attribute GUI/unmanaged clients by LLM host: a process
				// connecting to a known LLM API is an AI client even if we never
				// launched it (DESIGN.md §9.1).
				title := "内核层网络连接"
				fields := map[string]any{"comm": c.Comm, "ip": c.IP, "port": c.Port, "host": c.Host}
				if a := agents.MatchByHost(c.Host); a != nil {
					if agent == "" {
						agent = a.ID
					}
					capb := agents.CapabilityOf(a.ID)
					title = "AI 客户端直连 LLM：" + capb.Display
					fields["intercept"] = string(capb.Intercept)
					fields["note"] = capb.Note
					// Direct LLM connection not routed through our proxy = evasion signal.
					if !routedThroughProxy(c.Port) {
						fields["direct_llm_egress"] = true
					}
				}
				g.Emit(&event.Event{
					Layer: event.LayerL1, Kind: event.KindIntent, Type: "connect",
					Session: session, Agent: agent, PID: c.PID, Risk: event.RiskLow, Title: title,
					Fields: fields,
				})
			}
		}
	}()
	log.Printf("L1 probe active: %s", be.Name())
	_ = time.Second
}

// routedThroughProxy reports whether a connection on port looks like it went to
// our local proxy rather than straight to the LLM (a direct connection to 443
// bypasses L4). This is a coarse heuristic for the direct_llm_egress signal.
func routedThroughProxy(port int) bool {
	return port == 7789
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
