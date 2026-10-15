package main

import (
	"xmonitor/internal/agentcfg"
	"xmonitor/internal/agents"
	"xmonitor/internal/proctree"
)

// detectedAgent is one AI agent found running on the host, with what X-Monitor
// can and cannot do about it.
type detectedAgent struct {
	agents.Capability
	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	Cmdline     string `json:"cmdline"`
	Managed     bool   `json:"managed"`
	Children    int    `json:"children"`
	Events      int    `json:"events"`
	HookReady   bool   `json:"hook_ready"`   // a native hook is installed for it
	HookSeen    bool   `json:"hook_seen"`    // ...and has actually reported a call (so the agent loaded it)
	HookCapable bool   `json:"hook_capable"` // a native hook exists for it
	// Action is the one command that would improve coverage ("" = nothing to do).
	Action string `json:"action,omitempty"`
}

// buildDetected combines the process snapshot with the capability table.
func buildDetected(snap []proctree.Running, home string, events func(agent string) int, hookSeen func(agent string) bool) []detectedAgent {
	out := make([]detectedAgent, 0, len(snap))
	for _, r := range snap {
		d := detectedAgent{Capability: agents.CapabilityOf(r.Agent), PID: r.PID, Comm: r.Comm, Cmdline: r.Cmdline,
			Managed: r.Managed, Children: r.Children}
		if events != nil {
			d.Events = events(r.Agent)
		}
		d.HookCapable = d.Hooks
		d.HookReady = agentcfg.HookInstalled(r.Agent, home)
		d.HookSeen = d.HookReady && hookSeen != nil && hookSeen(r.Agent)
		switch {
		case d.Managed:
			// already behind the proxy
		case d.HookCapable && !d.HookReady:
			d.Action = agentcfg.InstallHint(r.Agent)
		case !d.HookCapable:
			d.Action = "xmon run --agent " + r.Agent + " -- <command>"
		}
		out = append(out, d)
	}
	return out
}
