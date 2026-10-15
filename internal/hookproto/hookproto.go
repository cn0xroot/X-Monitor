// Package hookproto holds the wire types of the native-hook channel, shared by
// the tiny xmon-hook binary and the daemon's hook gateway. It has no
// dependencies on purpose: xmon-hook must start in a few milliseconds.
//
// The input side (AgentInput) accepts what different agents write to a hook's
// stdin — Claude Code's PreToolUse/PostToolUse JSON and OpenCode's plugin
// payload (design adapted from CC-Monitor's opencode adapter, MIT; see NOTICE).
package hookproto

// Request is what xmon-hook sends to the gateway.
type Request struct {
	Agent        string         `json:"agent"`
	Session      string         `json:"session"`       // xmon session (from XMON_SESSION)
	AgentSession string         `json:"agent_session"` // the agent's own session id
	ToolCallID   string         `json:"tool_call_id"`
	Tool         string         `json:"tool"`
	Args         map[string]any `json:"args"`
	CWD          string         `json:"cwd"`
	Phase        string         `json:"phase"` // pre | post
}

// Response is the gateway's verdict.
type Response struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Reused  bool   `json:"reused,omitempty"`
}

// AgentInput is the union of the hook payloads agents send on stdin.
type AgentInput struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path"`
	CWD            string         `json:"cwd"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolUseID      string         `json:"tool_use_id"` // Claude Code
	CallID         string         `json:"call_id"`     // OpenCode
}

// Phase derives "pre" or "post". An explicit mode (the first CLI argument) wins;
// otherwise the agent's event name decides.
func Phase(mode, eventName string) string {
	switch mode {
	case "pre", "post":
		return mode
	}
	switch eventName {
	case "PostToolUse", "tool.execute.after":
		return "post"
	}
	return "pre"
}

// Build turns an agent's payload into a gateway request. agent defaults to
// "claude-code" (the only agent that sends no --agent flag).
func Build(in AgentInput, agent, mode, xmonSession string) Request {
	if agent == "" {
		agent = "claude-code"
	}
	id := in.ToolUseID
	if id == "" {
		id = in.CallID
	}
	return Request{
		Agent: agent, Session: xmonSession, AgentSession: in.SessionID, ToolCallID: id,
		Tool: in.ToolName, Args: in.ToolInput, CWD: in.CWD, Phase: Phase(mode, in.HookEventName),
	}
}

// ParseArgs reads `xmon-hook [pre|post] [--agent X]`.
func ParseArgs(args []string) (mode, agent string) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--agent" && i+1 < len(args):
			agent = args[i+1]
			i++
		case len(a) > 8 && a[:8] == "--agent=":
			agent = a[8:]
		case a == "pre" || a == "post":
			mode = a
		}
	}
	return mode, agent
}
