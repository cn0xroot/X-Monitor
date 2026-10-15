// Package event defines the unified event model shared by every layer
// (L4 proxy, hook gateway, and later L3/L2/L1 probes). See DESIGN.md §6.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Risk is an ordered risk level.
type Risk string

const (
	RiskInfo     Risk = "info"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Rank returns a sortable rank (higher is riskier).
func (r Risk) Rank() int {
	switch r {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

// Max returns the riskier of r and o.
func (r Risk) Max(o Risk) Risk {
	if o.Rank() > r.Rank() {
		return o
	}
	return r
}

// Action is what a rule or the decision engine wants done with an intent.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionLog     Action = "log"
	ActionNotify  Action = "notify"
	ActionConfirm Action = "confirm"
	ActionBlock   Action = "block"
)

// Rank orders actions by strictness.
func (a Action) Rank() int {
	switch a {
	case ActionBlock:
		return 3
	case ActionConfirm:
		return 2
	case ActionLog, ActionNotify:
		return 1
	default:
		return 0
	}
}

// Layers.
const (
	LayerProxy = "L4"
	LayerHook  = "hook"
	LayerL3    = "L3"
	LayerL2    = "L2"
	LayerL1    = "L1"
)

// Kinds.
const (
	KindIntent   = "intent"
	KindLLM      = "llm"
	KindAlert    = "alert"
	KindApproval = "approval"
	KindSession  = "session"
)

// Tool is the tool-call payload of an intent event.
type Tool struct {
	Raw   string         `json:"raw"`
	Class string         `json:"class"`
	Args  map[string]any `json:"args,omitempty"`
}

// GLMVerdict is the semantic engine's structured output (DESIGN.md §12.4).
type GLMVerdict struct {
	Intent          string   `json:"intent"`
	Risk            Risk     `json:"risk"`
	Action          Action   `json:"action"`
	Tags            []string `json:"tags,omitempty"`
	FalsePositive   bool     `json:"is_false_positive"`
	PromptInjection bool     `json:"prompt_injection"`
	Confidence      float64  `json:"confidence"`
	Reason          string   `json:"reason"`
	Recommendation  string   `json:"recommendation,omitempty"`
	Model           string   `json:"model,omitempty"`
	LatencyMS       int64    `json:"latency_ms,omitempty"`
}

// Event is one audited record.
type Event struct {
	Seq   int64  `json:"seq"` // store-assigned, monotonically increasing
	ID    string `json:"id"`
	TS    int64  `json:"ts"` // unix ms
	Layer string `json:"layer"`
	Kind  string `json:"kind"`
	Type  string `json:"type"`

	Agent        string `json:"agent,omitempty"`
	Session      string `json:"session,omitempty"`
	AgentSession string `json:"agent_session,omitempty"`
	ToolCallID   string `json:"tool_call_id,omitempty"`

	PID         int    `json:"pid,omitempty"`
	CWD         string `json:"cwd,omitempty"`
	ProjectRoot string `json:"project_root,omitempty"`

	Tool   *Tool          `json:"tool,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`

	Risk      Risk        `json:"risk"`
	Decision  Action      `json:"decision,omitempty"`
	DecidedBy string      `json:"decided_by,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Matched   string      `json:"matched,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	GLM       *GLMVerdict `json:"glm,omitempty"`

	Title string `json:"title,omitempty"`

	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// NewID returns a time-ordered, random-suffixed identifier.
func NewID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s%013x%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(b[:]))
}

// Now returns the current time in unix milliseconds.
func Now() int64 { return time.Now().UnixMilli() }
