// Package gate is the single enforcement point shared by the LLM proxy and the
// hook gateway: decide → (confirm) → audit, with per-tool_call_id outcome
// sharing so a call vetted by the proxy isn't re-prompted by the hook (§8).
package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/decide"
	"xmonitor/internal/event"
	"xmonitor/internal/store"
	"xmonitor/internal/toolclass"
	"xmonitor/internal/workdir"
)

// Outcome is the final result for one tool call.
type Outcome struct {
	Allowed    bool           `json:"allowed"`
	Verdict    decide.Verdict `json:"verdict"`
	ViaConfirm bool           `json:"via_confirm"` // a human approved it
	Approval   string         `json:"approval,omitempty"`
	Message    string         `json:"message,omitempty"` // shown to the model when blocked
	EventID    string         `json:"event_id,omitempty"`
	Reused     bool           `json:"reused,omitempty"`
}

// Gate wires the decider, broker and store together.
type Gate struct {
	D   *decide.Decider
	B   *approval.Broker
	St  *store.Store
	Cfg func() *config.Config

	// OnEvent is called after every persisted event (live UI feed).
	OnEvent func(*event.Event)

	mu       sync.Mutex
	outcomes map[string]timed
}

type timed struct {
	o   Outcome
	exp time.Time
}

// New creates a gate.
func New(d *decide.Decider, b *approval.Broker, st *store.Store, cfg func() *config.Config) *Gate {
	return &Gate{D: d, B: b, St: st, Cfg: cfg, outcomes: map[string]timed{}}
}

func key(c toolclass.Call) string {
	if c.ID == "" {
		return ""
	}
	return c.Session + "|" + c.ID + "|" + c.Class + "|" + c.Summary()
}

// Lookup returns a previously decided outcome for the same tool call.
func (g *Gate) Lookup(c toolclass.Call) (Outcome, bool) {
	k := key(c)
	if k == "" {
		return Outcome{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.outcomes[k]
	if !ok || time.Now().After(t.exp) {
		return Outcome{}, false
	}
	return t.o, true
}

func (g *Gate) remember(c toolclass.Call, o Outcome) {
	k := key(c)
	if k == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.outcomes) > 20000 {
		now := time.Now()
		for k, t := range g.outcomes {
			if now.After(t.exp) {
				delete(g.outcomes, k)
			}
		}
	}
	g.outcomes[k] = timed{o, time.Now().Add(10 * time.Minute)}
}

// Check decides one call, asks a human when needed, and audits the result.
func (g *Gate) Check(ctx context.Context, layer string, c toolclass.Call) Outcome {
	if prev, ok := g.Lookup(c); ok {
		prev.Reused = true
		g.audit(layer, c, prev, "cache")
		return prev
	}
	cfg := g.Cfg()
	v := g.D.Decide(ctx, c)
	o := Outcome{Verdict: v}
	switch v.Action {
	case event.ActionBlock:
		o.Allowed = false
	case event.ActionConfirm:
		a := &store.Approval{
			Session: c.Session, Agent: c.Agent, ToolCallID: c.ID, ToolRaw: c.Raw, ToolClass: c.Class,
			Summary: truncate(c.Summary(), 2000), Rule: v.RuleID, Risk: string(v.Risk), Reason: firstNonEmpty(v.Title, v.Reason),
		}
		if v.GLM != nil {
			b, _ := json.Marshal(v.GLM)
			a.GLM = string(b)
		}
		r, _ := g.B.Request(ctx, a)
		o.Approval = r.Status
		o.Allowed = r.Allowed
		o.ViaConfirm = r.Allowed
		if r.Allowed && r.Scope == "session" && v.RuleID != "" {
			_ = g.St.AllowForSession(c.Session, v.RuleID, 0)
		}
	default:
		o.Allowed = true
	}
	if !o.Allowed {
		o.Message = BlockMessage(c, o)
	}
	if cfg.Mode != config.ModeStopped {
		o.EventID = g.audit(layer, c, o, "")
		g.D.Sessions.Get(c.Session).Record(fmt.Sprintf("[%s] %s: %s", decisionWord(o), c.Raw, truncate(c.Summary(), 200)))
	}
	g.remember(c, o)
	return o
}

func decisionWord(o Outcome) string {
	if o.Allowed {
		return "allowed"
	}
	return "blocked"
}

func (g *Gate) audit(layer string, c toolclass.Call, o Outcome, decidedBy string) string {
	v := o.Verdict
	dec := event.ActionAllow
	if !o.Allowed {
		dec = event.ActionBlock
	}
	ev := &event.Event{
		Layer: layer, Kind: event.KindIntent, Type: "tool_use",
		Agent: c.Agent, Session: c.Session, AgentSession: c.AgentSession, ToolCallID: c.ID,
		CWD: c.CWD, Tool: &event.Tool{Raw: c.Raw, Class: c.Class, Args: redactArgs(c.Args)},
		Risk: v.Risk, Decision: dec, DecidedBy: firstNonEmpty(decidedBy, v.DecidedBy),
		Rule: v.RuleID, Matched: truncate(v.Matched, 500), Reason: v.Reason, GLM: v.GLM, Title: v.Title,
		Fields: map[string]any{"would": string(v.Would)},
	}
	if c.CWD != "" {
		ev.ProjectRoot = workdir.ProjectRoot(c.CWD)
	}
	if o.Approval != "" {
		ev.Fields["approval"] = o.Approval
	}
	if v.Action == event.ActionConfirm || o.Approval != "" {
		ev.Fields["confirm"] = true
	}
	if o.Reused {
		ev.Fields["reused_from"] = o.EventID
	}
	if c.Model != "" {
		ev.Fields["model"] = c.Model
	}
	if err := g.St.Append(ev); err != nil {
		return ""
	}
	if g.OnEvent != nil {
		g.OnEvent(ev)
	}
	return ev.ID
}

// Emit persists a non-intent event (alerts, llm metadata, sessions).
func (g *Gate) Emit(ev *event.Event) {
	if g.Cfg().Mode == config.ModeStopped {
		return
	}
	if err := g.St.Append(ev); err == nil && g.OnEvent != nil {
		g.OnEvent(ev)
	}
}

// redactArgs keeps the audit trail free of bulky file contents (cc-monitor's
// "metadata only" principle): long content fields are reduced to their size.
func redactArgs(a map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		if s, ok := v.(string); ok {
			switch k {
			case "content", "new_string", "old_string", "new_source", "code_edit", "file_text", "contents", "text", "input", "patch":
				if len(s) > 256 {
					out[k] = fmt.Sprintf("<%d bytes>", len(s))
					continue
				}
			}
			out[k] = truncate(s, 4000)
			continue
		}
		out[k] = v
	}
	return out
}

// BlockMessage is the text the model (and the user) sees instead of the call.
func BlockMessage(c toolclass.Call, o Outcome) string {
	v := o.Verdict
	var b strings.Builder
	b.WriteString("[X-Monitor] 已拦截工具调用 ")
	b.WriteString(c.Raw)
	if v.RuleID != "" {
		fmt.Fprintf(&b, "（规则 %s：%s）", v.RuleID, v.Title)
	}
	fmt.Fprintf(&b, "：%s", truncate(c.Summary(), 300))
	switch o.Approval {
	case "denied":
		b.WriteString("。用户在审批中拒绝了此操作。")
	case "expired":
		b.WriteString("。等待用户审批超时，已默认拒绝。")
	default:
		b.WriteString("。")
	}
	if v.Reason != "" {
		fmt.Fprintf(&b, "原因：%s。", truncate(v.Reason, 400))
	} else if v.Desc != "" {
		fmt.Fprintf(&b, "原因：%s", v.Desc)
	}
	if v.GLM != nil && v.GLM.Recommendation != "" {
		fmt.Fprintf(&b, " 建议：%s", truncate(v.GLM.Recommendation, 300))
	}
	b.WriteString(" 请不要尝试用其他方式绕过此限制；如确有必要，请向用户说明原因，由用户决定是否放行。")
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
