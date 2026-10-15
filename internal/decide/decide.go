// Package decide is the hybrid decision pipeline (DESIGN.md §12.3):
// rules fast path → session correlation → allow-list → cache → GLM → merge matrix.
package decide

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"xmonitor/internal/config"
	"xmonitor/internal/event"
	"xmonitor/internal/glm"
	"xmonitor/internal/rules"
	"xmonitor/internal/shellparse"
	"xmonitor/internal/toolclass"
	"xmonitor/internal/workdir"
)

// Verdict is the decision for one tool call.
type Verdict struct {
	Action     event.Action      `json:"action"`      // effective: allow | confirm | block
	Would      event.Action      `json:"would"`       // what active mode would do (differs in paused mode)
	RuleAction event.Action      `json:"rule_action"` // the rule's own action ("" if no rule)
	Risk       event.Risk        `json:"risk"`
	DecidedBy  string            `json:"decided_by"` // rule | glm | allow_list | cache | session | fallback | mode
	RuleID     string            `json:"rule,omitempty"`
	Title      string            `json:"title,omitempty"`
	Desc       string            `json:"desc,omitempty"`
	Matched    string            `json:"matched,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	GLM        *event.GLMVerdict `json:"glm,omitempty"`
}

// AllowList answers "did the user say always allow this rule in this session".
type AllowList interface {
	IsAllowedForSession(session, rule string) bool
}

// Decider evaluates calls.
type Decider struct {
	Rules     *rules.Engine
	GLM       glm.Analyzer // nil = rules only
	AllowList AllowList
	Cfg       func() *config.Config
	Sessions  *Sessions

	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	v   *event.GLMVerdict
	exp time.Time
}

// New creates a Decider.
func New(re *rules.Engine, an glm.Analyzer, al AllowList, cfg func() *config.Config) *Decider {
	return &Decider{Rules: re, GLM: an, AllowList: al, Cfg: cfg, Sessions: NewSessions(), cache: map[string]cacheEntry{}}
}

var obfuscationRE = regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}|\beval\s|\$\(\s*(echo|printf|base64|xxd)\b|xxd\s+-r|\b(python[0-9.]*|perl|ruby|node)\s+-[ce]\s|\bopenssl\s+enc\s+-d|\$'\\[0-7x]`)

// Obfuscated reports whether a shell command uses encoding/indirection that
// static rules can't see through.
func Obfuscated(cmd string) bool { return obfuscationRE.MatchString(cmd) }

// Decide evaluates one call.
func (d *Decider) Decide(ctx context.Context, c toolclass.Call) Verdict {
	cfg := d.Cfg()
	if cfg.Mode == config.ModeStopped {
		return Verdict{Action: event.ActionAllow, Would: event.ActionAllow, Risk: event.RiskInfo, DecidedBy: "mode"}
	}
	v := d.decideActive(ctx, c, cfg)
	v.Would = v.Action
	if cfg.Mode == config.ModePaused && v.Action != event.ActionAllow {
		v.Action = event.ActionAllow
		v.DecidedBy = "mode"
	}
	return v
}

func (d *Decider) decideActive(ctx context.Context, c toolclass.Call, cfg *config.Config) Verdict {
	v := Verdict{Risk: event.RiskLow, DecidedBy: "rule"}
	var rule *rules.Rule
	if m := d.Rules.Evaluate(c); m != nil {
		rule = m.Rule
		v.RuleID, v.Title, v.Desc, v.Matched = rule.ID, rule.Title, rule.Desc, m.Value
		v.RuleAction, v.Risk = rule.Action, rule.Risk
	}
	base := v.RuleAction
	if base == "" || base == event.ActionLog || base == event.ActionNotify {
		base = event.ActionAllow
	}

	// Session correlation can only escalate.
	st := d.Sessions.Get(c.Session)
	if esc := st.observe(c, rule); esc != nil && esc.action.Rank() > base.Rank() {
		base = esc.action
		v.Risk = v.Risk.Max(esc.risk)
		v.RuleID, v.Title, v.Desc, v.Reason = esc.id, esc.title, esc.desc, esc.desc
		v.DecidedBy = "session"
		rule = nil // a sequence verdict is never GLM-downgradable
	}

	// Fast path: high-confidence block.
	if base == event.ActionBlock && (rule == nil || rule.Conf() >= 0.95) {
		v.Action = event.ActionBlock
		return v
	}
	// Session "always allow" for this rule.
	if base == event.ActionConfirm && rule != nil && d.AllowList != nil && d.AllowList.IsAllowedForSession(c.Session, rule.ID) {
		v.Action, v.DecidedBy = event.ActionAllow, "allow_list"
		return v
	}

	obf := false
	if c.Class == toolclass.ExecShell {
		if s, _ := c.Args["command"].(string); s != "" && Obfuscated(s) {
			obf = true
			v.Risk = v.Risk.Max(event.RiskMedium)
		}
	}
	needGLM := d.GLM != nil && cfg.GLM.Enabled &&
		(base == event.ActionConfirm || base == event.ActionBlock || obf ||
			(rule == nil && cfg.GLM.ReviewUnmatched && c.Class == toolclass.ExecShell))
	if !needGLM {
		v.Action = base
		return v
	}

	downgradable := rule != nil && rule.Downgradable() && !st.has(TaintInjection)
	key := cacheKey(c, st.taintList())
	gv, cached := d.cached(key)
	if !cached {
		in := glm.Input{
			Call: c, OS: runtime.GOOS, Taints: st.taintList(), UserGoal: st.goal(), RecentOps: st.recent(),
			RuleID: v.RuleID, RuleRisk: v.Risk, RuleAction: v.RuleAction, RuleDesc: v.Desc, Matched: v.Matched,
		}
		if c.CWD != "" {
			in.ProjectRoot = workdir.ProjectRoot(c.CWD)
		}
		var err error
		gv, err = d.GLM.Analyze(ctx, in)
		if err != nil {
			gv = nil
		} else {
			d.store(key, gv)
		}
	}
	v.GLM = gv
	if gv != nil && gv.PromptInjection {
		st.taint(TaintInjection)
	}
	v.Action = Merge(base, downgradable, gv, cfg.GLM.MinConfidence)
	switch {
	case gv == nil:
		v.DecidedBy = "fallback"
	case cached:
		v.DecidedBy = "cache"
	case v.Action != base:
		v.DecidedBy = "glm"
	}
	if gv != nil {
		if v.Action.Rank() > base.Rank() || v.Action != base {
			v.Risk = gv.Risk
		}
		v.Reason = gv.Reason
	}
	return v
}

// Merge implements the decision matrix of DESIGN.md §12.3: the semantic
// engine may escalate anything, but may relax only a downgradable confirm.
func Merge(rule event.Action, downgradable bool, g *event.GLMVerdict, minConf float64) event.Action {
	if minConf <= 0 {
		minConf = 0.85
	}
	if rule == "" || rule == event.ActionLog || rule == event.ActionNotify {
		rule = event.ActionAllow
	}
	if rule == event.ActionBlock {
		return event.ActionBlock
	}
	if g == nil {
		return rule
	}
	if g.PromptInjection && rule == event.ActionAllow {
		return event.ActionConfirm
	}
	switch rule {
	case event.ActionConfirm:
		switch {
		case g.Action == event.ActionBlock:
			return event.ActionBlock
		case g.Action == event.ActionAllow && downgradable && !g.PromptInjection && g.Confidence >= minConf:
			return event.ActionAllow
		default:
			return event.ActionConfirm
		}
	default: // allow / unmatched
		switch g.Action {
		case event.ActionBlock:
			if g.Confidence >= 0.8 {
				return event.ActionBlock
			}
			return event.ActionConfirm
		case event.ActionConfirm:
			return event.ActionConfirm
		default:
			return event.ActionAllow
		}
	}
}

func cacheKey(c toolclass.Call, taints []string) string {
	args, _ := json.Marshal(c.Args)
	h := sha256.New()
	h.Write([]byte(c.Class + "\x00" + c.Raw + "\x00" + c.CWD + "\x00" + strings.Join(taints, ",") + "\x00"))
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

func (d *Decider) cached(k string) (*event.GLMVerdict, bool) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	e, ok := d.cache[k]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.v, true
}

func (d *Decider) store(k string, v *event.GLMVerdict) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if len(d.cache) > 10000 {
		d.cache = map[string]cacheEntry{}
	}
	d.cache[k] = cacheEntry{v, time.Now().Add(24 * time.Hour)}
}

// ---- session correlation (DESIGN.md §12.2) ----

// Taints.
const (
	TaintSecretRead = "secret_read"
	TaintInjection  = "injection"
)

// Sessions holds per-session state.
type Sessions struct {
	mu sync.Mutex
	m  map[string]*State
}

// NewSessions creates an empty registry.
func NewSessions() *Sessions { return &Sessions{m: map[string]*State{}} }

// Get returns (creating) the state for id.
func (s *Sessions) Get(id string) *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		id = "_default"
	}
	st, ok := s.m[id]
	if !ok {
		st = &State{taints: map[string]time.Time{}}
		s.m[id] = st
	}
	return st
}

// State is one session's correlation state.
type State struct {
	mu       sync.Mutex
	taints   map[string]time.Time
	ops      []string
	userGoal string
}

func (st *State) has(t string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	at, ok := st.taints[t]
	return ok && time.Since(at) < 15*time.Minute
}

func (st *State) taint(t string) {
	st.mu.Lock()
	st.taints[t] = time.Now()
	st.mu.Unlock()
}

// Taint marks the session (used by the proxy's request-side analysis).
func (st *State) Taint(t string) { st.taint(t) }

// SetGoal records the user's first instruction (from the proxy).
func (st *State) SetGoal(g string) {
	st.mu.Lock()
	if st.userGoal == "" {
		st.userGoal = g
	}
	st.mu.Unlock()
}

func (st *State) goal() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.userGoal
}

func (st *State) taintList() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []string
	for t, at := range st.taints {
		if time.Since(at) < 15*time.Minute {
			out = append(out, t)
		}
	}
	return out
}

func (st *State) recent() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]string(nil), st.ops...)
}

// Record appends an operation summary with its final decision.
func (st *State) Record(op string) {
	st.mu.Lock()
	st.ops = append(st.ops, op)
	if len(st.ops) > 10 {
		st.ops = st.ops[len(st.ops)-10:]
	}
	st.mu.Unlock()
}

type escalation struct {
	id, title, desc string
	risk            event.Risk
	action          event.Action
}

var secretReadRules = map[string]bool{
	"sensitive_file_read": true, "sensitive_file_read_bash": true, "browser_credential_read": true,
	"browser_credential_read_bash": true, "cloud_vpn_config_read": true, "env_dump": true, "proc_env_read": true,
	"credential_grep_scan": true, "history_read": true, "history_file_read": true, "workdir_escape_read_sensitive": true,
}

var egressHeadRE = regexp.MustCompile(`(?i)^(curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|ssh|telnet|http|https|aria2c)\b`)

// observe updates taints from this call and returns an escalation if the call
// completes a risky sequence.
func (st *State) observe(c toolclass.Call, r *rules.Rule) *escalation {
	if r != nil && secretReadRules[r.ID] {
		st.taint(TaintSecretRead)
		return nil
	}
	if !st.has(TaintSecretRead) {
		return nil
	}
	egress := c.Class == toolclass.NetFetch
	if c.Class == toolclass.ExecShell {
		if cmd, _ := c.Args["command"].(string); cmd != "" {
			for _, h := range shellparse.SegmentHeads(cmd) {
				if egressHeadRE.MatchString(h) {
					egress = true
					break
				}
			}
		}
	}
	if c.Class == toolclass.MCPCall {
		egress = true
	}
	if !egress {
		return nil
	}
	return &escalation{
		id: "read_then_egress", risk: event.RiskHigh, action: event.ActionConfirm,
		title: "读取敏感信息后发起外部网络访问",
		desc:  "本会话 15 分钟内读取过凭据/敏感文件，现在又要向外部发送数据，可能是数据外泄。",
	}
}
