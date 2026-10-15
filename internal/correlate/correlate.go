// Package correlate implements cross-verification and bypass detection
// (DESIGN.md §13). It matches execution events (from L1/L3) against intent
// events (from L4/hook). Execution with no matching intent is a bypass; a
// blocked intent that still executed is critical.
package correlate

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"xmonitor/internal/event"
)

// window is how long an intent stays matchable against later execution.
const window = 15 * time.Second

type intent struct {
	when    time.Time
	session string
	summary string // normalized command/arg
	blocked bool
	toolID  string
}

// Correlator tracks recent intents per session and flags bypasses.
type Correlator struct {
	emit func(*event.Event)

	mu      sync.Mutex
	intents map[string][]intent // session -> recent intents
}

// New creates a correlator. emit receives alert events.
func New(emit func(*event.Event)) *Correlator {
	return &Correlator{emit: emit, intents: map[string][]intent{}}
}

var quoteStrip = strings.NewReplacer("'", "", "\"", "")

func normalize(s string) string { return quoteStrip.Replace(s) }

// NoteIntent records an intent event (from the gate).
func (c *Correlator) NoteIntent(ev *event.Event) {
	if ev.Tool == nil {
		return
	}
	cmd, _ := ev.Tool.Args["command"].(string)
	summary := cmd
	if summary == "" {
		summary = ev.Matched
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc(ev.Session)
	c.intents[ev.Session] = append(c.intents[ev.Session], intent{
		when: time.Now(), session: ev.Session, summary: normalize(summary),
		blocked: ev.Decision == event.ActionBlock, toolID: ev.ToolCallID,
	})
}

var infraNoise = regexp.MustCompile(`^(git|ps|grep|awk|sed|cat|ls|which|type|env|pwd|echo|node|python3?|dirname|basename|wc|head|tail|sort|uniq|date)\b`)

// NoteExec records an execution event (from L1/L3) and emits a bypass/critical
// alert when it doesn't line up with a recent intent. Returns the alert, if any.
func (c *Correlator) NoteExec(session, command string) *event.Event {
	command = strings.TrimSpace(command)
	if command == "" || infraNoise.MatchString(command) {
		return nil
	}
	norm := normalize(command)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc(session)
	cut := time.Now().Add(-window)
	for i := range c.intents[session] {
		in := c.intents[session][i]
		if in.when.Before(cut) {
			continue
		}
		// The probe sees the real argv, often wrapping the hook's command
		// (eval '<cmd>'), so the hook record is a substring of what ran.
		needle := in.summary
		if len(needle) > 80 {
			needle = needle[:80]
		}
		if needle != "" && strings.Contains(norm, needle) {
			if in.blocked {
				return c.alert(session, command, "blocked_but_executed", event.RiskCritical,
					"被拦截的操作仍被执行", in.toolID)
			}
			return nil // matched a passed intent: fine
		}
	}
	return c.alert(session, command, "hook_bypass", event.RiskHigh,
		"检测到未经意图层审查就执行的命令（疑似绕过监控）", "")
}

func (c *Correlator) alert(session, command, typ string, risk event.Risk, title, toolID string) *event.Event {
	ev := &event.Event{
		Layer: event.LayerL1, Kind: event.KindAlert, Type: typ,
		Session: session, Risk: risk, Title: title, ToolCallID: toolID,
		Fields: map[string]any{"command": clip(command, 400)},
	}
	if c.emit != nil {
		c.emit(ev)
	}
	return ev
}

func (c *Correlator) gc(session string) {
	cut := time.Now().Add(-window)
	xs := c.intents[session]
	i := 0
	for i < len(xs) && xs[i].when.Before(cut) {
		i++
	}
	c.intents[session] = xs[i:]
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// SetEmit sets the alert sink (used when the correlator is created before the
// gate exists).
func (c *Correlator) SetEmit(fn func(*event.Event)) { c.emit = fn }
