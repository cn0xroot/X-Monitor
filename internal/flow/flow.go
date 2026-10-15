// Package flow turns one session's audit events into the operation flow shown
// under the dashboard timeline: turns of operation cards, each with an outcome.
//
// Adapted in spirit from CC-Monitor's sessionFlow (MIT License, see NOTICE).
// CC-Monitor splits turns on the user's prompts and pairs hook pre/post records
// using Claude Code's transcript. X-Monitor works on any agent and does not see
// transcripts, so turns are split on idle gaps instead, and outcomes are what the
// monitor itself decided (allowed / approved / blocked / denied), not whether
// the tool later succeeded.
package flow

import (
	"encoding/json"
	"sort"
	"strings"

	"xmonitor/internal/event"
	"xmonitor/internal/toolclass"
)

// TurnGapMs: an idle gap longer than this starts a new turn.
const TurnGapMs = 5 * 60 * 1000

// GroupMin: this many consecutive observations of one kind collapse into one card.
const GroupMin = 3

// maxGroupIDs caps the event ids carried on a collapsed card.
const maxGroupIDs = 50

// Node types.
const (
	TypeOp      = "op"      // a tool call vetted by the proxy / hook
	TypeObserve = "observe" // a system-layer observation (L1 / L2 / L3)
	TypeAlert   = "alert"
	TypeGroup   = "group" // several consecutive observations folded together
)

// Statuses.
const (
	StatusOK       = "ok"
	StatusApproved = "approved" // allowed after a human confirmed
	StatusBlocked  = "blocked"
	StatusDenied   = "denied" // a human refused, or the confirmation timed out
	StatusWarn     = "warn"
	StatusObserved = "observed"
)

// Node is one card.
type Node struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Layer    string   `json:"layer"`
	Layers   []string `json:"layers,omitempty"` // every layer that audited this call (proxy + hook)
	Tool     string   `json:"tool"`
	Class    string   `json:"class"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	StartTS  int64    `json:"startTs"`
	EndTS    int64    `json:"endTs"`
	Risk     string   `json:"risk"`
	Decision string   `json:"decision"`
	Status   string   `json:"status"`
	Rule     string   `json:"rule"`
	Branch   bool     `json:"branch"`
	Count    int      `json:"count"`
	EventIDs []string `json:"eventIds"`
}

// Turn is a run of nodes without a long idle gap.
type Turn struct {
	Index   int    `json:"index"`
	StartTS int64  `json:"startTs"`
	EndTS   int64  `json:"endTs"`
	Nodes   []Node `json:"nodes"`
}

// Flow is the whole response.
type Flow struct {
	SessionID  string `json:"sessionId"`
	Agent      string `json:"agent"`
	CWD        string `json:"cwd"`
	EventCount int    `json:"eventCount"`
	Truncated  bool   `json:"truncated"`
	Turns      []Turn `json:"turns"`
}

var riskRank = map[string]int{"": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func worse(a, b string) string {
	if riskRank[b] > riskRank[a] {
		return b
	}
	return a
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// summaryOf picks the most telling argument of a tool call.
func summaryOf(t *event.Tool) string {
	if t == nil {
		return ""
	}
	for _, k := range []string{"command", "file_path", "url", "query", "pattern"} {
		if s := str(t.Args, k); s != "" {
			return clip(s, 300)
		}
	}
	if len(t.Args) == 0 {
		return ""
	}
	b, _ := json.Marshal(t.Args)
	return clip(string(b), 300)
}

// observeSummary describes a system-layer event.
func observeSummary(e *event.Event) string {
	f := e.Fields
	switch {
	case str(f, "command") != "":
		return clip(str(f, "command"), 300)
	case str(f, "cmdline") != "":
		return clip(str(f, "cmdline"), 300)
	case str(f, "path") != "":
		return clip(str(f, "path"), 300)
	case str(f, "ip") != "":
		s := str(f, "ip")
		if p, ok := f["port"].(float64); ok {
			s += ":" + itoa(int(p))
		}
		if h := str(f, "host"); h != "" {
			s = h + " (" + s + ")"
		}
		return s
	}
	return "" // the card's title already says what happened; don't repeat it
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func nodeFor(e *event.Event) Node {
	n := Node{
		ID: e.ID, Layer: e.Layer, Layers: []string{e.Layer}, StartTS: e.TS, Risk: string(e.Risk),
		Decision: string(e.Decision), Rule: e.Rule, Count: 1, EventIDs: []string{e.ID}, Title: e.Title,
	}
	switch {
	case e.Kind == event.KindIntent && e.Tool != nil:
		n.Type, n.Tool, n.Class = TypeOp, e.Tool.Raw, e.Tool.Class
		n.Summary = summaryOf(e.Tool)
		n.Branch = e.Tool.Class == toolclass.AgentSpawn
		approval := str(e.Fields, "approval")
		switch {
		case e.Decision == event.ActionBlock && (approval == "denied" || approval == "expired"):
			n.Status = StatusDenied
		case e.Decision == event.ActionBlock:
			n.Status = StatusBlocked
		case approval == "allowed":
			n.Status = StatusApproved
		default:
			n.Status = StatusOK
		}
	case e.Kind == event.KindAlert:
		n.Type, n.Tool = TypeAlert, e.Type
		n.Summary = observeSummary(e)
		if e.Decision == event.ActionBlock {
			n.Status = StatusBlocked
		} else {
			n.Status = StatusWarn
		}
	default:
		n.Type, n.Tool = TypeObserve, e.Type
		n.Summary = observeSummary(e)
		n.Status = StatusObserved
		if e.Type == "silent_sensitive_write" || e.Risk == event.RiskHigh || e.Risk == event.RiskCritical {
			n.Status = StatusWarn
		}
	}
	return n
}

// Build assembles the flow from a lane's events (chronological order).
func Build(events []*event.Event, truncated bool) *Flow {
	f := &Flow{EventCount: len(events), Truncated: truncated, Turns: []Turn{}}
	if len(events) > 0 {
		last := events[len(events)-1]
		f.SessionID, f.Agent, f.CWD = last.Session, last.Agent, last.CWD
		for _, e := range events { // the first event that knows a cwd wins
			if f.CWD == "" {
				f.CWD = e.CWD
			}
			if f.Agent == "" {
				f.Agent = e.Agent
			}
		}
	}

	// 1) one node per event; a call re-audited by the hook folds into the node
	// the proxy already created.
	var nodes []Node
	byEvent := map[string]int{}
	for _, e := range events {
		if from := str(e.Fields, "reused_from"); from != "" {
			if i, ok := byEvent[from]; ok {
				nodes[i].EventIDs = append(nodes[i].EventIDs, e.ID)
				nodes[i].Layers = appendUnique(nodes[i].Layers, e.Layer)
				continue
			}
		}
		n := nodeFor(e)
		byEvent[e.ID] = len(nodes)
		nodes = append(nodes, n)
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].StartTS < nodes[j].StartTS })

	// 2) fold runs of identical observations.
	nodes = group(nodes)

	// 3) split into turns on idle gaps.
	var cur *Turn
	var lastTS int64
	for _, n := range nodes {
		if cur == nil || n.StartTS-lastTS > TurnGapMs {
			f.Turns = append(f.Turns, Turn{Index: len(f.Turns) + 1, StartTS: n.StartTS, Nodes: []Node{}})
			cur = &f.Turns[len(f.Turns)-1]
		}
		cur.Nodes = append(cur.Nodes, n)
		end := n.StartTS
		if n.EndTS > end {
			end = n.EndTS
		}
		cur.EndTS = end
		lastTS = end
	}
	return f
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// group folds runs of GroupMin or more consecutive observations of the same
// layer and kind into a single card.
func group(nodes []Node) []Node {
	var out []Node
	for i := 0; i < len(nodes); {
		n := nodes[i]
		if n.Type != TypeObserve {
			out = append(out, n)
			i++
			continue
		}
		j := i
		for j < len(nodes) && nodes[j].Type == TypeObserve && nodes[j].Layer == n.Layer && nodes[j].Tool == n.Tool {
			j++
		}
		run := nodes[i:j]
		if len(run) < GroupMin {
			out = append(out, run...)
			i = j
			continue
		}
		g := Node{
			ID: run[0].ID, Type: TypeGroup, Layer: n.Layer, Layers: n.Layers, Tool: n.Tool, Title: n.Title,
			StartTS: run[0].StartTS, EndTS: run[len(run)-1].StartTS, Count: len(run), Status: StatusObserved,
			Summary: run[0].Summary,
		}
		for k, r := range run {
			g.Risk = worse(g.Risk, r.Risk)
			if r.Status == StatusWarn {
				g.Status = StatusWarn
			}
			if k < maxGroupIDs {
				g.EventIDs = append(g.EventIDs, r.EventIDs...)
			}
		}
		if len(g.EventIDs) > maxGroupIDs {
			g.EventIDs = g.EventIDs[:maxGroupIDs]
		}
		out = append(out, g)
		i = j
	}
	return out
}

// Label is a convenience for callers that need a short name.
func Label(f *Flow) string {
	if f.CWD != "" {
		parts := strings.Split(strings.TrimRight(f.CWD, "/"), "/")
		return parts[len(parts)-1]
	}
	return f.Agent
}
