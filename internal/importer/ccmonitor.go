// Package importer ingests another monitor's audit database as a read-only
// data source (DESIGN.md "理解 B"). The CC-Monitor importer opens
// ~/.cc-monitor/events.db in mode=ro and maps its rows onto X-Monitor's unified
// event model, so a CC-Monitor instance that keeps running (handling Claude
// Code's hooks) can feed the aggregated X-Monitor dashboard without any change
// to CC-Monitor itself. It never writes to that database.
package importer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"xmonitor/internal/event"
	"xmonitor/internal/toolclass"
)

// Source is a read-only CC-Monitor database.
type Source struct {
	db   *sql.DB
	path string
}

// Open opens the CC-Monitor events.db strictly read-only.
func Open(path string) (*Source, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(true)")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open cc-monitor db %s: %w", path, err)
	}
	return &Source{db: db, path: path}, nil
}

// Close releases the database.
func (s *Source) Close() error { return s.db.Close() }

// Mapped is one imported event plus its CC-Monitor row id (for dedup).
type Mapped struct {
	OrigID int64
	Event  *event.Event
}

// Fetch returns up to limit events with id > afterID, oldest first.
func (s *Source) Fetch(afterID int64, limit int) ([]Mapped, error) {
	if limit <= 0 {
		limit = 500
	}
	// transcript_path exists only on upgraded DBs; select the stable columns.
	rows, err := s.db.Query(
		`SELECT id, ts, session_id, source, tool_name, cwd, risk, matched_rule, decision, detail
		 FROM events WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mapped
	for rows.Next() {
		var id int64
		var ts, sess, source, tool, cwd, risk, rule, decision, detail sql.NullString
		if err := rows.Scan(&id, &ts, &sess, &source, &tool, &cwd, &risk, &rule, &decision, &detail); err != nil {
			return nil, err
		}
		out = append(out, Mapped{OrigID: id, Event: mapRow(id, ts.String, sess.String, source.String,
			tool.String, cwd.String, risk.String, rule.String, decision.String, detail.String)})
	}
	return out, rows.Err()
}

func mapRow(id int64, ts, sess, source, tool, cwd, risk, rule, decision, detail string) *event.Event {
	ev := &event.Event{
		TS:           parseTS(ts),
		Agent:        "claude-code", // CC-Monitor monitors Claude Code
		AgentSession: sess,
		CWD:          cwd,
		Risk:         mapRisk(risk),
		Decision:     mapDecision(decision),
		Rule:         rule,
		DecidedBy:    "cc-monitor",
		Fields:       map[string]any{"imported_from": "cc-monitor", "cc_id": id, "cc_source": source},
	}
	switch source {
	case "hook_pre", "hook_post":
		ev.Layer, ev.Kind, ev.Type = event.LayerHook, event.KindIntent, "tool_use"
		if args := parseDetail(detail); args != nil {
			ev.Tool = &event.Tool{Raw: tool, Class: toolclass.Classify(tool), Args: args}
		}
	default:
		// os_probe / os_net / os_exec and anything else: system-layer observation.
		ev.Layer, ev.Kind = event.LayerL1, event.KindIntent
		ev.Type = sysType(source)
		if args := parseDetail(detail); args != nil {
			for k, v := range args {
				ev.Fields[k] = v
			}
		}
	}
	ev.Title = "CC-Monitor 事件"
	return ev
}

func sysType(source string) string {
	switch source {
	case "os_net":
		return "connect"
	case "os_exec":
		return "execve"
	default:
		return "os_event"
	}
}

func parseDetail(detail string) map[string]any {
	if detail == "" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(detail), &m) == nil {
		return m
	}
	// Non-object detail (e.g. a bare string): wrap it.
	return map[string]any{"detail": detail}
}

func parseTS(ts string) int64 {
	for _, layout := range []string{"2006-01-02T15:04:05-0700", "2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.UnixMilli()
		}
	}
	return time.Now().UnixMilli()
}

func mapRisk(r string) event.Risk {
	switch r {
	case "critical":
		return event.RiskCritical
	case "high":
		return event.RiskHigh
	case "medium":
		return event.RiskMedium
	case "low":
		return event.RiskLow
	default:
		return event.RiskInfo
	}
}

func mapDecision(d string) event.Action {
	switch d {
	case "blocked":
		return event.ActionBlock
	case "pending_confirm":
		return event.ActionConfirm
	case "allowed":
		return event.ActionAllow
	default:
		return event.ActionLog
	}
}
