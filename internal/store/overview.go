package store

import (
	"database/sql"
	"sort"

	"xmonitor/internal/event"
)

// RuleStat is how often one rule fired, split by outcome.
type RuleStat struct {
	Rule    string `json:"rule"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Confirm int64  `json:"confirm"`
}

// Bucket is one timeline slot.
type Bucket struct {
	TS      int64 `json:"ts"` // slot start, unix ms
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// Overview is the raw aggregate behind the dashboard's home page. Threat
// categories are derived from ByRule / ByAlert by the caller, which owns the
// rule set; the store only counts.
type Overview struct {
	Since        int64            `json:"since"`
	Events       int64            `json:"events"`
	ToolCalls    int64            `json:"tool_calls"`
	Alerts       int64            `json:"alerts"`
	ByLayer      map[string]int64 `json:"by_layer"`
	ByRisk       map[string]int64 `json:"by_risk"`
	ByDecision   map[string]int64 `json:"by_decision"`
	ByAgent      map[string]int64 `json:"by_agent"`
	ByToolClass  map[string]int64 `json:"by_tool_class"`
	ByAlert      map[string]int64 `json:"by_alert"`
	ByRule       []RuleStat       `json:"by_rule"`
	Timeline     []Bucket         `json:"timeline"`
	SessionsRun  int64            `json:"sessions_running"`
	SessionsAll  int64            `json:"sessions_total"`
	Pending      int64            `json:"pending_approvals"`
	RecentBlocks []*event.Event   `json:"recent_blocked"`
}

// groupCount fills m from a two-column (key, count) query.
func (s *Store) groupCount(m map[string]int64, q string, args ...any) error {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k sql.NullString
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		if k.Valid && k.String != "" {
			m[k.String] = n
		}
	}
	return rows.Err()
}

// Overview aggregates everything the home page shows for [since, now]. slots is
// the number of timeline buckets (the bucket width is derived from the span).
func (s *Store) Overview(since, now int64, slots int) (*Overview, error) {
	o := &Overview{
		Since: since, ByLayer: map[string]int64{}, ByRisk: map[string]int64{}, ByDecision: map[string]int64{},
		ByAgent: map[string]int64{}, ByToolClass: map[string]int64{}, ByAlert: map[string]int64{},
		ByRule: []RuleStat{}, Timeline: []Bucket{}, RecentBlocks: []*event.Event{},
	}
	one := func(dst *int64, q string, args ...any) { _ = s.db.QueryRow(q, args...).Scan(dst) }
	one(&o.Events, `SELECT COUNT(*) FROM events WHERE ts >= ?`, since)
	one(&o.Alerts, `SELECT COUNT(*) FROM events WHERE ts >= ? AND kind = 'alert'`, since)
	// A call vetted by the proxy and again by the hook is audited twice; the
	// second record carries reused_from and must not be counted as another call.
	const notReused = ` AND json_extract(body, '$.fields.reused_from') IS NULL`
	one(&o.ToolCalls, `SELECT COUNT(*) FROM events WHERE ts >= ? AND kind = 'intent' AND type = 'tool_use'`+notReused, since)
	one(&o.Pending, `SELECT COUNT(*) FROM approvals WHERE status = 'pending'`)
	one(&o.SessionsAll, `SELECT COUNT(*) FROM sessions WHERE started_at >= ? OR ended_at IS NULL`, since)
	one(&o.SessionsRun, `SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL`)

	for _, g := range []struct {
		m map[string]int64
		q string
	}{
		{o.ByLayer, `SELECT layer, COUNT(*) FROM events WHERE ts >= ?1 GROUP BY layer`},
		{o.ByRisk, `SELECT risk, COUNT(*) FROM events WHERE ts >= ?1 GROUP BY risk`},
		{o.ByDecision, `SELECT decision, COUNT(*) FROM events WHERE ts >= ?1 AND kind = 'intent' AND decision != '' GROUP BY decision`},
		{o.ByAgent, `SELECT agent, COUNT(*) FROM events WHERE ts >= ?1 AND agent != '' GROUP BY agent`},
		{o.ByAlert, `SELECT type, COUNT(*) FROM events WHERE ts >= ?1 AND kind = 'alert' GROUP BY type`},
		{o.ByToolClass, `SELECT json_extract(body, '$.tool.class'), COUNT(*) FROM events
			WHERE ts >= ?1 AND kind = 'intent' AND type = 'tool_use'` + notReused + ` GROUP BY 1`},
	} {
		if err := s.groupCount(g.m, g.q, since); err != nil {
			return nil, err
		}
	}

	rows, err := s.db.Query(`SELECT rule, decision, COUNT(*) FROM events
		WHERE ts >= ? AND kind = 'intent' AND rule != '' GROUP BY rule, decision`+"", since)
	if err != nil {
		return nil, err
	}
	byRule := map[string]*RuleStat{}
	for rows.Next() {
		var rule, dec string
		var n int64
		if err := rows.Scan(&rule, &dec, &n); err != nil {
			rows.Close()
			return nil, err
		}
		rs := byRule[rule]
		if rs == nil {
			rs = &RuleStat{Rule: rule}
			byRule[rule] = rs
		}
		rs.Total += n
		switch dec {
		case "block":
			rs.Blocked += n
		case "confirm":
			rs.Confirm += n
		}
	}
	rows.Close()
	for _, rs := range byRule {
		o.ByRule = append(o.ByRule, *rs)
	}
	sort.Slice(o.ByRule, func(i, j int) bool {
		if o.ByRule[i].Total != o.ByRule[j].Total {
			return o.ByRule[i].Total > o.ByRule[j].Total
		}
		return o.ByRule[i].Rule < o.ByRule[j].Rule
	})

	// Timeline: fixed-width slots covering [since, now], zero-filled.
	if slots < 1 {
		slots = 24
	}
	span := now - since
	if span <= 0 {
		span = 1
	}
	width := span / int64(slots)
	if width < 1000 {
		width = 1000
	}
	counts := map[int64]*Bucket{}
	trows, err := s.db.Query(`SELECT (ts - ?1) / ?2 AS slot, COUNT(*), SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END)
		FROM events WHERE ts >= ?1 AND kind = 'intent' GROUP BY slot`, since, width)
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		var slot, total int64
		var blocked sql.NullInt64
		if err := trows.Scan(&slot, &total, &blocked); err != nil {
			trows.Close()
			return nil, err
		}
		counts[slot] = &Bucket{Total: total, Blocked: blocked.Int64}
	}
	trows.Close()
	for i := int64(0); i < int64(slots); i++ {
		b := Bucket{TS: since + i*width}
		if c, ok := counts[i]; ok {
			b.Total, b.Blocked = c.Total, c.Blocked
		}
		o.Timeline = append(o.Timeline, b)
	}

	blocked, err := s.ListEvents(Query{Since: since, Kind: "intent", Decision: "block", Desc: true, Limit: 20})
	if err != nil {
		return nil, err
	}
	o.RecentBlocks = blocked
	return o, nil
}
