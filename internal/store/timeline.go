package store

import (
	"database/sql"
	"path"
	"sort"
	"strings"

	"xmonitor/internal/event"
)

// laneExpr is the SQL expression that assigns an event to a swim lane:
//
//	zs_…            a session managed by `xmon run`
//	ext:<id>        a session imported from another monitor (CC-Monitor)
//	agent:<agent>   an agent we saw but did not launch (all its activity in one lane)
//	unattributed    everything else
const laneExpr = `CASE
	WHEN session != '' THEN session
	WHEN COALESCE(json_extract(body, '$.agent_session'), '') != '' THEN 'ext:' || json_extract(body, '$.agent_session')
	WHEN agent != '' THEN 'agent:' || agent
	ELSE 'unattributed' END`

// TLBucket is one time slot of a lane. Risk is kept as a composition (not an
// average): a single high-risk event must stay visible among many harmless ones.
type TLBucket struct {
	StartMs  int64 `json:"startMs"`
	N        int64 `json:"n"`
	NHigh    int64 `json:"nHigh"` // high + critical
	NMedium  int64 `json:"nMedium"`
	NLow     int64 `json:"nLow"`
	NInfo    int64 `json:"nInfo"`
	NBlocked int64 `json:"nBlocked"`
}

// TLLane is one swim lane.
type TLLane struct {
	SessionID    string     `json:"sessionId"`
	Label        string     `json:"label"`
	Agent        string     `json:"agent"`
	CWD          string     `json:"cwd"`
	Managed      bool       `json:"managed"`
	EventCount   int64      `json:"eventCount"`
	BlockedCount int64      `json:"blockedCount"`
	BypassCount  int64      `json:"bypassCount"`
	FirstTS      int64      `json:"firstTs"`
	LastTS       int64      `json:"lastTs"`
	Buckets      []TLBucket `json:"buckets"`
}

// Timeline is the multi-session timeline.
type Timeline struct {
	RangeMinutes int      `json:"rangeMinutes"`
	BucketMs     int64    `json:"bucketMs"`
	Now          int64    `json:"now"`
	Lanes        []TLLane `json:"lanes"`
}

// BucketSizeFor picks the slot width for a window; fixed steps (not free input)
// keep the chart from having too many or too few columns.
func BucketSizeFor(rangeMinutes int) int64 {
	switch {
	case rangeMinutes <= 60:
		return 60 * 1000
	case rangeMinutes <= 6*60:
		return 5 * 60 * 1000
	case rangeMinutes <= 24*60:
		return 15 * 60 * 1000
	}
	return 2 * 60 * 60 * 1000
}

// Timeline aggregates the last rangeMinutes into per-lane buckets. Process-spawn
// inventory events (L3) are excluded: they are bookkeeping and would drown out
// the lanes; they still appear in a session's flow view.
func (s *Store) Timeline(rangeMinutes int, now int64, maxLanes int) (*Timeline, error) {
	if maxLanes <= 0 || maxLanes > 100 {
		maxLanes = 50
	}
	bucket := BucketSizeFor(rangeMinutes)
	since := now - int64(rangeMinutes)*60*1000
	tl := &Timeline{RangeMinutes: rangeMinutes, BucketMs: bucket, Now: now, Lanes: []TLLane{}}

	rows, err := s.db.Query(`SELECT `+laneExpr+` AS lane, COUNT(*), MIN(ts), MAX(ts),
			SUM(CASE WHEN kind = 'intent' AND decision = 'block' THEN 1 ELSE 0 END),
			SUM(CASE WHEN type IN ('hook_bypass','silent_sensitive_write','blocked_but_executed') THEN 1 ELSE 0 END),
			COALESCE(MAX(json_extract(body, '$.cwd')), ''), COALESCE(MAX(agent), '')
		FROM events WHERE ts >= ? AND type != 'proc_spawn'
		GROUP BY lane ORDER BY MAX(ts) DESC LIMIT ?`, since, maxLanes)
	if err != nil {
		return nil, err
	}
	index := map[string]*TLLane{}
	for rows.Next() {
		var l TLLane
		var blocked, bypass sql.NullInt64
		if err := rows.Scan(&l.SessionID, &l.EventCount, &l.FirstTS, &l.LastTS, &blocked, &bypass, &l.CWD, &l.Agent); err != nil {
			rows.Close()
			return nil, err
		}
		l.BlockedCount, l.BypassCount = blocked.Int64, bypass.Int64
		l.Managed = strings.HasPrefix(l.SessionID, "zs_")
		l.Buckets = []TLBucket{}
		tl.Lanes = append(tl.Lanes, l)
	}
	rows.Close()
	for i := range tl.Lanes {
		index[tl.Lanes[i].SessionID] = &tl.Lanes[i]
	}

	// Managed sessions know their own cwd/agent more reliably than their events.
	for id, l := range index {
		if !l.Managed {
			continue
		}
		if ss, err := s.GetSession(id); err == nil && ss != nil {
			if ss.CWD != "" {
				l.CWD = ss.CWD
			}
			if ss.Agent != "" {
				l.Agent = ss.Agent
			}
		}
	}
	for _, l := range index {
		l.Label = laneLabel(l)
	}

	brows, err := s.db.Query(`SELECT `+laneExpr+` AS lane, (ts / ?1) * ?1 AS b, COUNT(*),
			SUM(CASE WHEN risk IN ('critical','high') THEN 1 ELSE 0 END),
			SUM(CASE WHEN risk = 'medium' THEN 1 ELSE 0 END),
			SUM(CASE WHEN risk = 'low' THEN 1 ELSE 0 END),
			SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END)
		FROM events WHERE ts >= ?2 AND type != 'proc_spawn' GROUP BY lane, b`, bucket, since)
	if err != nil {
		return nil, err
	}
	defer brows.Close()
	for brows.Next() {
		var lane string
		var b TLBucket
		var hi, med, low, blk sql.NullInt64
		if err := brows.Scan(&lane, &b.StartMs, &b.N, &hi, &med, &low, &blk); err != nil {
			return nil, err
		}
		l := index[lane]
		if l == nil {
			continue // lane beyond the limit
		}
		b.NHigh, b.NMedium, b.NLow, b.NBlocked = hi.Int64, med.Int64, low.Int64, blk.Int64
		b.NInfo = b.N - b.NHigh - b.NMedium - b.NLow
		l.Buckets = append(l.Buckets, b)
	}
	if err := brows.Err(); err != nil {
		return nil, err
	}
	for i := range tl.Lanes {
		bs := tl.Lanes[i].Buckets
		sort.Slice(bs, func(a, b int) bool { return bs[a].StartMs < bs[b].StartMs })
	}
	return tl, nil
}

func laneLabel(l *TLLane) string {
	if l.CWD != "" {
		if b := path.Base(strings.TrimRight(l.CWD, "/")); b != "" && b != "." && b != "/" {
			return b
		}
	}
	switch {
	case strings.HasPrefix(l.SessionID, "agent:"):
		return strings.TrimPrefix(l.SessionID, "agent:")
	case l.SessionID == "unattributed":
		return ""
	}
	return l.Agent
}

// LaneEvents returns the events of one lane in chronological order (the most
// recent `limit` of them) and whether older events were cut off.
func (s *Store) LaneEvents(lane string, limit int) ([]*event.Event, bool, error) {
	if limit <= 0 {
		limit = 3000
	}
	rows, err := s.db.Query(`SELECT seq, body, prev_hash, hash FROM events WHERE `+laneExpr+` = ?
		ORDER BY seq DESC LIMIT ?`, lane, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []*event.Event
	for rows.Next() {
		var seq int64
		var body, prev, hash string
		if err := rows.Scan(&seq, &body, &prev, &hash); err != nil {
			return nil, false, err
		}
		ev := &event.Event{}
		if jsonUnmarshal(body, ev) != nil {
			continue
		}
		ev.Seq, ev.PrevHash, ev.Hash = seq, prev, hash
		out = append(out, ev)
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { // oldest first
		out[i], out[j] = out[j], out[i]
	}
	return out, truncated, rows.Err()
}
