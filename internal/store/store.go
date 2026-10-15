// Package store persists events, sessions, approvals and allow-lists in
// SQLite (pure Go, no CGO). Events form a hash chain for tamper evidence
// (DESIGN.md §15).
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"xmonitor/internal/event"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  ts INTEGER NOT NULL,
  layer TEXT, kind TEXT, type TEXT,
  agent TEXT, session TEXT, tool_call_id TEXT,
  risk TEXT, decision TEXT, rule TEXT,
  body TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
CREATE INDEX IF NOT EXISTS idx_events_tool_call ON events(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  agent TEXT, cwd TEXT, argv TEXT, root_pid INTEGER,
  upstreams TEXT,
  started_at INTEGER NOT NULL, ended_at INTEGER,
  exit_code INTEGER
);

CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  session TEXT, agent TEXT, tool_call_id TEXT,
  tool_raw TEXT, tool_class TEXT, summary TEXT,
  rule TEXT, risk TEXT, reason TEXT, glm TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  resolved_at INTEGER, resolved_via TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS allow_list (
  session TEXT NOT NULL,
  rule TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  PRIMARY KEY (session, rule)
);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
`

// Genesis is the prev_hash of the first event.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Store wraps the database. Writes to events are serialized so the hash chain
// stays linear; only xmond writes to it.
type Store struct {
	db   *sql.DB
	mu   sync.Mutex
	head string
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s := &Store{db: db, head: Genesis}
	var h sql.NullString
	if err := db.QueryRow(`SELECT hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&h); err == nil && h.Valid {
		s.head = h.String
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// canonicalBody is the event serialized without seq/prev_hash/hash.
func canonicalBody(ev *event.Event) ([]byte, error) {
	c := *ev
	c.Seq, c.PrevHash, c.Hash = 0, "", ""
	return json.Marshal(&c)
}

func chainHash(prev string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Append writes an event, filling ID/TS/Seq/PrevHash/Hash.
func (s *Store) Append(ev *event.Event) error {
	if ev.ID == "" {
		ev.ID = event.NewID("ev_")
	}
	if ev.TS == 0 {
		ev.TS = event.Now()
	}
	if ev.Risk == "" {
		ev.Risk = event.RiskInfo
	}
	body, err := canonicalBody(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := chainHash(s.head, body)
	res, err := s.db.Exec(`INSERT INTO events(id,ts,layer,kind,type,agent,session,tool_call_id,risk,decision,rule,body,prev_hash,hash)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.TS, ev.Layer, ev.Kind, ev.Type, ev.Agent, ev.Session, ev.ToolCallID,
		string(ev.Risk), string(ev.Decision), ev.Rule, string(body), s.head, hash)
	if err != nil {
		return err
	}
	ev.Seq, _ = res.LastInsertId()
	ev.PrevHash, ev.Hash = s.head, hash
	s.head = hash
	return nil
}

// Query filters for ListEvents.
type Query struct {
	After   int64 // seq > After
	Limit   int
	MinRisk event.Risk
	Session string
	ToolID  string
	Desc    bool

	Since    int64    // ts >= Since (unix ms)
	Kind     string   // event kind (intent, alert, ...)
	Decision string   // allow | block | confirm
	Rules    []string // rule IN (...) ...
	Types    []string // ... OR type IN (...) (either list may be empty; both empty = no filter)

	// Exact-match filters (combined with AND), used when a dashboard number is
	// clicked: the list must be exactly the set of events that number counted.
	Layers    []string // layer IN (...)
	TypeIn    []string // type IN (...)
	Agent     string
	ToolClass string // tool.class of tool_use events
	RiskEq    string // risk = ... (MinRisk is "at least")
	Rule      string
	NoReused  bool // skip hook records that merely re-audit a call the proxy already vetted
}

// ListEvents returns events matching q.
func (s *Store) ListEvents(q Query) ([]*event.Event, error) {
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 200
	}
	var where []string
	var args []any
	if q.After > 0 {
		where = append(where, "seq > ?")
		args = append(args, q.After)
	}
	if q.Session != "" {
		where = append(where, "session = ?")
		args = append(args, q.Session)
	}
	if q.ToolID != "" {
		where = append(where, "tool_call_id = ?")
		args = append(args, q.ToolID)
	}
	if q.Since > 0 {
		where = append(where, "ts >= ?")
		args = append(args, q.Since)
	}
	if q.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, q.Kind)
	}
	if q.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, q.Decision)
	}
	if len(q.Rules) > 0 || len(q.Types) > 0 {
		var ors []string
		if len(q.Rules) > 0 {
			ors = append(ors, "rule IN ("+placeholders(len(q.Rules))+")")
			for _, r := range q.Rules {
				args = append(args, r)
			}
		}
		if len(q.Types) > 0 {
			ors = append(ors, "type IN ("+placeholders(len(q.Types))+")")
			for _, t := range q.Types {
				args = append(args, t)
			}
		}
		where = append(where, "("+strings.Join(ors, " OR ")+")")
	}
	if len(q.Layers) > 0 {
		where = append(where, "layer IN ("+placeholders(len(q.Layers))+")")
		for _, l := range q.Layers {
			args = append(args, l)
		}
	}
	if len(q.TypeIn) > 0 {
		where = append(where, "type IN ("+placeholders(len(q.TypeIn))+")")
		for _, t := range q.TypeIn {
			args = append(args, t)
		}
	}
	if q.Agent != "" {
		where = append(where, "agent = ?")
		args = append(args, q.Agent)
	}
	if q.ToolClass != "" {
		where = append(where, "json_extract(body, '$.tool.class') = ?")
		args = append(args, q.ToolClass)
	}
	if q.RiskEq != "" {
		where = append(where, "risk = ?")
		args = append(args, q.RiskEq)
	}
	if q.Rule != "" {
		where = append(where, "rule = ?")
		args = append(args, q.Rule)
	}
	if q.NoReused {
		where = append(where, "json_extract(body, '$.fields.reused_from') IS NULL")
	}
	if q.MinRisk != "" {
		var rs []string
		for _, r := range []event.Risk{event.RiskInfo, event.RiskLow, event.RiskMedium, event.RiskHigh, event.RiskCritical} {
			if r.Rank() >= q.MinRisk.Rank() {
				rs = append(rs, "'"+string(r)+"'")
			}
		}
		where = append(where, "risk IN ("+strings.Join(rs, ",")+")")
	}
	sqlq := "SELECT seq, body, prev_hash, hash FROM events"
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Desc {
		sqlq += " ORDER BY seq DESC"
	} else {
		sqlq += " ORDER BY seq ASC"
	}
	sqlq += fmt.Sprintf(" LIMIT %d", q.Limit)
	rows, err := s.db.Query(sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*event.Event{}
	for rows.Next() {
		var seq int64
		var body, prev, hash string
		if err := rows.Scan(&seq, &body, &prev, &hash); err != nil {
			return nil, err
		}
		ev := &event.Event{}
		if err := json.Unmarshal([]byte(body), ev); err != nil {
			continue
		}
		ev.Seq, ev.PrevHash, ev.Hash = seq, prev, hash
		out = append(out, ev)
	}
	return out, rows.Err()
}

// VerifyResult is the outcome of a chain verification.
type VerifyResult struct {
	Checked  int64  `json:"checked"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
	Head     string `json:"head"`
}

// VerifyChain recomputes every hash in order.
func (s *Store) VerifyChain() (VerifyResult, error) {
	rows, err := s.db.Query(`SELECT seq, body, prev_hash, hash FROM events ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	prev := s.ChainAnchor() // Genesis unless old events were pruned
	var r VerifyResult
	r.OK = true
	for rows.Next() {
		var seq int64
		var body, p, h string
		if err := rows.Scan(&seq, &body, &p, &h); err != nil {
			return r, err
		}
		r.Checked++
		if p != prev {
			return VerifyResult{Checked: r.Checked, BrokenAt: seq, Problem: "prev_hash does not link to previous event (row deleted or reordered)", Head: prev}, nil
		}
		if chainHash(p, []byte(body)) != h {
			return VerifyResult{Checked: r.Checked, BrokenAt: seq, Problem: "hash mismatch (row modified)", Head: prev}, nil
		}
		prev = h
	}
	r.Head = prev
	return r, rows.Err()
}

// ---- sessions ----

// Session is a monitored agent run.
type Session struct {
	ID        string            `json:"id"`
	Agent     string            `json:"agent"`
	CWD       string            `json:"cwd"`
	Argv      []string          `json:"argv,omitempty"`
	RootPID   int               `json:"root_pid,omitempty"`
	Upstreams map[string]string `json:"upstreams,omitempty"`
	StartedAt int64             `json:"started_at"`
	EndedAt   int64             `json:"ended_at,omitempty"`
	ExitCode  *int              `json:"exit_code,omitempty"`
}

// PutSession inserts or replaces a session.
func (s *Store) PutSession(ss *Session) error {
	argv, _ := json.Marshal(ss.Argv)
	ups, _ := json.Marshal(ss.Upstreams)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO sessions(id,agent,cwd,argv,root_pid,upstreams,started_at,ended_at,exit_code)
		VALUES(?,?,?,?,?,?,?,?,?)`, ss.ID, ss.Agent, ss.CWD, string(argv), ss.RootPID, string(ups), ss.StartedAt, nullInt(ss.EndedAt), ss.ExitCode)
	return err
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// GetSession loads a session by id.
func (s *Store) GetSession(id string) (*Session, error) {
	rows, err := s.db.Query(`SELECT id,agent,cwd,argv,root_pid,upstreams,started_at,ended_at,exit_code FROM sessions WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanSessions(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return list[0], nil
}

// ListSessions returns the most recent sessions.
func (s *Store) ListSessions(limit int) ([]*Session, error) {
	rows, err := s.db.Query(`SELECT id,agent,cwd,argv,root_pid,upstreams,started_at,ended_at,exit_code FROM sessions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]*Session, error) {
	out := []*Session{}
	for rows.Next() {
		var ss Session
		var argv, ups sql.NullString
		var pid sql.NullInt64
		var ended, code sql.NullInt64
		if err := rows.Scan(&ss.ID, &ss.Agent, &ss.CWD, &argv, &pid, &ups, &ss.StartedAt, &ended, &code); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(argv.String), &ss.Argv)
		_ = json.Unmarshal([]byte(ups.String), &ss.Upstreams)
		ss.RootPID = int(pid.Int64)
		ss.EndedAt = ended.Int64
		if code.Valid {
			c := int(code.Int64)
			ss.ExitCode = &c
		}
		out = append(out, &ss)
	}
	return out, rows.Err()
}

// ---- approvals ----

// Approval is a pending or resolved confirmation request.
type Approval struct {
	ID          int64  `json:"id"`
	TS          int64  `json:"ts"`
	Session     string `json:"session"`
	Agent       string `json:"agent"`
	ToolCallID  string `json:"tool_call_id"`
	ToolRaw     string `json:"tool_raw"`
	ToolClass   string `json:"tool_class"`
	Summary     string `json:"summary"`
	Rule        string `json:"rule"`
	Risk        string `json:"risk"`
	Reason      string `json:"reason"`
	GLM         string `json:"glm,omitempty"`
	Status      string `json:"status"` // pending | allowed | denied | expired
	ResolvedAt  int64  `json:"resolved_at,omitempty"`
	ResolvedVia string `json:"resolved_via,omitempty"`
}

// CreateApproval inserts a pending approval and returns its id.
func (s *Store) CreateApproval(a *Approval) (int64, error) {
	if a.TS == 0 {
		a.TS = event.Now()
	}
	res, err := s.db.Exec(`INSERT INTO approvals(ts,session,agent,tool_call_id,tool_raw,tool_class,summary,rule,risk,reason,glm,status)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending')`, a.TS, a.Session, a.Agent, a.ToolCallID, a.ToolRaw, a.ToolClass, a.Summary, a.Rule, a.Risk, a.Reason, a.GLM)
	if err != nil {
		return 0, err
	}
	a.ID, _ = res.LastInsertId()
	a.Status = "pending"
	return a.ID, nil
}

// ErrNotPending is returned when resolving an approval that is already resolved.
var ErrNotPending = errors.New("approval is not pending")

// ResolveApproval moves a pending approval to status.
func (s *Store) ResolveApproval(id int64, status, via string) error {
	res, err := s.db.Exec(`UPDATE approvals SET status=?, resolved_at=?, resolved_via=? WHERE id=? AND status='pending'`,
		status, event.Now(), via, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotPending
	}
	return nil
}

// ListApprovals returns approvals with the given status ("" = all), newest first.
func (s *Store) ListApprovals(status string, limit int) ([]*Approval, error) {
	q := `SELECT id,ts,session,agent,tool_call_id,tool_raw,tool_class,summary,rule,risk,reason,COALESCE(glm,''),status,COALESCE(resolved_at,0),COALESCE(resolved_via,'') FROM approvals`
	var args []any
	if status != "" {
		q += " WHERE status=?"
		args = append(args, status)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Approval{}
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.TS, &a.Session, &a.Agent, &a.ToolCallID, &a.ToolRaw, &a.ToolClass, &a.Summary,
			&a.Rule, &a.Risk, &a.Reason, &a.GLM, &a.Status, &a.ResolvedAt, &a.ResolvedVia); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// ExpireStalePending marks approvals left pending by a previous daemon run.
func (s *Store) ExpireStalePending() error {
	_, err := s.db.Exec(`UPDATE approvals SET status='expired', resolved_at=?, resolved_via='restart' WHERE status='pending'`, event.Now())
	return err
}

// ---- allow list ----

// AllowForSession records "always allow rule in this session".
func (s *Store) AllowForSession(session, rule string, ttl time.Duration) error {
	var exp any
	if ttl > 0 {
		exp = time.Now().Add(ttl).UnixMilli()
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO allow_list(session,rule,created_at,expires_at) VALUES(?,?,?,?)`,
		session, rule, event.Now(), exp)
	return err
}

// IsAllowedForSession reports whether rule is always-allowed in session.
func (s *Store) IsAllowedForSession(session, rule string) bool {
	if session == "" || rule == "" {
		return false
	}
	var exp sql.NullInt64
	err := s.db.QueryRow(`SELECT expires_at FROM allow_list WHERE session=? AND rule=?`, session, rule).Scan(&exp)
	if err != nil {
		return false
	}
	return !exp.Valid || exp.Int64 > event.Now()
}

// Stats is a small dashboard summary.
type Stats struct {
	Events    int64            `json:"events"`
	ByRisk    map[string]int64 `json:"by_risk"`
	ByDecison map[string]int64 `json:"by_decision"`
	Pending   int64            `json:"pending_approvals"`
	Sessions  int64            `json:"sessions"`
}

// Stats returns counts since sinceMS.
func (s *Store) Stats(sinceMS int64) (Stats, error) {
	st := Stats{ByRisk: map[string]int64{}, ByDecison: map[string]int64{}}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE ts>=?`, sinceMS).Scan(&st.Events)
	for _, q := range []struct {
		col string
		m   map[string]int64
	}{{"risk", st.ByRisk}, {"decision", st.ByDecison}} {
		rows, err := s.db.Query(`SELECT `+q.col+`, COUNT(*) FROM events WHERE ts>=? AND kind='intent' GROUP BY `+q.col, sinceMS)
		if err != nil {
			return st, err
		}
		for rows.Next() {
			var k sql.NullString
			var n int64
			if rows.Scan(&k, &n) == nil {
				q.m[k.String] = n
			}
		}
		rows.Close()
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&st.Pending)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE started_at>=?`, sinceMS).Scan(&st.Sessions)
	return st, nil
}

// Prune deletes events older than the retention window. The chain head is
// anchored in meta before deletion so verification can resume from it.
func (s *Store) Prune(retention time.Duration, maxEvents int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-retention).UnixMilli()
	var cutSeq int64
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM events WHERE ts < ?`, cut).Scan(&cutSeq)
	var total, maxSeq int64
	_ = s.db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(seq),0) FROM events`).Scan(&total, &maxSeq)
	if maxEvents > 0 && total > maxEvents {
		if c := maxSeq - maxEvents; c > cutSeq {
			cutSeq = c
		}
	}
	if cutSeq == 0 {
		return 0, nil
	}
	var anchor string
	if err := s.db.QueryRow(`SELECT hash FROM events WHERE seq=?`, cutSeq).Scan(&anchor); err != nil {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`DELETE FROM events WHERE seq <= ?`, cutSeq)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta(key,value) VALUES('chain_anchor',?)`, anchor); err != nil {
		tx.Rollback()
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

// Meta reads a value from the key/value table ("" if absent).
func (s *Store) Meta(key string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v); err != nil {
		return ""
	}
	return v
}

// SetMeta writes a value to the key/value table.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)`, key, value)
	return err
}

// ChainAnchor is the hash of the last pruned event (Genesis if none).
func (s *Store) ChainAnchor() string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key='chain_anchor'`).Scan(&v); err != nil {
		return Genesis
	}
	return v
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", n), ",")
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// HookSeen reports whether a native hook has ever reported a call for the agent:
// the evidence that an installed hook is actually loaded by the running agent.
func (s *Store) HookSeen(agent string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE agent=? AND layer='hook' LIMIT 1)`, agent).Scan(&n)
	return n > 0
}

// AgentEventCount counts the events attributed to an agent.
func (s *Store) AgentEventCount(agent string) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE agent=?`, agent).Scan(&n)
	return n
}

// ActivityStat summarises the events of one session (or, for ActivityByAgent,
// of one agent's session-less events).
type ActivityStat struct {
	Agent   string
	Events  int
	Blocked int
	FirstTS int64
	LastTS  int64
	CWD     string
	// Imported: the events came from another tool's database (CC-Monitor), not from a live hook.
	Imported bool
}

// ActivityBySession returns per-session event counts and first/last timestamps.
// Events imported from CC-Monitor carry their session in the body
// (agent_session) and are keyed "ext:<id>", like the timeline lanes.
func (s *Store) ActivityBySession() (map[string]ActivityStat, error) {
	return s.activity(`SELECT k, COALESCE(MAX(agent),''), COUNT(*), COALESCE(SUM(decision='block'),0), MIN(ts), MAX(ts), COALESCE(MAX(cwd),''), MAX(imp) FROM (
		SELECT ts, agent, decision,
		  CASE WHEN session IS NOT NULL AND session<>'' THEN session
		       ELSE 'ext:'||json_extract(body,'$.agent_session') END AS k,
		  COALESCE(json_extract(body,'$.cwd'),'') AS cwd,
		  CASE WHEN json_extract(body,'$.fields.imported_from') IS NOT NULL THEN 1 ELSE 0 END AS imp
		FROM events) WHERE k IS NOT NULL GROUP BY k`)
}

// ActivityByAgent covers events that carry an agent but no session at all:
// processes X-Monitor merely observed (L1-L3) and agents it did not start.
func (s *Store) ActivityByAgent() (map[string]ActivityStat, error) {
	return s.activity(`SELECT agent, agent, COUNT(*), COALESCE(SUM(decision='block'),0), MIN(ts), MAX(ts), '', 0 FROM events
		WHERE (session IS NULL OR session='') AND json_extract(body,'$.agent_session') IS NULL
		  AND agent IS NOT NULL AND agent<>'' GROUP BY agent`)
}

func (s *Store) activity(q string) (map[string]ActivityStat, error) {
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ActivityStat{}
	for rows.Next() {
		var k string
		var a ActivityStat
		var imp int
		if err := rows.Scan(&k, &a.Agent, &a.Events, &a.Blocked, &a.FirstTS, &a.LastTS, &a.CWD, &imp); err != nil {
			return nil, err
		}
		a.Imported = imp == 1
		out[k] = a
	}
	return out, rows.Err()
}

// ModelUse is how many audited tool calls were made on behalf of one model.
type ModelUse struct {
	Model    string `json:"model"`
	Calls    int    `json:"calls"`
	Blocked  int    `json:"blocked"`
	Sessions int    `json:"sessions"`
	Agents   int    `json:"agents"`
	LastTS   int64  `json:"last_ts"`
}

// ModelUsage groups audited tool calls by the model the proxy saw in the
// request. Calls re-audited by a hook (reused_from) are not counted twice.
// Tokens are not recorded: the proxy rewrites tool calls, it does not meter them.
func (s *Store) ModelUsage(since int64) ([]ModelUse, error) {
	rows, err := s.db.Query(`SELECT json_extract(body,'$.fields.model') m, COUNT(*), COALESCE(SUM(decision='block'),0),
		COUNT(DISTINCT CASE WHEN session<>'' THEN session ELSE 'ext:'||COALESCE(json_extract(body,'$.agent_session'),'') END),
		COUNT(DISTINCT agent), MAX(ts)
		FROM events WHERE kind='intent' AND type='tool_use' AND ts>=?
		  AND json_extract(body,'$.fields.model') IS NOT NULL AND json_extract(body,'$.fields.reused_from') IS NULL
		GROUP BY m ORDER BY COUNT(*) DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ModelUse{}
	for rows.Next() {
		var m ModelUse
		if err := rows.Scan(&m.Model, &m.Calls, &m.Blocked, &m.Sessions, &m.Agents, &m.LastTS); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
