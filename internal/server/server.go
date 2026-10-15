// Package server is the dashboard HTTP/WS API (DESIGN.md §16.2). It binds
// 127.0.0.1 by default, requires a token, and prints a warning on non-local
// binds. The embedded web UI is served from web/.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xmonitor/internal/agents"
	"xmonitor/internal/approval"
	"xmonitor/internal/config"
	"xmonitor/internal/event"
	"xmonitor/internal/glm"
	"xmonitor/internal/rules"
	"xmonitor/internal/sessionview"
	"xmonitor/internal/store"
	"xmonitor/internal/usage"
)

// Server is the dashboard API.
type Server struct {
	Store   *store.Store
	Rules   *rules.Engine
	Broker  *approval.Broker
	Cfg     func() *config.Config
	SetMode func(config.Mode)
	GLM     interface{ Status() string }
	// Detected lists the AI agents found running on this host (nil = unsupported).
	Detected func() any
	// Live lists the agent process trees currently alive (nil = no process view).
	Live func() []sessionview.Live
	// Anthropic reads the plan quota; nil or disabled in config means the page explains how to enable it.
	Anthropic interface {
		Get(context.Context) usage.Result
	}
	Token   string
	Version string

	hub *hub
}

// New creates a dashboard server.
func New(s *Server) *Server {
	s.hub = newHub()
	go s.watchApprovals()
	return s
}

// Broadcast pushes a live event to connected clients.
func (s *Server) Broadcast(ev *event.Event) { s.hub.broadcast("event", ev) }

func (s *Server) watchApprovals() {
	ch, cancel := s.Broker.Subscribe()
	defer cancel()
	for range ch {
		if list, err := s.Store.ListApprovals("pending", 100); err == nil {
			s.hub.broadcast("approvals", list)
		}
	}
}

// Handler builds the mux. uiFS may be nil (API only).
func (s *Server) Handler(uiFS http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", s.auth(s.handleInfo))
	mux.HandleFunc("/api/events", s.auth(s.handleEvents))
	mux.HandleFunc("/api/stats", s.auth(s.handleStats))
	mux.HandleFunc("/api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("/api/timeline", s.auth(s.handleTimeline))
	mux.HandleFunc("/api/session-flow", s.auth(s.handleSessionFlow))
	mux.HandleFunc("/api/sessions", s.auth(s.handleSessions))
	mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	mux.HandleFunc("/api/capabilities", s.auth(s.handleCapabilities))
	mux.HandleFunc("/api/detected", s.auth(s.handleDetected))
	mux.HandleFunc("/api/usage", s.auth(s.handleUsage))
	mux.HandleFunc("/api/model-usage", s.auth(s.handleModelUsage))
	mux.HandleFunc("/api/approvals", s.auth(s.handleApprovals))
	mux.HandleFunc("/api/approvals/", s.auth(s.handleResolve))
	mux.HandleFunc("/api/mode", s.auth(s.handleMode))
	mux.HandleFunc("/api/verify", s.auth(s.handleVerify))
	mux.HandleFunc("/ws", s.auth(s.handleWS))
	if uiFS != nil {
		mux.Handle("/", uiFS)
	}
	return mux
}

// auth enforces the token on API/WS routes. The token may arrive as an
// X-Token header or ?token= query param (DESIGN.md §16.2).
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" {
			h(w, r)
			return
		}
		tok := r.Header.Get("X-Token")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if subtleEqual(tok, s.Token) {
			h(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()
	host, _ := os.Hostname()
	glmStatus := "disabled"
	if s.GLM != nil {
		glmStatus = s.GLM.Status()
	}
	writeJSON(w, map[string]any{
		"version": s.Version, "host": host, "mode": cfg.Mode,
		"glm": glmStatus, "proxy_addr": cfg.ProxyAddr, "ui_addr": cfg.UIAddr,
		"rules": len(s.Rules.Rules()), "rules_fingerprint": s.Rules.Fingerprint(),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := store.Query{Desc: true}
	if v := r.URL.Query().Get("after"); v != "" {
		q.After, _ = strconv.ParseInt(v, 10, 64)
		q.Desc = false
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		q.Limit, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("risk"); v != "" {
		q.MinRisk = event.Risk(v)
	}
	q.Session = r.URL.Query().Get("session")
	q.Decision = r.URL.Query().Get("decision")
	q.Kind = r.URL.Query().Get("kind")
	if v := r.URL.Query().Get("since_ms"); v != "" {
		q.Since, _ = strconv.ParseInt(v, 10, 64)
	}
	qs := r.URL.Query()
	q.Layers, q.TypeIn = splitCSV(qs.Get("layer")), splitCSV(qs.Get("type"))
	q.Agent, q.ToolClass, q.RiskEq, q.Rule = qs.Get("agent"), qs.Get("tool_class"), qs.Get("risk_eq"), qs.Get("rule")
	q.NoReused = qs.Get("no_reused") == "1" || qs.Get("no_reused") == "true"
	if cat := r.URL.Query().Get("category"); cat != "" {
		q.Rules, q.Types = s.Rules.RulesIn(cat), rules.AlertTypes(cat)
		if len(q.Rules) == 0 && len(q.Types) == 0 {
			writeJSON(w, []any{})
			return
		}
	}
	if lane := qs.Get("lane"); lane != "" { // a timeline lane key: zs_… / ext:… / agent:…
		limit := q.Limit
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		evs, _, err := s.Store.LaneEvents(lane, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 { // newest first, like the other lists
			evs[i], evs[j] = evs[j], evs[i]
		}
		if evs == nil {
			evs = []*event.Event{}
		}
		writeJSON(w, evs)
		return
	}
	evs, err := s.Store.ListEvents(q)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, evs)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	if v := r.URL.Query().Get("since_ms"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	st, err := s.Store.Stats(since)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, st)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if id := r.URL.Query().Get("id"); id != "" {
		ss, err := s.Store.GetSession(id)
		if err != nil || ss == nil {
			http.Error(w, "not found", 404)
			return
		}
		evs, _ := s.Store.ListEvents(store.Query{Session: id, Limit: 2000})
		writeJSON(w, map[string]any{"session": ss, "events": evs})
		return
	}
	list, err := s.Store.ListSessions(200)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	in := sessionview.Input{Sessions: list, Pending: map[string]int{}, Now: time.Now()}
	in.Stats, _ = s.Store.ActivityBySession()
	in.Agents, _ = s.Store.ActivityByAgent()
	if pend, err := s.Store.ListApprovals("pending", 500); err == nil {
		for _, a := range pend {
			in.Pending[a.Session]++
		}
	}
	if s.Live != nil {
		in.Live = s.Live()
	}
	rows := sessionview.Build(in)
	for i := range rows {
		rows[i].Branch = gitBranch(rows[i].CWD)
	}
	writeJSON(w, rows)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	type ruleView struct {
		ID, Risk, Action, Title, Desc string
		Downgradable                  bool
		TitleEn, DescEn               string
	}
	var out []ruleView
	for _, rr := range s.Rules.Rules() {
		out = append(out, ruleView{rr.ID, string(rr.Risk), string(rr.Action), rr.Title, rr.Desc, rr.Downgradable(), rr.TitleEn, rr.DescEn})
	}
	writeJSON(w, out)
}

// handleUsage returns the plan quota, or {enabled:false} when the user has not opted in.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if s.Anthropic == nil || !s.Cfg().Usage.AnthropicEnabled {
		writeJSON(w, usage.Result{Enabled: false})
		return
	}
	writeJSON(w, s.Anthropic.Get(r.Context()))
}

// handleModelUsage counts audited tool calls per model over a range.
func (s *Server) handleModelUsage(w http.ResponseWriter, r *http.Request) {
	ms := map[string]int64{"1h": 3600e3, "6h": 6 * 3600e3, "24h": 86400e3, "7d": 7 * 86400e3}
	d, ok := ms[r.URL.Query().Get("range")]
	if !ok {
		d = ms["24h"]
	}
	list, err := s.Store.ModelUsage(time.Now().UnixMilli() - d)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, list)
}

// handleDetected lists the agents currently running on the host.
func (s *Server) handleDetected(w http.ResponseWriter, r *http.Request) {
	if s.Detected == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, s.Detected())
}

// handleCapabilities lists per-agent interception capability and degradation
// notes (DESIGN.md §16: honest labeling of what can and cannot be enforced).
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, agents.AllCapabilities())
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	list, err := s.Store.ListApprovals(status, 200)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	var body struct{ Decision string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.Broker.Resolve(id, body.Decision, "web"); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"mode": s.Cfg().Mode})
		return
	}
	var body struct{ Mode string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "bad body", 400)
		return
	}
	m := config.Mode(body.Mode)
	if m != config.ModeActive && m != config.ModePaused && m != config.ModeStopped {
		http.Error(w, "mode must be active|paused|stopped", 400)
		return
	}
	if s.SetMode != nil {
		s.SetMode(m)
	}
	writeJSON(w, map[string]any{"mode": m})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	res, err := s.Store.VerifyChain()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, res)
}

// Listen binds and serves; it logs a warning for non-local binds and enforces
// that a non-local bind must have a token (DESIGN.md §16.2).
func Listen(addr string, h http.Handler, hasToken bool) (net.Listener, error) {
	host, _, _ := net.SplitHostPort(addr)
	if !isLoopback(host) {
		fmt.Fprintf(os.Stderr, "zai-monitor: WARNING binding %s exposes the dashboard beyond this machine.\n", addr)
		if !hasToken {
			return nil, fmt.Errorf("refusing to bind %s without a token; set a token or bind 127.0.0.1", addr)
		}
	}
	return net.Listen("tcp", addr)
}

func isLoopback(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var _ = glm.ErrUnavailable
var _ sync.Mutex

// splitCSV splits a comma-separated query value, dropping empty parts.
func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// gitBranch reads the checked-out branch of the repository containing dir
// (empty if it is not in a git work tree). It only reads .git/HEAD.
func gitBranch(dir string) string {
	for i := 0; dir != "" && dir != "/" && i < 12; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD")); err == nil {
			ref := strings.TrimSpace(string(b))
			if strings.HasPrefix(ref, "ref: refs/heads/") {
				return strings.TrimPrefix(ref, "ref: refs/heads/")
			}
			if len(ref) >= 7 {
				return ref[:7] + " (detached)"
			}
			return ""
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return ""
}
