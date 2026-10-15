package server

import (
	"net/http"
	"strconv"
	"time"

	"xmonitor/internal/enforce"
	"xmonitor/internal/flow"
	"xmonitor/internal/rules"
	"xmonitor/internal/store"
)

// CatStat is one threat-category card on the overview.
type CatStat struct {
	Key     string `json:"key"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Confirm int64  `json:"confirm"`
}

// bypassTypes are the alert types that suggest the monitor was evaded.
var bypassTypes = []string{"hook_bypass", "blocked_but_executed", "silent_sensitive_write"}

// OverviewResponse is the payload behind the dashboard's home page.
type OverviewResponse struct {
	*store.Overview
	Mode       string    `json:"mode"`
	GLM        string    `json:"glm"`
	Blocked    int64     `json:"blocked"`
	Confirmed  int64     `json:"confirmed"`
	Bypass     int64     `json:"bypass"`
	Categories []CatStat `json:"categories"`
	Sandbox    struct {
		Tier      string `json:"tier"`
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
	} `json:"sandbox"`
	KillAfterExec bool `json:"kill_after_exec"`
}

// rangeMinutes parses ?range= (1h|6h|24h|7d) or ?range_minutes=, default 24h,
// capped at 7 days.
func rangeMinutes(r *http.Request) int {
	q := r.URL.Query()
	m := 1440
	switch q.Get("range") {
	case "1h":
		m = 60
	case "6h":
		m = 360
	case "24h":
		m = 1440
	case "7d":
		m = 7 * 1440
	default:
		if v, err := strconv.Atoi(q.Get("range_minutes")); err == nil && v > 0 {
			m = v
		}
	}
	if m > 7*1440 {
		m = 7 * 1440
	}
	return m
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UnixMilli()
	since := now - int64(rangeMinutes(r))*60*1000
	o, err := s.Store.Overview(since, now, 24)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cfg := s.Cfg()
	resp := OverviewResponse{Overview: o, Mode: string(cfg.Mode), KillAfterExec: cfg.Probe.Enforce}
	resp.GLM = "disabled"
	if s.GLM != nil {
		resp.GLM = s.GLM.Status()
	}
	resp.Blocked, resp.Confirmed = o.ByDecision["block"], o.ByDecision["confirm"]
	for _, t := range bypassTypes {
		resp.Bypass += o.ByAlert[t]
	}
	resp.Sandbox.Tier = enforce.Tier
	resp.Sandbox.Available, resp.Sandbox.Reason = enforce.Available()

	byCat := map[string]*CatStat{}
	for _, c := range rules.Categories {
		byCat[c] = &CatStat{Key: c}
	}
	for _, rs := range o.ByRule {
		if c := byCat[rules.Category(rs.Rule)]; c != nil {
			c.Total += rs.Total
			c.Blocked += rs.Blocked
			c.Confirm += rs.Confirm
		}
	}
	for typ, n := range o.ByAlert {
		if c := byCat[rules.AlertCategory(typ)]; c != nil {
			c.Total += n
		}
	}
	resp.Categories = make([]CatStat, 0, len(rules.Categories))
	for _, c := range rules.Categories {
		resp.Categories = append(resp.Categories, *byCat[c])
	}
	writeJSON(w, resp)
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	lanes, _ := strconv.Atoi(r.URL.Query().Get("lanes"))
	tl, err := s.Store.Timeline(rangeMinutes(r), time.Now().UnixMilli(), lanes)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, tl)
}

func (s *Server) handleSessionFlow(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session_id")
	if id == "" {
		http.Error(w, "session_id required", http.StatusBadRequest)
		return
	}
	evs, truncated, err := s.Store.LaneEvents(id, 3000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	f := flow.Build(evs, truncated)
	f.SessionID = id // the lane key (ext:… / agent:… lanes have no session id of their own)
	if ss, _ := s.Store.GetSession(id); ss != nil {
		if ss.CWD != "" {
			f.CWD = ss.CWD
		}
		if ss.Agent != "" {
			f.Agent = ss.Agent
		}
	}
	writeJSON(w, f)
}
