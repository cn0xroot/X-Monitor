// Package rules is the deterministic rule engine (DESIGN.md §12.1). The rule
// format is a superset of cc-monitor's default_rules.json, so its 86 rules
// load unchanged; tool names are mapped to canonical classes at load time.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"

	"xmonitor/internal/event"
	"xmonitor/internal/shellparse"
	"xmonitor/internal/toolclass"
	"xmonitor/internal/workdir"
	defaults "xmonitor/rules"
)

// Rule is one rule. Unknown JSON keys are preserved on round-trip by the
// sync logic, which works on raw maps.
type Rule struct {
	ID          string       `json:"id"`
	Risk        event.Risk   `json:"risk"`
	Action      event.Action `json:"action"`
	Title       string       `json:"title"`
	Desc        string       `json:"desc"`
	TitleEn     string       `json:"title_en"`
	DescEn      string       `json:"desc_en"`
	Tools       []string     `json:"tools,omitempty"`   // legacy cc-monitor tool names
	Classes     []string     `json:"classes,omitempty"` // canonical classes
	Field       string       `json:"field,omitempty"`
	Pattern     string       `json:"pattern,omitempty"`
	Match       string       `json:"match,omitempty"` // search | segment | workdir
	Access      string       `json:"access,omitempty"`
	Scopes      []string     `json:"scopes,omitempty"`
	IgnorePaths []string     `json:"ignore_paths,omitempty"`
	Confidence  *float64     `json:"confidence,omitempty"`
	Downgrade   *bool        `json:"downgradable,omitempty"`
	Tags        []string     `json:"tags,omitempty"`

	classSet map[string]bool
	rawSet   map[string]bool
	re       matcher
}

// Conf returns the rule's confidence (defaults: block 0.98, others 0.9).
func (r *Rule) Conf() float64 {
	if r.Confidence != nil {
		return *r.Confidence
	}
	if r.Action == event.ActionBlock {
		return 0.98
	}
	return 0.9
}

// Downgradable reports whether the semantic engine may relax this rule's
// verdict. High/critical rules are not downgradable unless stated otherwise.
func (r *Rule) Downgradable() bool {
	if r.Downgrade != nil {
		return *r.Downgrade
	}
	return r.Action != event.ActionBlock && r.Risk.Rank() < event.RiskHigh.Rank()
}

// Match is a rule hit.
type Match struct {
	Rule  *Rule
	Value string // the matched field value / segment / out-of-workspace paths
}

type matcher interface {
	search(s string) bool
	prefix(s string) bool
}

type reStd struct{ any, anchored *regexp.Regexp }

func (m reStd) search(s string) bool { return m.any.MatchString(s) }
func (m reStd) prefix(s string) bool { return m.anchored.MatchString(s) }

type reBT struct{ any, anchored *regexp2.Regexp }

func (m reBT) search(s string) bool { ok, _ := m.any.MatchString(s); return ok }
func (m reBT) prefix(s string) bool { ok, _ := m.anchored.MatchString(s); return ok }

// compile uses RE2 when possible and falls back to a backtracking engine for
// Python-only syntax (lookaround). The fallback has a match timeout so a
// hostile command can't trigger catastrophic backtracking.
func compile(p string) (matcher, error) {
	if a, err := regexp.Compile("(?i)" + p); err == nil {
		b := regexp.MustCompile("(?i)^(?:" + p + ")")
		return reStd{a, b}, nil
	}
	a, err := regexp2.Compile(p, regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}
	b, err := regexp2.Compile(`\A(?:`+p+`)`, regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}
	a.MatchTimeout = 50 * time.Millisecond
	b.MatchTimeout = 50 * time.Millisecond
	return reBT{a, b}, nil
}

func (r *Rule) prepare() error {
	r.classSet = map[string]bool{}
	r.rawSet = map[string]bool{}
	for _, c := range r.Classes {
		r.classSet[c] = true
	}
	for _, c := range toolclass.LegacyToolClasses(r.Tools) {
		r.classSet[c] = true
	}
	for _, t := range r.Tools {
		r.rawSet[strings.ToLower(t)] = true
	}
	if len(r.Tools) == 0 && len(r.Classes) == 0 {
		r.classSet["*"] = true
	}
	if r.Match != "workdir" && r.Pattern != "" {
		m, err := compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		r.re = m
	}
	return nil
}

func (r *Rule) appliesTo(c toolclass.Call) bool {
	return r.classSet["*"] || r.classSet[c.Class] || r.rawSet[strings.ToLower(c.Raw)]
}

var fieldCandidates = map[string][]string{
	"command":   {"command"},
	"file_path": {"file_path", "path", "notebook_path"},
	"url":       {"url"},
	"content":   {"content", "new_string", "new_source"},
}

func extract(args map[string]any, field string) (string, bool) {
	keys, ok := fieldCandidates[field]
	if !ok {
		keys = []string{field}
	}
	for _, k := range keys {
		v, ok := args[k]
		if !ok || v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			return s, true
		}
		b, _ := json.Marshal(v)
		return string(b), true
	}
	return "", false
}

// Engine evaluates calls against an ordered rule list (first match wins).
type Engine struct {
	mu          sync.RWMutex
	rules       []*Rule
	fingerprint string
	userPath    string
	snapPath    string
	lastCheck   time.Time
	lastMod     time.Time
	loadErr     error
}

// New loads the built-in defaults merged into the user's rules file under dir
// (dir=="" means built-in defaults only).
func New(dir string) (*Engine, error) {
	e := &Engine{}
	if dir != "" {
		e.userPath = filepath.Join(dir, "rules.json")
		e.snapPath = filepath.Join(dir, "rules.defaults_snapshot.json")
	}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) load() error {
	raw, err := loadMerged(e.userPath, e.snapPath)
	if err != nil {
		return err
	}
	rs, fp, err := build(raw)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.rules, e.fingerprint = rs, fp
	if e.userPath != "" {
		if st, err := os.Stat(e.userPath); err == nil {
			e.lastMod = st.ModTime()
		}
	}
	e.mu.Unlock()
	return nil
}

func build(raw []byte) ([]*Rule, string, error) {
	var rs []*Rule
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, "", fmt.Errorf("parse rules: %w", err)
	}
	var out []*Rule
	for _, r := range rs {
		if r == nil || r.ID == "" {
			continue
		}
		if err := r.prepare(); err != nil {
			// A broken user rule must not disable every other rule.
			fmt.Fprintln(os.Stderr, "zai-monitor: skipping", err)
			continue
		}
		out = append(out, r)
	}
	sum := sha256.Sum256(raw)
	return out, hex.EncodeToString(sum[:8]), nil
}

// maybeReload hot-reloads the user rules file when its mtime changes
// (checked at most once per second).
func (e *Engine) maybeReload() {
	if e.userPath == "" {
		return
	}
	e.mu.RLock()
	due := time.Since(e.lastCheck) > time.Second
	e.mu.RUnlock()
	if !due {
		return
	}
	e.mu.Lock()
	e.lastCheck = time.Now()
	last := e.lastMod
	e.mu.Unlock()
	st, err := os.Stat(e.userPath)
	if err != nil || st.ModTime().Equal(last) {
		return
	}
	if err := e.load(); err != nil {
		e.mu.Lock()
		e.loadErr = err
		e.lastMod = st.ModTime()
		e.mu.Unlock()
	}
}

// Rules returns a snapshot of the current rules.
func (e *Engine) Rules() []*Rule {
	e.maybeReload()
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

// Fingerprint identifies the currently loaded rule set.
func (e *Engine) Fingerprint() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.fingerprint
}

// ByID looks up a rule.
func (e *Engine) ByID(id string) *Rule {
	for _, r := range e.Rules() {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// Evaluate returns the first matching rule, or nil.
func (e *Engine) Evaluate(c toolclass.Call) *Match {
	var hits []workdir.Hit
	scanned := false
	for _, r := range e.Rules() {
		if !r.appliesTo(c) {
			continue
		}
		if r.Match == "workdir" {
			if c.CWD == "" {
				continue
			}
			if !scanned {
				hits, scanned = workdir.Scan(c), true
			}
			if sel := workdir.Select(hits, r.Scopes, r.Access, r.IgnorePaths); len(sel) > 0 {
				return &Match{Rule: r, Value: workdir.Describe(sel, 5)}
			}
			continue
		}
		if r.re == nil {
			continue
		}
		var value string
		if r.Field == "tool_name" {
			value = c.Raw
		} else {
			v, ok := extract(c.Args, r.Field)
			if !ok {
				continue
			}
			value = v
		}
		if r.Match == "segment" {
			for _, h := range shellparse.SegmentHeads(value) {
				if r.re.prefix(h) {
					return &Match{Rule: r, Value: h}
				}
			}
		} else if r.re.search(value) {
			return &Match{Rule: r, Value: value}
		}
	}
	return nil
}

// ---- default/user rule merge (port of cc-monitor _sync_new_default_rules) ----

func readJSONList(p string) ([]map[string]any, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var l []map[string]any
	if json.Unmarshal(b, &l) != nil {
		return nil, false
	}
	return l, true
}

func atomicWrite(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	_ = os.Chmod(f.Name(), 0o600)
	return os.Rename(f.Name(), p)
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// loadMerged returns the effective rule JSON. On first run the defaults are
// copied to the user file; afterwards new default rules are merged in (and
// unmodified ones updated) while user edits and deletions are preserved.
func loadMerged(userPath, snapPath string) ([]byte, error) {
	def := defaults.JSON
	if userPath == "" {
		return def, nil
	}
	var defList []map[string]any
	if err := json.Unmarshal(def, &defList); err != nil {
		return nil, err
	}
	pretty := func(v any) []byte {
		b, _ := json.MarshalIndent(v, "", "  ")
		return append(b, '\n')
	}
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		_ = atomicWrite(userPath, pretty(defList))
		_ = atomicWrite(snapPath, pretty(defList))
		return def, nil
	}
	local, ok := readJSONList(userPath)
	if !ok {
		// Corrupt user file: fall back to defaults rather than running unprotected.
		return def, nil
	}
	snapList, _ := readJSONList(snapPath)
	snap := map[string]map[string]any{}
	for _, r := range snapList {
		if id, _ := r["id"].(string); id != "" {
			snap[id] = r
		}
	}
	idx := func(id string) int {
		for i, r := range local {
			if r["id"] == id {
				return i
			}
		}
		return -1
	}
	changed := false
	insertAt := 0
	for _, d := range defList {
		id, _ := d["id"].(string)
		if i := idx(id); i >= 0 {
			insertAt = i + 1
			if s, ok := snap[id]; ok && jsonEq(local[i], s) && !jsonEq(d, s) {
				local[i] = d
				changed = true
			}
			continue
		}
		if _, ok := snap[id]; ok {
			continue // the user deleted it
		}
		local = append(local[:insertAt], append([]map[string]any{d}, local[insertAt:]...)...)
		insertAt++
		changed = true
	}
	out := pretty(local)
	if changed {
		_ = atomicWrite(userPath, out)
	}
	if !jsonEq(snapList, defList) {
		_ = atomicWrite(snapPath, pretty(defList))
	}
	return out, nil
}
