// Package fswatch is the L2 cross-platform file monitor (DESIGN.md §10). It
// watches active project roots and a sensitive-path list. FS events carry no
// PID, so attribution is temporal: a change is linked to an intent/exec in a
// short window, else flagged attribution="none" and only alerted for sensitive
// paths. Audit records metadata only (path, size) — never file contents.
package fswatch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"xmonitor/internal/event"
)

// SensitiveSuffixes and names flagged regardless of workspace (requirements §6.3).
var sensitiveFragments = []string{
	"/.ssh/", "/.aws/", "/.gcp/", "/.azure/", "/.kube/", "/.config/gh/",
	"/.env", "credentials.json", "service-account.json",
	"/.npmrc", "/.pypirc", "/.netrc", "id_rsa", "id_ed25519",
	// agent + monitor self-config (DESIGN.md §17)
	"/.claude/", "/.codex/", "/.cursor/", "/.gemini/", "/.codegeex/", "/.zai/", "/.xmon/",
}

// Intent is a recent tool call used for temporal attribution.
type Intent struct {
	When    time.Time
	Session string
	Agent   string
	Summary string
}

// Watcher is the L2 monitor.
type Watcher struct {
	w      *fsnotify.Watcher
	emit   func(*event.Event)
	window time.Duration

	mu       sync.Mutex
	recent   []Intent
	ignore   []string
	skipDirs map[string]bool

	// Feedback-loop protection. The daemon audits into files that live under a
	// watched directory (~/.xmon); without these guards every audit write
	// produces an event that is itself audited, forever.
	selfDir  string
	expected map[string]time.Time // path -> until: changes the daemon itself is about to cause
	now      func() time.Time
	lastSeen map[string]time.Time // path|op -> last emitted
	winStart time.Time
	winCount int
	dropped  int
	lastWarn time.Time
}

const (
	debounce      = 500 * time.Millisecond
	rateWindow    = 10 * time.Second
	rateMax       = 100 // events per window before the limiter kicks in
	stormAlertGap = time.Minute
)

// New creates a watcher. emit receives file events; window is the attribution
// window (default 3s).
func New(emit func(*event.Event), window time.Duration) (*Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if window <= 0 {
		window = 3 * time.Second
	}
	return &Watcher{
		w: w, emit: emit, window: window,
		now: time.Now, lastSeen: map[string]time.Time{}, expected: map[string]time.Time{},
		skipDirs: map[string]bool{"node_modules": true, ".git": true, "dist": true, "build": true, "target": true, "vendor": true},
	}, nil
}

// NoteIntent records a tool call for temporal attribution of later FS events.
func (w *Watcher) NoteIntent(in Intent) {
	w.mu.Lock()
	w.recent = append(w.recent, in)
	cut := time.Now().Add(-w.window)
	i := 0
	for i < len(w.recent) && w.recent[i].When.Before(cut) {
		i++
	}
	w.recent = w.recent[i:]
	w.mu.Unlock()
}

// WatchProject adds a project root (recursively, skipping heavy dirs).
func (w *Watcher) WatchProject(root string) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if w.skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			_ = w.w.Add(p)
		}
		return nil
	})
}

// WatchSensitive adds the sensitive-path parent dirs under home.
func (w *Watcher) WatchSensitive(home string) {
	for _, d := range []string{".ssh", ".aws", ".config", ".claude", ".codex", ".cursor", ".gemini", ".xmon"} {
		p := filepath.Join(home, d)
		if _, err := os.Stat(p); err == nil {
			_ = w.w.Add(p)
		}
	}
	_ = w.w.Add(home)
}

func isSensitive(path string) bool {
	p := filepath.ToSlash(path)
	for _, frag := range sensitiveFragments {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

// Start processes events until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) {
	defer w.w.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.w.Events:
			if !ok {
				return
			}
			w.handle(ev)
		case <-w.w.Errors:
		}
	}
}

func (w *Watcher) handle(ev fsnotify.Event) {
	// Keep watching newly created directories.
	if ev.Op&fsnotify.Create != 0 {
		if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() && !w.skipDirs[filepath.Base(ev.Name)] {
			_ = w.w.Add(ev.Name)
		}
	}
	if w.isOwnFile(ev.Name) || w.expectedWrite(ev.Name) {
		return
	}
	sensitive := isSensitive(ev.Name)
	in, attr := w.attribute()

	// Only emit for sensitive paths, or for any change we could attribute.
	if !sensitive && attr == "none" {
		return
	}
	risk := event.RiskLow
	typ := opType(ev.Op)
	title := "文件变更"
	if sensitive {
		risk = event.RiskHigh
		title = "敏感文件变更"
	}
	var size int64
	if fi, err := os.Stat(ev.Name); err == nil {
		size = fi.Size()
	}
	e := &event.Event{
		Layer: event.LayerL2, Kind: event.KindIntent, Type: typ,
		Session: in.Session, Agent: in.Agent, Risk: risk, Title: title,
		Fields: map[string]any{"path": ev.Name, "op": ev.Op.String(), "size": size, "attribution": attr},
	}
	if sensitive && attr == "none" {
		// A sensitive change with no matching tool call is a bypass signal.
		e.Risk = event.RiskHigh
		e.Type = "silent_sensitive_write"
		e.Title = "无对应意图的敏感文件变更"
	}
	if !w.admit(ev.Name, e.Type) {
		return
	}
	w.emit(e)
}

// SetSelfDir tells the watcher where the daemon keeps its own data, so files
// the daemon writes continuously are never reported. Other files in that
// directory (rules, config, token, policy) are still reported: an agent
// tampering with them is exactly what L2 should see.
func (w *Watcher) SetSelfDir(dir string) { w.selfDir = filepath.Clean(dir) }

// ownFiles are written by the daemon during normal operation.
var ownFiles = map[string]bool{
	"events.db": true, "events.db-wal": true, "events.db-shm": true, "events.db-journal": true,
	"xmond.pid": true, "xmond.log": true, "tracked-roots.json": true,
}

// ExpectWrite tells the watcher that the daemon itself is about to modify path
// (for example saving config.yaml after a mode change from the dashboard), so the
// change in the next d is not reported as an unattributed tampering. Unlike
// listing the file as "own", this suppresses only that one self-inflicted write:
// an agent editing the same file later is still reported.
func (w *Watcher) ExpectWrite(path string, d time.Duration) {
	w.mu.Lock()
	w.expected[filepath.Clean(path)] = w.now().Add(d)
	w.mu.Unlock()
}

func (w *Watcher) expectedWrite(p string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	until, ok := w.expected[filepath.Clean(p)]
	if !ok {
		return false
	}
	if w.now().After(until) {
		delete(w.expected, filepath.Clean(p))
		return false
	}
	return true
}

func (w *Watcher) isOwnFile(p string) bool {
	if w.selfDir == "" || filepath.Dir(filepath.Clean(p)) != w.selfDir {
		return false
	}
	b := filepath.Base(p)
	return ownFiles[b] || strings.HasSuffix(b, ".sock") || strings.HasSuffix(b, ".tmp")
}

// admit applies per-path debouncing and a global rate limit. When the limit is
// hit, further events are dropped and a single storm alert is emitted per
// minute, so a runaway source can't flood the audit log.
func (w *Watcher) admit(path, typ string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	key := path + "|" + typ
	if t, ok := w.lastSeen[key]; ok && now.Sub(t) < debounce {
		return false
	}
	if len(w.lastSeen) > 4096 {
		w.lastSeen = map[string]time.Time{}
	}
	w.lastSeen[key] = now

	if now.Sub(w.winStart) > rateWindow {
		w.winStart, w.winCount = now, 0
	}
	w.winCount++
	if w.winCount > rateMax {
		w.dropped++
		if now.Sub(w.lastWarn) > stormAlertGap {
			w.lastWarn = now
			n := w.dropped
			w.dropped = 0
			go w.emit(&event.Event{
				Layer: event.LayerL2, Kind: event.KindAlert, Type: "fs_event_storm",
				Risk: event.RiskMedium, Title: "文件事件风暴，已限流",
				Fields: map[string]any{"dropped": n, "limit": rateMax, "window_s": int(rateWindow / time.Second)},
			})
		}
		return false
	}
	return true
}

func (w *Watcher) attribute() (Intent, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cut := time.Now().Add(-w.window)
	for i := len(w.recent) - 1; i >= 0; i-- {
		if w.recent[i].When.After(cut) {
			return w.recent[i], "temporal"
		}
	}
	return Intent{}, "none"
}

func opType(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Remove != 0:
		return "unlink"
	case op&fsnotify.Create != 0:
		return "create"
	case op&fsnotify.Rename != 0:
		return "rename"
	default:
		return "write"
	}
}

// SetEmit sets the event sink.
func (w *Watcher) SetEmit(fn func(*event.Event)) { w.emit = fn }
