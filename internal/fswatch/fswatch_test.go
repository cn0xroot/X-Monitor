package fswatch

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"xmonitor/internal/event"
)

type sink struct {
	mu sync.Mutex
	ev []*event.Event
}

func (s *sink) add(e *event.Event) { s.mu.Lock(); s.ev = append(s.ev, e); s.mu.Unlock() }
func (s *sink) n() int             { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ev) }
func (s *sink) types() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]int{}
	for _, e := range s.ev {
		m[e.Type]++
	}
	return m
}

func newTest(t *testing.T, selfDir string) (*Watcher, *sink) {
	t.Helper()
	s := &sink{}
	w, err := New(s.add, 3*time.Second)
	if err != nil {
		t.Skip("fsnotify unavailable:", err)
	}
	t.Cleanup(func() { w.w.Close() })
	if selfDir != "" {
		w.SetSelfDir(selfDir)
	}
	return w, s
}

func TestOwnFilesAreIgnoredButOtherFilesInDataDirAreNot(t *testing.T) {
	self := filepath.Join(t.TempDir(), ".xmon")
	w, s := newTest(t, self)
	for _, f := range []string{"events.db", "events.db-wal", "events.db-shm", "xmond.pid", "tracked-roots.json", "hook.sock", "rules.json.123.tmp"} {
		w.handle(fsnotify.Event{Name: filepath.Join(self, f), Op: fsnotify.Write})
	}
	if s.n() != 0 {
		t.Fatalf("daemon's own files must not produce events, got %v", s.types())
	}
	// An agent editing the monitor's rules/token/policy is still reported.
	for _, f := range []string{"rules.json", "token", "enforce-policy.json", "config.yaml"} {
		w.handle(fsnotify.Event{Name: filepath.Join(self, f), Op: fsnotify.Write})
	}
	if got := s.types()["silent_sensitive_write"]; got != 4 {
		t.Errorf("tampering with monitor config must still alert, got %v", s.types())
	}
	// A same-named file elsewhere is not "own".
	w.handle(fsnotify.Event{Name: filepath.Join(self, "sub", "events.db"), Op: fsnotify.Write})
	if w.isOwnFile(filepath.Join(self, "sub", "events.db")) {
		t.Error("only files directly in the data dir are own files")
	}
}

func TestDebounceSamePathAndOp(t *testing.T) {
	w, s := newTest(t, "")
	clock := time.Unix(1_000_000, 0)
	w.now = func() time.Time { return clock }
	p := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	for i := 0; i < 5; i++ {
		w.handle(fsnotify.Event{Name: p, Op: fsnotify.Write})
	}
	if s.n() != 1 {
		t.Fatalf("burst on one path must collapse to 1 event, got %d", s.n())
	}
	clock = clock.Add(2 * debounce)
	w.handle(fsnotify.Event{Name: p, Op: fsnotify.Write})
	if s.n() != 2 {
		t.Errorf("a later write must be reported again, got %d", s.n())
	}
}

func TestRateLimitCapsAStormAndAlertsOnce(t *testing.T) {
	w, s := newTest(t, "")
	clock := time.Unix(2_000_000, 0)
	w.now = func() time.Time { return clock }
	dir := filepath.Join(t.TempDir(), ".ssh")
	for i := 0; i < 5000; i++ { // distinct paths defeat the debounce
		w.handle(fsnotify.Event{Name: filepath.Join(dir, "k"+itoa(i)), Op: fsnotify.Write})
	}
	time.Sleep(50 * time.Millisecond) // the storm alert is emitted from a goroutine
	ty := s.types()
	if ty["silent_sensitive_write"] != rateMax {
		t.Errorf("expected exactly %d admitted events, got %d", rateMax, ty["silent_sensitive_write"])
	}
	if ty["fs_event_storm"] != 1 {
		t.Errorf("expected exactly one storm alert, got %d", ty["fs_event_storm"])
	}
	// A new window admits events again.
	clock = clock.Add(rateWindow + time.Second)
	w.handle(fsnotify.Event{Name: filepath.Join(dir, "after"), Op: fsnotify.Write})
	if s.types()["silent_sensitive_write"] != rateMax+1 {
		t.Errorf("limiter must reset after the window, got %v", s.types())
	}
}

// TestNoFeedbackLoop reproduces the incident: the audit sink writes into a
// file under a watched directory. With the guards, one real change yields a
// bounded number of events; without them the count grows without limit.
func TestNoFeedbackLoop(t *testing.T) {
	self := filepath.Join(t.TempDir(), ".xmon")
	if err := os.MkdirAll(self, 0o755); err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	audit := filepath.Join(self, "events.db-wal")
	// Like the real daemon, the audit file already exists when watching starts.
	if err := os.WriteFile(audit, []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := New(func(e *event.Event) {
		count.Add(1)
		f, _ := os.OpenFile(audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if f != nil { // "persist the event" == write under the watched directory
			f.WriteString("audit row\n")
			f.Close()
		}
	}, 3*time.Second)
	if err != nil {
		t.Skip(err)
	}
	w.SetSelfDir(self)
	if err := w.w.Add(self); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() { w.Start(ctxDone(done)) }()
	defer close(done)

	// One genuine tamper event kicks the loop off.
	if err := os.WriteFile(filepath.Join(self, "rules.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	t.Logf("events after 1.5s: %d", count.Load())
	if n := count.Load(); n < 1 || n > 5 {
		t.Fatalf("expected a small bounded number of events (feedback loop?), got %d", n)
	}
	first := count.Load()
	time.Sleep(700 * time.Millisecond)
	if count.Load() != first {
		t.Fatalf("event count still growing after the trigger: %d -> %d", first, count.Load())
	}
}

// The daemon saves config.yaml itself when the mode is changed from the
// dashboard. That one write must not be reported as tampering, but a later write
// by anyone else to the same file must be.
func TestExpectedSelfWriteIsSuppressedOnce(t *testing.T) {
	self := filepath.Join(t.TempDir(), ".xmon")
	w, s := newTest(t, self)
	clock := time.Unix(3_000_000, 0)
	w.now = func() time.Time { return clock }
	cfg := filepath.Join(self, "config.yaml")

	w.ExpectWrite(cfg, time.Second)
	w.handle(fsnotify.Event{Name: cfg, Op: fsnotify.Chmod}) // the CHMOD that macOS reports for a rewrite
	w.handle(fsnotify.Event{Name: cfg, Op: fsnotify.Write})
	if s.n() != 0 {
		t.Fatalf("the daemon's own write must not be reported: %v", s.types())
	}

	clock = clock.Add(2 * time.Second) // the expectation has expired
	w.handle(fsnotify.Event{Name: cfg, Op: fsnotify.Write})
	if s.types()["silent_sensitive_write"] != 1 {
		t.Errorf("a later write to the same file must be reported again: %v", s.types())
	}

	// expecting one path must not hide another
	w.ExpectWrite(cfg, time.Second)
	w.handle(fsnotify.Event{Name: filepath.Join(self, "rules.json"), Op: fsnotify.Write})
	if s.types()["silent_sensitive_write"] != 2 {
		t.Errorf("only the announced path is suppressed: %v", s.types())
	}
}
