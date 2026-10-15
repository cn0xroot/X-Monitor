package store

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"xmonitor/internal/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// An empty collection must serialize as [] — clients iterate it directly, and
// "null" breaks them (it did).
func TestEmptyListsSerializeAsArrays(t *testing.T) {
	s := open(t)
	ev, _ := s.ListEvents(Query{})
	ss, _ := s.ListSessions(10)
	ap, _ := s.ListApprovals("pending", 10)
	for name, v := range map[string]any{"events": ev, "sessions": ss, "approvals": ap} {
		b, _ := json.Marshal(v)
		if string(b) != "[]" {
			t.Errorf("%s: got %s, want []", name, b)
		}
	}
}

func TestHashChainDetectsTamperingAndDeletion(t *testing.T) {
	s := open(t)
	for i := 0; i < 5; i++ {
		if err := s.Append(&event.Event{Layer: "L4", Kind: "intent", Type: "tool_use", Risk: event.RiskLow}); err != nil {
			t.Fatal(err)
		}
	}
	if r, _ := s.VerifyChain(); !r.OK || r.Checked != 5 {
		t.Fatalf("clean chain: %+v", r)
	}
	// Modify a row.
	if _, err := s.db.Exec(`UPDATE events SET body = replace(body, '"L4"', '"L1"') WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.VerifyChain(); r.OK || r.BrokenAt != 3 {
		t.Errorf("modified row must break the chain at seq 3: %+v", r)
	}
}

func TestHashChainDetectsDeletedRow(t *testing.T) {
	s := open(t)
	for i := 0; i < 5; i++ {
		_ = s.Append(&event.Event{Layer: "L4", Kind: "intent", Type: "tool_use"})
	}
	if _, err := s.db.Exec(`DELETE FROM events WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.VerifyChain(); r.OK {
		t.Errorf("a deleted row must be detected: %+v", r)
	}
}
