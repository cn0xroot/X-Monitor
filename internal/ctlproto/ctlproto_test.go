package ctlproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegisterSessionRoundTrip(t *testing.T) {
	in := RegisterSession{ID: "zs_1", Agent: "claude-code", CWD: "/p", Argv: []string{"sh", "-c", "x"}, RootPID: 4242, StartedAt: 123}
	b, _ := json.Marshal(in)
	var out RegisterSession
	if err := Decode(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.RootPID != 4242 || out.ID != "zs_1" || len(out.Argv) != 3 || out.StartedAt != 123 {
		t.Errorf("round trip lost data: %+v", out)
	}
}

// The original bug, pinned: a mis-spelled key must be an error, not a dropped value.
func TestDecodeRejectsUnknownFields(t *testing.T) {
	var out RegisterSession
	err := Decode([]byte(`{"id":"zs_1","RootPID":4242}`), &out)
	if err == nil || !strings.Contains(err.Error(), "RootPID") {
		t.Fatalf("a field the daemon doesn't know must be rejected loudly, got %v", err)
	}
}
