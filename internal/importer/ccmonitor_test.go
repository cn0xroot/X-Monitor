package importer

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"xmonitor/internal/event"
	"xmonitor/internal/toolclass"
)

func makeCCDB(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT,
		source TEXT, tool_name TEXT, cwd TEXT, risk TEXT, matched_rule TEXT, decision TEXT, detail TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	rows := [][]any{
		{"2026-09-11T22:10:00+0800", "s1", "hook_pre", "Bash", "/home/u/p", "high", "dangerous_delete", "blocked", `{"command":"rm -rf /"}`},
		{"2026-09-11T22:11:00+0800", "s1", "hook_pre", "Read", "/home/u/p", "low", "", "allowed", `{"file_path":"a.txt"}`},
		{"2026-09-11T22:12:00+0800", "s1", "os_net", "claude", "/home/u/p", "low", "", "allowed", `{"ip":"1.2.3.4","port":443}`},
	}
	for _, r := range rows {
		_, err := db.Exec(`INSERT INTO events(ts,session_id,source,tool_name,cwd,risk,matched_rule,decision,detail)
			VALUES(?,?,?,?,?,?,?,?,?)`, r...)
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestImportMapping(t *testing.T) {
	src, err := Open(makeCCDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	batch, err := src.Fetch(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 3 {
		t.Fatalf("got %d", len(batch))
	}
	e0 := batch[0].Event
	if e0.Layer != event.LayerHook || e0.Decision != event.ActionBlock || e0.Rule != "dangerous_delete" {
		t.Errorf("row0: %+v", e0)
	}
	if e0.Tool == nil || e0.Tool.Class != toolclass.ExecShell || e0.Agent != "claude-code" {
		t.Errorf("row0 tool: %+v", e0.Tool)
	}
	if e0.Fields["imported_from"] != "cc-monitor" || e0.Fields["cc_id"].(int64) != 1 {
		t.Errorf("row0 fields: %+v", e0.Fields)
	}
	if e0.TS == 0 {
		t.Error("ts not parsed")
	}
	e2 := batch[2].Event
	if e2.Layer != event.LayerL1 || e2.Type != "connect" || e2.Fields["ip"] != "1.2.3.4" {
		t.Errorf("row2: %+v", e2)
	}
	// Incremental: nothing after the last id.
	more, _ := src.Fetch(batch[2].OrigID, 100)
	if len(more) != 0 {
		t.Errorf("expected no new rows, got %d", len(more))
	}
}
