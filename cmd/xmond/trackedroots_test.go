//go:build !windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"xmonitor/internal/store"
)

func TestTrackedRootsOnlyLiveManagedSessions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XMON_HOME", dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	live := os.Getpid()
	for _, s := range []*store.Session{
		{ID: "live", Agent: "a", StartedAt: 1, RootPID: live},
		{ID: "ended", Agent: "a", StartedAt: 2, RootPID: live + 1, EndedAt: 3},
		{ID: "dead", Agent: "a", StartedAt: 4, RootPID: 4194000}, // no such process
		{ID: "norootpid", Agent: "a", StartedAt: 5},
	} {
		if err := st.PutSession(s); err != nil {
			t.Fatal(err)
		}
	}
	writeTrackedRoots(st)

	b, err := os.ReadFile(filepath.Join(dir, "tracked-roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != live {
		t.Errorf("roots=%v want [%d]", got, live)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "tracked-roots.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("perm=%v want 0600", fi.Mode().Perm())
	}
}
