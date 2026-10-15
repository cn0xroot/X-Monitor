package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"xmonitor/internal/config"
	"xmonitor/internal/store"
)

// writeTrackedRoots publishes the root pids of live managed sessions to
// ~/.xmon/tracked-roots.json. Kernel-level enforcers that see system-wide
// events (the macOS Endpoint Security client) read it to scope their action to
// agent process trees only. Roots whose process has exited are dropped so a
// reused pid can't pull an unrelated process tree into scope.
func writeTrackedRoots(st *store.Store) {
	sessions, err := st.ListSessions(500)
	if err != nil {
		return
	}
	roots := []int{}
	for _, s := range sessions {
		if s.EndedAt == 0 && s.RootPID > 1 && pidAlive(s.RootPID) {
			roots = append(roots, s.RootPID)
		}
	}
	b, _ := json.Marshal(roots)
	file := filepath.Join(config.Home(), "tracked-roots.json")
	tmp := file + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, file)
	}
}
