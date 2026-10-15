package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// cmdImport pulls a CC-Monitor events.db into X-Monitor's store (read-only on
// the source). With -f/--follow the daemon keeps importing new rows. Default
// source is ~/.cc-monitor/events.db.
func cmdImport(args []string) error {
	path := ""
	follow := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from":
			if i+1 < len(args) {
				path = args[i+1]
				i++
			}
		case "-f", "--follow":
			follow = true
		}
	}
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".cc-monitor", "events.db")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cc-monitor database not found: %s", path)
	}
	abs, _ := filepath.Abs(path)
	var r struct {
		OK        bool   `json:"ok"`
		Error     string `json:"error"`
		Imported  int    `json:"imported"`
		Following bool   `json:"following"`
	}
	if err := ctl("import", map[string]any{"Path": abs, "Follow": follow}, &r); err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("%s (imported %d before error)", r.Error, r.Imported)
	}
	fmt.Printf("imported %d event(s) from %s\n", r.Imported, abs)
	if r.Following {
		fmt.Println("following: new CC-Monitor events will be imported every 2s while the daemon runs")
	}
	return nil
}
