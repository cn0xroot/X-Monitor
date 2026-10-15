// Package ctlproto holds the wire types spoken between the xmon CLI and the
// xmond daemon over the control socket. Both sides marshal and unmarshal the
// same Go types, so a field can't be renamed on one side only.
//
// This exists because it once was: `xmon run` sent {"RootPID": …} while the
// daemon decoded into a struct tagged `root_pid`. encoding/json ignores case
// but not underscores, so the value was silently dropped, no session was ever
// bound to its process tree, and every event ended up unattributed.
package ctlproto

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RegisterSession registers (or updates) a managed session. `xmon run` sends it
// twice: before launch (no RootPID) and again once the child's pid is known.
type RegisterSession struct {
	ID        string   `json:"id"`
	Agent     string   `json:"agent"`
	CWD       string   `json:"cwd"`
	Argv      []string `json:"argv,omitempty"`
	RootPID   int      `json:"root_pid,omitempty"`
	StartedAt int64    `json:"started_at,omitempty"`
}

// Decode parses a control-socket argument strictly: unknown fields are an
// error, never silently ignored.
func Decode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad control request: %w", err)
	}
	return nil
}
