package main

import (
	"encoding/json"
	"errors"
	"net"
	"time"

	"xmonitor/internal/config"
)

// ctl sends one control command to the daemon and decodes the JSON reply.
func ctl(cmd string, args any, out any) error {
	conn, err := net.DialTimeout("unix", config.SocketPath(), 2*time.Second)
	if err != nil {
		return errors.New("daemon not running (start it with `xmon start`)")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	raw, _ := json.Marshal(args)
	req := map[string]any{"cmd": cmd, "args": json.RawMessage(raw)}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	if out == nil {
		out = &map[string]any{}
	}
	return json.NewDecoder(conn).Decode(out)
}

func daemonRunning() bool {
	conn, err := net.DialTimeout("unix", config.SocketPath(), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
