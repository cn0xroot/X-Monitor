// Package hookgw is the L4b native-hook gateway (DESIGN.md §8). xmon-hook sends
// a tool call over the UDS; the gateway reuses any decision the proxy already
// made for the same tool_call_id, otherwise it runs the full gate. The wire
// protocol is newline-delimited JSON so the tiny hook binary needs no deps.
package hookgw

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"time"

	"xmonitor/internal/event"
	"xmonitor/internal/gate"
	"xmonitor/internal/hookproto"
	"xmonitor/internal/toolclass"
)

// Request and Response are the shared wire types (see hookproto).
type (
	Request  = hookproto.Request
	Response = hookproto.Response
)

// Gateway serves hook requests over a UDS.
type Gateway struct {
	Gate *gate.Gate
	ln   net.Listener
}

// Listen binds the UDS at path (removing a stale socket first).
func Listen(path string, g *gate.Gate) (*Gateway, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return &Gateway{Gate: g, ln: ln}, nil
}

// Serve accepts connections until the listener is closed.
func (gw *Gateway) Serve() {
	for {
		conn, err := gw.ln.Accept()
		if err != nil {
			return
		}
		go gw.handle(conn)
	}
}

// Close stops the gateway.
func (gw *Gateway) Close() error { return gw.ln.Close() }

func (gw *Gateway) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	dec := json.NewDecoder(bufio.NewReader(conn))
	var req Request
	if err := dec.Decode(&req); err != nil {
		return
	}
	if req.Phase == "post" {
		// Post-tool is advisory for now; just acknowledge.
		_ = json.NewEncoder(conn).Encode(Response{Allowed: true})
		return
	}
	calls := toolclass.Normalize(req.ToolCallID, req.Tool, req.Args)
	resp := Response{Allowed: true}
	for i := range calls {
		calls[i].Agent, calls[i].Session, calls[i].AgentSession, calls[i].CWD = req.Agent, req.Session, req.AgentSession, req.CWD
		o := gw.Gate.Check(context.Background(), event.LayerHook, calls[i])
		resp.Reused = resp.Reused || o.Reused
		if !o.Allowed {
			resp.Allowed = false
			resp.Message = o.Message
			resp.Rule = o.Verdict.RuleID
			resp.Reason = o.Verdict.Reason
			break
		}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}
