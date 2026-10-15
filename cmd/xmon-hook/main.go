// Command xmon-hook is the native-hook adapter (DESIGN.md §8). An agent invokes
// it per tool call; it reads the hook JSON on stdin, forwards it to xmond's
// hook gateway over a UDS, and translates the verdict back into the agent's
// hook protocol. It is intentionally tiny and dependency-free so it starts in
// well under 10 ms, and it fails safe (deny on connect error for a configured
// strict mode, else allow) when the daemon is unreachable.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"xmonitor/internal/hookproto"
)

func home(getenv func(string) string) string {
	if h := getenv("XMON_HOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".xmon")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr, os.Getenv))
}

// run is main without the process plumbing, so the whole hook path can be tested.
// It returns the process exit code: 0 = allow, 2 = block (reason on stderr).
func run(args []string, stdin io.Reader, stderr io.Writer, getenv func(string) string) int {
	mode, agent := hookproto.ParseArgs(args)
	if agent == "" {
		agent = getenv("XMON_AGENT")
	}
	in, err := readInput(stdin)
	if err != nil {
		return 0 // never break the agent on our own parse error
	}
	req := hookproto.Build(in, agent, mode, getenv("XMON_SESSION"))
	resp, err := call(home(getenv), req)
	if err != nil {
		// Daemon unreachable: fail open unless XMON_STRICT=1.
		if getenv("XMON_STRICT") == "1" && req.Phase == "pre" {
			fmt.Fprintln(stderr, "[X-Monitor] 监控守护进程不可达，严格模式下拒绝本次操作")
			return 2
		}
		return 0
	}
	if req.Phase == "post" || resp.Allowed {
		return 0
	}
	// Block: exit code 2 feeds stderr back to the model. Claude Code reads it
	// directly; the OpenCode plugin turns a 2 into a thrown Error.
	fmt.Fprintln(stderr, resp.Message)
	return 2
}

func readInput(r io.Reader) (hookproto.AgentInput, error) {
	var in hookproto.AgentInput
	dec := json.NewDecoder(bufio.NewReader(r))
	err := dec.Decode(&in)
	return in, err
}

func call(home string, req hookproto.Request) (hookproto.Response, error) {
	conn, err := net.DialTimeout("unix", filepath.Join(home, "hook.sock"), 2*time.Second)
	if err != nil {
		return hookproto.Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return hookproto.Response{}, err
	}
	var resp hookproto.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return hookproto.Response{}, err
	}
	return resp, nil
}
