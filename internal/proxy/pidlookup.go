package proxy

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// LookupPID returns the PID that owns the local TCP connection whose remote end
// is remoteAddr (the proxy's client). It uses lsof, which is available on both
// Linux and macOS without privileges for the current user's own sockets.
// Returns 0 when it can't be determined.
func LookupPID(remoteAddr string) int {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0
	}
	_ = host
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	// The client's source port is the remote port from the proxy's view; lsof
	// can find the process whose TCP socket uses that local port.
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:ESTABLISHED", "-Fpn").Output()
	if err != nil {
		return 0
	}
	// -F output: lines starting with 'p' (pid) then 'n' (name addr:port).
	var curPID int
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			curPID, _ = strconv.Atoi(line[1:])
		case 'n':
			// e.g. 127.0.0.1:54321->127.0.0.1:7789 ; the local side is the client.
			if strings.Contains(line, ":"+portStr+"->") {
				return curPID
			}
		}
	}
	return 0
}
