package enforce

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Windows Firewall rule names. Rules sharing a name are removed together.
const (
	fwNameV4 = "XMON-lock-v4"
	fwNameV6 = "XMON-lock-v6"
)

// Everything except 127.0.0.0/8, and all of IPv6 (the proxy is reached via
// 127.0.0.1, so ::1 is not needed). Windows Firewall block rules override allow
// rules, so "block all but loopback" is expressed as "block the complement".
const (
	nonLoopbackV4 = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255"
	allV6         = "::/1,8000::/1"
)

// FirewallCommands renders the netsh commands that lock each program to
// loopback. It is pure so it can be reviewed (and tested) on any OS; nothing is
// changed until RunFirewall is called on Windows with administrator rights.
func FirewallCommands(p *Policy) []string {
	var cmds []string
	for _, prog := range uniqSorted(p.LoopbackOnlyPrograms) {
		q := `"` + strings.ReplaceAll(prog, `"`, ``) + `"`
		cmds = append(cmds,
			fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=out action=block enable=yes profile=any protocol=any program=%s remoteip=%s`, fwNameV4, q, nonLoopbackV4),
			fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=out action=block enable=yes profile=any protocol=any program=%s remoteip=%s`, fwNameV6, q, allV6),
		)
	}
	return cmds
}

// FirewallRemoveCommands renders the commands that delete every rule we added.
func FirewallRemoveCommands() []string {
	return []string{
		fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, fwNameV4),
		fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, fwNameV6),
	}
}

// RunFirewall executes netsh commands. It refuses on non-Windows hosts.
func RunFirewall(cmds []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("firewall enforcement is only available on Windows")
	}
	for _, c := range cmds {
		parts := splitCommand(c)
		if out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", c, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// splitCommand splits on spaces, keeping double-quoted segments together.
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ' ' && !inQ:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}
