// Command xmon is the X-Monitor CLI (DESIGN.md §16.3).
package main

import (
	"fmt"
	"os"
)

const usage = `xmon — X-Monitor control

Usage:
  xmon start [--foreground]        start the daemon
  xmon stop                        stop the daemon
  xmon status                      show daemon status
  xmon run [--agent X] [--sandbox] -- <cmd…>   launch an agent under monitoring
                                   (--sandbox: kernel-enforced write/exec limits)
  xmon install [--agent X]         register hooks / print env for an agent
  xmon tail [--risk high] [-f]     stream recent events
  xmon rules test "<command>"      see which rule a command hits
  xmon approve <id> | xmon deny <id>
  xmon pending                     list pending approvals
  xmon mode active|paused|stopped  set intervention level
  xmon verify                      check the audit hash chain
  xmon import [--from <db>] [-f]    import a CC-Monitor events.db (read-only)
  xmon policy init|show|firewall   manage the kernel-enforcement policy
  xmon ui [--open]                 print (and open) the dashboard URL with its access token
  xmon doctor                      check setup (daemon, token, proxy, GLM)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "start":
		err = cmdStart(args)
	case "stop":
		err = cmdStop()
	case "status":
		err = cmdStatus()
	case "run":
		err = cmdRun(args)
	case "install":
		err = cmdInstall(args)
	case "tail":
		err = cmdTail(args)
	case "rules":
		err = cmdRules(args)
	case "approve":
		err = cmdResolve("approve", args)
	case "deny":
		err = cmdResolve("deny", args)
	case "pending":
		err = cmdPending()
	case "mode":
		err = cmdMode(args)
	case "verify":
		err = cmdVerify()
	case "import":
		err = cmdImport(args)
	case "policy":
		err = cmdPolicy(args)
	case "ui":
		err = cmdUI(args)
	case "__sandbox":
		err = cmdSandbox(args)
	case "doctor":
		err = cmdDoctor()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xmon:", err)
		os.Exit(1)
	}
}
