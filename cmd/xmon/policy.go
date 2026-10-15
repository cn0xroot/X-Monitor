package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"xmonitor/internal/config"
	"xmonitor/internal/enforce"
	"xmonitor/internal/workdir"
)

func loadPolicy() (*enforce.Policy, error) {
	home, _ := os.UserHomeDir()
	return enforce.Load(enforce.Path(config.Home()), home)
}

// wrapSandbox wraps argv in the platform's kernel sandbox using the user's
// policy and the current directory's project root.
func wrapSandbox(argv []string) ([]string, error) {
	p, err := loadPolicy()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	cwd, _ := os.Getwd()
	return enforce.Wrap(p, workdir.ProjectRoot(cwd), argv)
}

// cmdPolicy manages the enforcement policy.
//
//	xmon policy init [--force]      write the default policy file
//	xmon policy show                print the effective policy and platform support
//	xmon policy firewall [--apply|--remove]   Windows: lock programs to loopback
func cmdPolicy(args []string) error {
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	home, _ := os.UserHomeDir()
	file := enforce.Path(config.Home())
	switch sub {
	case "init":
		force := len(args) > 1 && args[1] == "--force"
		if _, err := os.Stat(file); err == nil && !force {
			return fmt.Errorf("%s already exists (use --force to overwrite)", file)
		}
		if err := config.EnsureHome(); err != nil {
			return err
		}
		if err := enforce.Default(home).Save(file); err != nil {
			return err
		}
		fmt.Println("wrote", file)
		return nil
	case "show":
		p, err := loadPolicy()
		if err != nil {
			return err
		}
		ok, why := enforce.Available()
		fmt.Printf("# policy file: %s\n# sandbox tier: %s", file, enforce.Tier)
		if ok {
			fmt.Println(" (available)")
		} else {
			fmt.Printf(" (UNAVAILABLE: %s)\n", why)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
		return nil
	case "firewall":
		p, err := loadPolicy()
		if err != nil {
			return err
		}
		mode := ""
		if len(args) > 1 {
			mode = args[1]
		}
		var cmds []string
		if mode == "--remove" {
			cmds = enforce.FirewallRemoveCommands()
		} else {
			cmds = enforce.FirewallCommands(p)
		}
		if len(cmds) == 0 {
			fmt.Println("no programs in loopback_only_programs; nothing to do")
			return nil
		}
		if mode == "--apply" || mode == "--remove" {
			if err := enforce.RunFirewall(cmds); err != nil {
				return err
			}
			fmt.Printf("ran %d command(s)\n", len(cmds))
			return nil
		}
		fmt.Println("# Review, then run with --apply (administrator, Windows only):")
		fmt.Println("# " + strings.Repeat("-", 60))
		for _, c := range cmds {
			fmt.Println(c)
		}
		return nil
	default:
		return fmt.Errorf("usage: xmon policy init|show|firewall")
	}
}
