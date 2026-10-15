package main

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"

	"xmonitor/internal/config"
)

// cmdUI prints the dashboard URL including the access token, which the page
// needs to read the API; `--open` also launches the default browser. The URL is
// what `xmon status` used to print without the token — opening that bare URL
// shows an unauthorized, empty dashboard.
func cmdUI(args []string) error {
	cfg, _ := config.Load()
	tok, err := config.Token()
	if err != nil {
		return err
	}
	u := "http://" + cfg.UIAddr + "/?token=" + url.QueryEscape(tok)
	fmt.Println(u)
	for _, a := range args {
		if a == "--open" || a == "-o" {
			return openBrowser(u)
		}
	}
	return nil
}

func openBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}
