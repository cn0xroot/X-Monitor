// Package notify sends best-effort desktop notifications.
package notify

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Desktop shows a notification; errors are ignored.
func Desktop(title, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	switch runtime.GOOS {
	case "darwin":
		script := "display notification " + q(msg) + " with title " + q(title) + " sound name \"Ping\""
		_ = exec.CommandContext(ctx, "osascript", "-e", script).Run()
	case "linux":
		_ = exec.CommandContext(ctx, "notify-send", "-u", "critical", title, msg).Run()
	case "windows":
		ps := "[reflection.assembly]::loadwithpartialname('System.Windows.Forms')|Out-Null;" +
			"$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;" +
			"$n.ShowBalloonTip(10000," + psq(title) + "," + psq(msg) + ",'Warning');Start-Sleep 5"
		_ = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", ps).Run()
	}
}

// q quotes for AppleScript.
func q(s string) string {
	return "\"" + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + "\""
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
