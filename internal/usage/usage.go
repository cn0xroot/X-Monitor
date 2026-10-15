// Package usage reads an AI account's plan quota.
//
// Anthropic is the only provider implemented, and it is opt-in
// (usage.anthropic_enabled in config.yaml; off by default). It does what
// CC-Monitor and ccstatusline do: take the OAuth token Claude Code keeps on this
// machine and ask api.anthropic.com/api/oauth/usage how much of the 5-hour and
// weekly allowance is used. That endpoint is not a documented public API: it is
// the one Claude Code's own /usage calls, found by reverse engineering, so it can
// change or disappear without notice, and using a subscription token from a
// third-party tool may be against the provider's terms. The token is read, held
// in memory for one request, sent only to that host, and never stored or logged.
package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Endpoint is fixed on purpose: it is not configurable, so editing a config
// file can never redirect the token to another host.
const Endpoint = "https://api.anthropic.com/api/oauth/usage"

// CacheTTL keeps the endpoint from being hit on every page refresh.
const CacheTTL = 180 * time.Second

// Bucket is one rolling allowance.
type Bucket struct {
	Utilization *float64 `json:"utilization"` // percent used
	ResetsAt    string   `json:"resets_at,omitempty"`
}

// Limit is one entry of the finer-grained limits list.
type Limit struct {
	Kind       string   `json:"kind"`
	Group      string   `json:"group,omitempty"`
	Percent    *float64 `json:"percent"`
	Severity   string   `json:"severity,omitempty"`
	ResetsAt   string   `json:"resets_at,omitempty"`
	ScopeModel string   `json:"scope_model,omitempty"`
	Active     bool     `json:"active"`
}

// Spend is paid usage beyond the plan.
type Spend struct {
	UsedMinor *int64   `json:"used_minor"`
	Currency  string   `json:"currency,omitempty"`
	Exponent  int      `json:"exponent"`
	Percent   *float64 `json:"percent"`
	Severity  string   `json:"severity,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// Quota is what the endpoint reports.
type Quota struct {
	Session      *Bucket `json:"session"`
	Weekly       *Bucket `json:"weekly"`
	WeeklySonnet *Bucket `json:"weekly_sonnet"`
	WeeklyOpus   *Bucket `json:"weekly_opus"`
	Limits       []Limit `json:"limits"`
	Spend        *Spend  `json:"spend"`
	Plan         string  `json:"plan,omitempty"`      // from the credential, not the endpoint
	RateTier     string  `json:"rate_tier,omitempty"` // likewise
}

// Result is a cached outcome: Quota or a human-readable Error.
type Result struct {
	Enabled   bool   `json:"enabled"`
	Quota     *Quota `json:"quota,omitempty"`
	Error     string `json:"error,omitempty"`
	FetchedAt int64  `json:"fetched_at,omitempty"`
}

// Token is a Claude Code OAuth credential.
type Token struct {
	Access    string
	ExpiresAt int64 // unix ms; 0 = unknown
	Plan      string
	RateTier  string
}

// TokenSource finds the credential. It is a field so tests never touch the
// real keychain or home directory.
type TokenSource func() (*Token, error)

// Anthropic fetches and caches the account quota.
type Anthropic struct {
	Source   TokenSource
	Endpoint string // tests only; production uses the Endpoint constant
	HTTP     *http.Client
	Now      func() time.Time

	mu     sync.Mutex
	cached *Result
	at     time.Time
}

// NewAnthropic returns a client that reads the real local credential.
func NewAnthropic() *Anthropic {
	return &Anthropic{Source: LocalToken, Endpoint: Endpoint, Now: time.Now,
		HTTP: &http.Client{Timeout: 6 * time.Second}}
}

// Get returns the cached result, refreshing it when older than CacheTTL.
func (a *Anthropic) Get(ctx context.Context) Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cached != nil && a.Now().Sub(a.at) < CacheTTL {
		return *a.cached
	}
	r := a.fetch(ctx)
	r.Enabled, r.FetchedAt = true, a.Now().UnixMilli()
	a.cached, a.at = &r, a.Now()
	return r
}

func (a *Anthropic) fetch(ctx context.Context) Result {
	tok, err := a.Source()
	if err != nil {
		return Result{Error: err.Error()}
	}
	if tok.ExpiresAt > 0 && tok.ExpiresAt <= a.Now().UnixMilli() {
		return Result{Error: "the Claude Code login has expired; run any command in Claude Code to refresh it, or /login"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Endpoint, nil)
	if err != nil {
		return Result{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok.Access)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return Result{Error: "quota request failed: " + redact(err.Error(), tok.Access)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{Error: fmt.Sprintf("quota endpoint returned %d", resp.StatusCode)}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	q, err := parseQuota(body)
	if err != nil {
		return Result{Error: err.Error()}
	}
	q.Plan, q.RateTier = tok.Plan, tok.RateTier
	return Result{Quota: q}
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	for i := 0; i+len(secret) <= len(s); i++ {
		if s[i:i+len(secret)] == secret {
			s = s[:i] + "***" + s[i+len(secret):]
		}
	}
	return s
}

type rawBucket struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    string   `json:"resets_at"`
}

func bucket(b *rawBucket) *Bucket {
	if b == nil {
		return nil
	}
	return &Bucket{Utilization: b.Utilization, ResetsAt: b.ResetsAt}
}

func parseQuota(body []byte) (*Quota, error) {
	var raw struct {
		FiveHour    *rawBucket `json:"five_hour"`
		SevenDay    *rawBucket `json:"seven_day"`
		SevenSonnet *rawBucket `json:"seven_day_sonnet"`
		SevenOpus   *rawBucket `json:"seven_day_opus"`
		Limits      []struct {
			Kind     string   `json:"kind"`
			Group    string   `json:"group"`
			Percent  *float64 `json:"percent"`
			Severity string   `json:"severity"`
			ResetsAt string   `json:"resets_at"`
			IsActive bool     `json:"is_active"`
			Scope    struct {
				Model struct {
					DisplayName string `json:"display_name"`
				} `json:"model"`
			} `json:"scope"`
		} `json:"limits"`
		Spend *struct {
			Used struct {
				AmountMinor *int64 `json:"amount_minor"`
				Currency    string `json:"currency"`
				Exponent    *int   `json:"exponent"`
			} `json:"used"`
			Percent  *float64 `json:"percent"`
			Severity string   `json:"severity"`
			Enabled  bool     `json:"enabled"`
		} `json:"spend"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("could not parse the quota response")
	}
	q := &Quota{Session: bucket(raw.FiveHour), Weekly: bucket(raw.SevenDay), WeeklySonnet: bucket(raw.SevenSonnet),
		WeeklyOpus: bucket(raw.SevenOpus), Limits: []Limit{}}
	for _, l := range raw.Limits {
		q.Limits = append(q.Limits, Limit{Kind: l.Kind, Group: l.Group, Percent: l.Percent, Severity: l.Severity,
			ResetsAt: l.ResetsAt, ScopeModel: l.Scope.Model.DisplayName, Active: l.IsActive})
	}
	if s := raw.Spend; s != nil {
		exp := 2
		if s.Used.Exponent != nil {
			exp = *s.Used.Exponent
		}
		q.Spend = &Spend{UsedMinor: s.Used.AmountMinor, Currency: s.Used.Currency, Exponent: exp,
			Percent: s.Percent, Severity: s.Severity, Enabled: s.Enabled}
	}
	return q, nil
}

// ---- reading Claude Code's credential ----

const keychainService = "Claude Code-credentials"

type oauthJSON struct {
	ClaudeAiOauth *struct {
		AccessToken      string `json:"accessToken"`
		ExpiresAt        int64  `json:"expiresAt"`
		SubscriptionType string `json:"subscriptionType"`
		RateLimitTier    string `json:"rateLimitTier"`
	} `json:"claudeAiOauth"`
}

func parseToken(raw []byte) *Token {
	var o oauthJSON
	if json.Unmarshal(raw, &o) != nil || o.ClaudeAiOauth == nil || o.ClaudeAiOauth.AccessToken == "" {
		return nil
	}
	c := o.ClaudeAiOauth
	return &Token{Access: c.AccessToken, ExpiresAt: c.ExpiresAt, Plan: c.SubscriptionType, RateTier: c.RateLimitTier}
}

// pick prefers a credential that has not expired, else the one that expires last.
func pick(cands []*Token, nowMs int64) *Token {
	var best *Token
	for _, t := range cands {
		if t == nil {
			continue
		}
		if t.ExpiresAt == 0 || t.ExpiresAt > nowMs {
			return t
		}
		if best == nil || t.ExpiresAt > best.ExpiresAt {
			best = t
		}
	}
	return best
}

// LocalToken reads ~/.claude/.credentials.json and, on macOS, the keychain
// item Claude Code stores there (the first read may show a system prompt).
func LocalToken() (*Token, error) {
	var cands []*Token
	if home, err := os.UserHomeDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json")); err == nil {
			cands = append(cands, parseToken(b))
		}
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", keychainService, "-w").Output(); err == nil {
			cands = append(cands, parseToken(out))
		}
	}
	if t := pick(cands, time.Now().UnixMilli()); t != nil {
		return t, nil
	}
	return nil, errors.New("no Claude Code login found (~/.claude/.credentials.json" + map[bool]string{true: " or the macOS keychain item \"Claude Code-credentials\"", false: ""}[runtime.GOOS == "darwin"] + ")")
}
