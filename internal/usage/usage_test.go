package usage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sample = `{"five_hour":{"utilization":42.5,"resets_at":"2026-10-15T05:00:00Z"},"seven_day":{"utilization":10,"resets_at":"2026-10-20T00:00:00Z"},
"seven_day_opus":null,
"limits":[{"kind":"weekly_scoped","percent":71,"severity":"warning","resets_at":"2026-10-20T00:00:00Z","is_active":true,"scope":{"model":{"display_name":"Fable"}}}],
"spend":{"used":{"amount_minor":1250,"currency":"USD","exponent":2},"percent":12.5,"enabled":true}}`

func client(t *testing.T, srv *httptest.Server, tok *Token) *Anthropic {
	a := NewAnthropic()
	a.Endpoint = srv.URL
	a.Source = func() (*Token, error) { return tok, nil }
	return a
}

func TestFetchParsesQuotaAndSendsTheTokenOnlyAsBearer(t *testing.T) {
	var gotAuth, gotBeta string
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth, gotBeta = r.Header.Get("Authorization"), r.Header.Get("anthropic-beta")
		_, _ = w.Write([]byte(sample))
	}))
	defer srv.Close()
	a := client(t, srv, &Token{Access: "tok-123", Plan: "max", RateTier: "tier_5x"})
	r := a.Get(context.Background())
	if r.Error != "" || r.Quota == nil || !r.Enabled {
		t.Fatalf("%+v", r)
	}
	q := r.Quota
	if gotAuth != "Bearer tok-123" || gotBeta != "oauth-2025-04-20" {
		t.Errorf("headers: %q %q", gotAuth, gotBeta)
	}
	if *q.Session.Utilization != 42.5 || q.Session.ResetsAt == "" || q.WeeklyOpus != nil || q.Plan != "max" {
		t.Errorf("quota: %+v", q)
	}
	if len(q.Limits) != 1 || q.Limits[0].ScopeModel != "Fable" || !q.Limits[0].Active {
		t.Errorf("limits: %+v", q.Limits)
	}
	if q.Spend == nil || *q.Spend.UsedMinor != 1250 || q.Spend.Currency != "USD" {
		t.Errorf("spend: %+v", q.Spend)
	}
	// cached: a second call within the TTL must not hit the endpoint again
	a.Get(context.Background())
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected 1 request, got %d", hits)
	}
	// and the token must never appear in anything we return
	if strings.Contains(strings.ToLower(string(mustJSON(r))), "tok-123") {
		t.Error("token leaked into the result")
	}
}

func TestCacheExpires(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(sample))
	}))
	defer srv.Close()
	a := client(t, srv, &Token{Access: "t"})
	now := time.Unix(1_000_000, 0)
	a.Now = func() time.Time { return now }
	a.Get(context.Background())
	now = now.Add(CacheTTL + time.Second)
	a.Get(context.Background())
	if hits != 2 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestErrorsAreReadableAndNeverContainTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	r := client(t, srv, &Token{Access: "secret-tok"}).Get(context.Background())
	if !strings.Contains(r.Error, "401") || r.Quota != nil {
		t.Errorf("%+v", r)
	}
	srv.Close() // connection refused: the Go error text carries the URL, never the header, but redact anyway
	r = client(t, srv, &Token{Access: "secret-tok"}).Get(context.Background())
	if r.Error == "" || strings.Contains(r.Error, "secret-tok") {
		t.Errorf("%+v", r)
	}
	if got := redact("x secret-tok y secret-tok", "secret-tok"); got != "x *** y ***" {
		t.Errorf("redact: %q", got)
	}
}

func TestExpiredTokenIsNotSent(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	r := client(t, srv, &Token{Access: "t", ExpiresAt: time.Now().Add(-time.Hour).UnixMilli()}).Get(context.Background())
	if hits != 0 || !strings.Contains(r.Error, "expired") {
		t.Fatalf("an expired token must not be sent anywhere: hits=%d %+v", hits, r)
	}
}

func TestMissingCredentialSaysWhereItLooked(t *testing.T) {
	a := NewAnthropic()
	a.Source = func() (*Token, error) { return nil, context.DeadlineExceeded }
	if r := a.Get(context.Background()); r.Error == "" || r.Quota != nil {
		t.Fatalf("%+v", r)
	}
}

func TestTokenParsingAndPick(t *testing.T) {
	tok := parseToken([]byte(`{"claudeAiOauth":{"accessToken":"a","expiresAt":5,"subscriptionType":"pro","rateLimitTier":"t"}}`))
	if tok == nil || tok.Access != "a" || tok.Plan != "pro" {
		t.Fatalf("%+v", tok)
	}
	if parseToken([]byte(`{"claudeAiOauth":{}}`)) != nil || parseToken([]byte(`not json`)) != nil {
		t.Error("bad credentials must parse to nil")
	}
	old, fresh, older := &Token{Access: "old", ExpiresAt: 10}, &Token{Access: "fresh", ExpiresAt: 1000}, &Token{Access: "older", ExpiresAt: 5}
	if pick([]*Token{old, fresh}, 100).Access != "fresh" || pick([]*Token{older, old}, 100).Access != "old" || pick(nil, 1) != nil {
		t.Error("pick: prefer unexpired, else the one that expires last")
	}
}

func TestEndpointIsAFixedConstant(t *testing.T) {
	if NewAnthropic().Endpoint != "https://api.anthropic.com/api/oauth/usage" {
		t.Fatal("the token must only ever go to Anthropic's host")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
