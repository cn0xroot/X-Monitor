// Package proxy — the HTTP front end. Agents point *_BASE_URL at
// http://127.0.0.1:7789/p/<provider>/... (DESIGN.md §7.1 mode A). The proxy
// forwards to the upstream, then rewrites the response stream through the
// matching adapter so each tool call is vetted by the gate.
package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"xmonitor/internal/agents"
	"xmonitor/internal/config"
	"xmonitor/internal/decide"
	"xmonitor/internal/dlp"
	"xmonitor/internal/event"
	"xmonitor/internal/gate"
	"xmonitor/internal/toolclass"
)

// Server is the LLM proxy.
type Server struct {
	Gate   *gate.Gate
	Cfg    func() *config.Config
	Client *http.Client
	// Resolve maps a client connection to (agent, session) via PID lookup;
	// returns ok=false when the caller is not a monitored agent.
	Resolve func(remoteAddr string) (agent, session string, ok bool)

	seenMu sync.Mutex
	seen   map[string]bool
}

// New creates a proxy server.
func New(g *gate.Gate, cfg func() *config.Config) *Server {
	return &Server{
		Gate: g, Cfg: cfg,
		Client: &http.Client{Timeout: 10 * time.Minute},
		seen:   map[string]bool{},
	}
}

// noteSeen emits a one-time capability/discovery event the first time an agent
// is observed through the proxy, with its interception-degradation note.
func (s *Server) noteSeen(agent, session string) {
	key := agent + "|" + session
	s.seenMu.Lock()
	if s.seen[key] {
		s.seenMu.Unlock()
		return
	}
	s.seen[key] = true
	s.seenMu.Unlock()

	cap := agents.CapabilityOf(agent)
	risk := event.RiskInfo
	if cap.Intercept == agents.InterceptObserve || cap.Intercept == agents.InterceptProxy {
		risk = event.RiskLow
	}
	s.Gate.Emit(&event.Event{
		Layer: event.LayerProxy, Kind: event.KindSession, Type: "agent_seen",
		Agent: agent, Session: session, Risk: risk,
		Title: "经代理识别到 AI 客户端：" + cap.Display,
		Fields: map[string]any{
			"kind": string(cap.Kind), "intercept": string(cap.Intercept),
			"hooks": cap.Hooks, "note": cap.Note, "managed": session != "",
		},
	})
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	return u.Host
}

// Handler returns the proxy's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/p/", s.handleProxy)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

// providerFormat maps a provider id to its wire format.
func providerFormat(provider, path string) string {
	switch provider {
	case "anthropic", "zai-anthropic":
		return "anthropic"
	case "gemini", "zai-gemini", "google":
		return "gemini"
	default:
		// Gemini's native endpoints are recognizable by path even on other routes.
		if strings.Contains(path, ":generateContent") || strings.Contains(path, ":streamGenerateContent") {
			return "gemini"
		}
		if strings.Contains(path, "/responses") {
			return "openai-responses"
		}
		return "openai-chat"
	}
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// /p/<provider>/<upstream path...>
	rest := strings.TrimPrefix(r.URL.Path, "/p/")
	provider, upstreamPath, _ := strings.Cut(rest, "/")
	cfg := s.Cfg()
	base, ok := cfg.Route(provider)
	if !ok {
		http.Error(w, "unknown provider: "+provider, http.StatusBadGateway)
		return
	}

	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024*1024))
	r.Body.Close()

	agent, session := "", ""
	if s.Resolve != nil {
		if a, ss, ok := s.Resolve(r.RemoteAddr); ok {
			agent, session = a, ss
		}
	}
	// GUI clients not launched via `xmon run` may not be identifiable by PID;
	// fall back to the upstream LLM host (DESIGN.md §9.1 reverse attribution).
	if agent == "" {
		if a := agents.MatchByHost(hostOf(base)); a != nil {
			agent = a.ID
		}
	}
	s.noteSeen(agent, session)

	format := providerFormat(provider, upstreamPath)
	adapter := adapterFor(format)

	// Request-side: user goal + DLP on outbound content (§7.5, §7.6).
	model := s.inspectRequest(adapter, reqBody, agent, session)
	if model == "" { // Gemini puts the model in the path, not the body
		model = modelFromPath(upstreamPath)
	}

	// Build and send the upstream request.
	target := base + "/" + strings.TrimLeft(upstreamPath, "/")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	copyHeaders(upReq.Header, r.Header)
	upReq.Header.Del("Accept-Encoding") // we rewrite the body; keep it uncompressed

	resp, err := s.Client.Do(upReq)
	if err != nil {
		// xmond reachable but upstream failed. fail_open would require the
		// run-wrapper to retry direct; here we surface the error.
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	decideFn := s.makeDecider(r.Context(), adapter.Name(), agent, session, model)

	if isSSE(resp.Header.Get("Content-Type")) {
		body, _ := io.ReadAll(resp.Body)
		fw := &flushWriter{w: w}
		_ = adapter.RewriteStream(body, decideFn, fw)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		if out, err := adapter.RewriteJSON(body, decideFn); err == nil {
			body = out
		}
	}
	w.Write(body)
}

// makeDecider returns a per-response decide function that runs each tool call
// through the gate, expanding composite calls (apply_patch) into sub-calls.
func (s *Server) makeDecider(ctx context.Context, format, agent, session, model string) func(ToolCall) Decision {
	return func(tc ToolCall) Decision {
		calls := tc.ToClass()
		for i := range calls {
			calls[i].Agent, calls[i].Session, calls[i].Model = agent, session, model
			o := s.Gate.Check(ctx, event.LayerProxy, calls[i])
			if !o.Allowed {
				return Decision{Block: true, Message: o.Message}
			}
		}
		return Decision{}
	}
}

func (s *Server) inspectRequest(a Adapter, body []byte, agent, session string) string {
	info := a.ExtractRequest(body)
	if session != "" && info.UserGoal != "" {
		s.Gate.D.Sessions.Get(session).SetGoal(info.UserGoal)
	}
	cfg := s.Cfg()
	// DLP: secrets about to be sent to the model.
	var kinds []string
	for _, chunk := range info.Egress {
		if fs := dlp.Scan(chunk); len(fs) > 0 {
			kinds = append(kinds, dlp.Kinds(fs)...)
		}
	}
	if len(kinds) > 0 {
		s.Gate.Emit(&event.Event{
			Layer: event.LayerProxy, Kind: event.KindAlert, Type: "secret_egress",
			Agent: agent, Session: session, Risk: event.RiskHigh,
			Title:  "凭据可能随请求发往云端模型",
			Fields: map[string]any{"kinds": uniq(kinds), "action": cfg.Proxy.DLPAction},
		})
	}
	// Prompt-injection heuristic on untrusted tool results (§7.6).
	for _, tr := range info.ToolResults {
		if injectionRE.MatchString(tr) && session != "" {
			s.Gate.D.Sessions.Get(session).Taint(decide.TaintInjection)
			s.Gate.Emit(&event.Event{
				Layer: event.LayerProxy, Kind: event.KindAlert, Type: "prompt_injection",
				Agent: agent, Session: session, Risk: event.RiskMedium,
				Title: "工具结果中疑似提示注入",
			})
			break
		}
	}
	_ = toolclass.Other
	return info.Model
}

func isSSE(ct string) bool { return strings.Contains(ct, "text/event-stream") }

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// flushWriter adapts http.ResponseWriter to the Writer interface.
type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(p []byte) (int, error) { return f.w.Write(p) }
func (f *flushWriter) Flush() {
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
}

// modelFromPath extracts the model from a Gemini-style path such as
// "v1beta/models/gemini-2.5-pro:streamGenerateContent".
func modelFromPath(p string) string {
	i := strings.Index(p, "models/")
	if i < 0 {
		return ""
	}
	m := p[i+len("models/"):]
	if j := strings.IndexAny(m, ":/?"); j >= 0 {
		m = m[:j]
	}
	return m
}
