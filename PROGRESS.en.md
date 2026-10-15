[中文](./PROGRESS.md) | **English**

# X-Monitor Progress

> Version `v0.1.0-dev` · Updated 2026-10-14 · Design: [DESIGN.md](./DESIGN.md) (Chinese) · Usage: [README.en.md](./README.en.md)

This document records **facts only**: what was built, how far it has been verified, and what is missing. Where the design and the implementation differ, this document describes the implementation.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | Implemented and actually run/verified on this machine (macOS) |
| 🟡 | Implemented and compiles, but **never run in the target environment** (missing platform, privilege or entitlement) |
| 🔶 | Partially implemented, with known gaps (see "Known gaps") |
| ⬜ | Not started |

## The two most important caveats

1. **Every protocol adapter was verified only against synthetic SSE samples. None has been run against a real Claude Code / Codex / Gemini CLI, or a real upstream API.** The "upstream" in the end-to-end tests is a fake server I wrote. Real streams may contain event shapes the samples don't cover (thinking blocks, signature deltas, pings, …). The adapters pass unknown events through unchanged, but that has not been confirmed against real streams.
2. **It has only been run on one macOS machine.** The Linux and Windows code has only been cross-compiled and passed through `go vet`; it has not been run on those systems.

## Overview

| Item | Figure |
|---|---|
| Go packages | 28 under `internal/`, 3 binaries (`xmon` / `xmond` / `xmon-hook`) |
| Code size | ~11.8k lines non-test, ~3.5k lines of tests |
| Tests | 116 Go tests + 3747 front-end assertions (`web/timeline_test.js`), all passing (macOS); a real-Chrome driver script clicked 30 drill-down targets with 0 failures (the script lives in /tmp, not in the repo) |
| Default rules | 92 (86 ported from cc-monitor + 6 self-protection rules) |
| Cross-compilation | linux/amd64, linux/arm64, darwin/arm64, windows/amd64 all build |
| Dependencies | Pure Go, no cgo; gorilla/websocket, fsnotify, modernc sqlite, regexp2, yaml.v3 |

Detailed usage: [USAGE.en.md](./USAGE.en.md).

## Roadmap vs. reality (DESIGN.md §21)

| Phase | Planned | Actual status |
|---|---|---|
| P1 MVP | Event model, store, rules, CLI, process tree, L4 proxy, managed launch, hooks, file monitor | ✅ Done (the proxy has a stream-buffering gap, see below) |
| P2 UI + GLM | Web UI, approval console, GLM engine, session correlation, DLP | 🔶 Implemented; GLM tested only against a local fake server; UI driven in a real Chrome |
| P3 Enhancement layer | Linux eBPF, macOS ESF, Windows ETW, cross-verification, MITM | 🔶 See the table below: collection uses subprocess backends, with **no** hand-written eBPF/ESF/ETW kernel collectors; MITM not built |
| P4 Advanced | Session replay, network map, central management, SIEM, GLM reports | ⬜ Not started (the Responses/Gemini adapters were pulled forward) |

## Progress by module

### Decision pipeline

| Module | Status | Notes |
|---|---|---|
| Rule engine (`internal/rules`) | ✅ | RE2 first; Python-only syntax (lookahead) falls back to a backtracking engine with a timeout; user/default rule merge and hot reload. cc-monitor's regression tests were ported |
| Shell parsing / cross-workspace detection | ✅ | Ported from cc-monitor (quote/heredoc aware, strips sudo/env, recurses into `bash -c`). macOS paths adapted |
| Decision engine (`internal/decide`) | ✅ | Rule fast path → session correlation → cache → GLM. Tests prove GLM cannot override a rule's block |
| Session correlation | ✅ | Only two sequence rules so far: "read sensitive data then connect out" (`read_then_egress`) and a prompt-injection taint |
| GLM client (`internal/glm`) | 🟡 | Injection-hardened prompt, schema validation, circuit breaker and redaction implemented, tested against a local fake HTTP server for request shape, redaction, timeout, breaker and rejection of invalid output; **never called against the real Z.ai API** |
| DLP (`internal/dlp`) | ✅ | Detection and redaction of common secret formats |
| Tool normalization (`internal/toolclass`) | ✅ | Tool-name mapping for Claude Code / Codex / Cursor / Gemini; `apply_patch` expanded into per-file calls |

### Interception layers

| Layer | Status | Notes |
|---|---|---|
| L4 proxy: Anthropic Messages | 🔶 | Stream rewriting verified end to end with synthetic samples; **gap: whole-response buffering** (below) |
| L4 proxy: OpenAI Chat (incl. GLM/Zhipu/DeepSeek-compatible) | 🔶 | Same |
| L4 proxy: Gemini `generateContent` (Z.ai CLI) | 🔶 | Same; the Z.ai Gemini endpoint path was inferred from naming conventions and is **unverified** |
| L4 proxy: OpenAI Responses | 🔶 | Non-streaming responses can be rewritten; **streaming is passed through without enforcement** |
| L4b hook (Claude Code) | 🟡 | `xmon-hook` + UDS gateway + de-duplication with the proxy by `tool_call_id` implemented; **not verified against a real Claude Code** (including hook input field names such as `tool_use_id`) |
| L3 process tree | ✅ | `ps` polling + downward mark propagation. Polling misses millisecond-lived processes (stated in the design) |
| L2 file monitor | 🔶 | fsnotify; **gap: only watches the daemon's startup working directory, not each session's project root** |
| Cross-verification (`internal/correlate`) | ✅ logic / 🟡 integration | Bypass-detection logic is tested; integration with a privileged L1 probe is unverified |

### L1 system layer

| Item | Status | Notes |
|---|---|---|
| Linux collection (bpftrace subprocess) | 🟡 | Script and parser written; needs root + bpftrace; **never run on Linux** |
| macOS collection (eslogger exec + nettop network) | 🟡 | Needs root; never run with privilege |
| Windows collection (Sysmon event log) | 🟡 | Needs administrator + Sysmon installed; **never run on Windows** |
| Managed sandbox: macOS `sandbox-exec` | ✅ | Unit test against the real sandbox + end to end (a simulated agent writing credentials, reading the token, deleting the monitor directory and running `nc` was refused by the kernel each time) |
| Managed sandbox: Linux Landlock | 🟡 | Implemented, with a test that runs automatically on Linux; **never run on a Linux host** |
| Kill after exec | ✅ logic / 🟡 integration | Tested against a real process; has a millisecond window; integration with a privileged probe unverified |
| Windows firewall lock (`netsh`) | 🟡 | Command generation tested; **never applied on Windows** |
| macOS ESF AUTH client | 🟡 | Source type-checks, compiles and links; **needs Apple's ES entitlement to run and has never been executed** |
| Linux BPF-LSM | ⬜ | Not built (needs the target kernel's BTF and clang on Linux) |

### Supporting capabilities

| Module | Status | Notes |
|---|---|---|
| Store + hash chain (`internal/store`) | ✅ | SQLite, hash-chain verification, retention pruning |
| Approval console (`internal/approval`) | 🔶 | Channels: web, CLI, desktop notification; **gap: no keep-alive is sent while the proxy waits for an approval** (below) |
| Web UI (`web/`) | ✅ | Single-file dashboard + WebSocket; overview modelled on CC-Monitor's home page (status cards, intervention level, 10 threat categories, activity, trend, distributions — **every number opens its detail list**, enforced by a Go consistency test), operation timeline and session flow chart (ported from CC-Monitor), **session list + heartbeat**, **detected AI**, 10 themes (default "Standard", from CC-Monitor), bilingual (309 entries aligned), an Appearance dialog (theme swatches / 7 interface fonts / 12–18px size, system font names only, nothing downloaded), and an "Auto-scroll to latest" switch on the Events page. Driven in a real Chrome |
| Multi-AI detection and OpenCode hook | 🔶 | `internal/agents` carries CC-Monitor's 10 agent definitions plus OpenCode; the L3 first scan also reports agents that were already running; `/api/detected` and `xmon doctor` list them with the next command to run; `xmon install --agent opencode` writes the plugin (idempotent). **The real plugin was driven from node against a running daemon (block / allow / recorded); it has not been loaded by a restarted real OpenCode** |
| Status page (account quota / model usage / session board) | 🔶 | Model usage: the proxy records the requested model into the audit event (Gemini takes it from the path) and counts tool calls per model, **not tokens**; the session board includes the Git branch; account quota is `internal/usage` — **off by default**, reads the local Claude Code OAuth token and queries a non-public endpoint, the address is hard-coded and not configurable, the token is never written to disk or logged. **The client was tested only against a local fake server, never the real endpoint** |
| Session list and heartbeat (`internal/sessionview`) | 🔶 | Covers **every** AI: sessions managed by `xmon run`, unmanaged processes on the host, sessions reported by a native hook, and imported CC-Monitor history; four states: working (activity within 5 minutes) / idle / awaiting approval / ended. **Limitation: a hook-only session has no pid to check, so liveness is a heuristic (the agent has a running process, or acted within 5 minutes)** |
| CLI (`xmon`) | ✅ | start/stop/status/run/install/tail/rules/approve/pending/mode/verify/import/policy/doctor |
| CC-Monitor read-only import (`xmon import`) | ✅ | Deduplication, joined to the hash chain, verified end to end |
| GUI client recognition + capability tiers | 🔶 | Recognition and the "Coverage" labels implemented; **the tooling that would deliver those tiers is not built** (below) |
| Bilingual docs | ✅ | README / PROGRESS in Chinese and English; DESIGN.md is Chinese only |

## Known gaps

Ordered by impact. The first three directly affect day-to-day use and should be handled first.

| # | Gap | Impact | Location |
|---|---|---|---|
| 1 | **The proxy buffers the entire SSE response before rewriting and forwarding**, instead of streaming | Every managed agent's reply appears only after the model has finished generating, so interaction is visibly slower and long replies may hit client timeouts. DESIGN §7.4's "text flows through immediately, only tool calls are buffered" is **not implemented** | `internal/proxy/server.go` (`io.ReadAll(resp.Body)`); the adapter interface also takes a complete `[]byte` |
| 2 | **No keep-alive while waiting for an approval**; the `proxy.confirm_ping_s` setting is not used by any code | When human confirmation is needed, the agent's connection sits silent for up to 90 s and may be dropped by a client timeout; because of gap 1 the client has received nothing by then anyway | `internal/gate`, `internal/proxy` |
| 3 | **The tooling for the GUI tiers is not built**: there is no installer that points an app's config at the proxy (`xmon install` currently supports only Claude Code and OpenCode), and no system proxy + selective MITM | The `config` / `proxy` tiers on the "Coverage" page describe what is **theoretically achievable**; no tool currently achieves it, so GUI clients are effectively observe-only | `cmd/xmon/install.go` (no MITM code exists) |
| 4 | OpenAI Responses streaming is passed through | Agents using that protocol with streaming on get **no tool-call interception** | `internal/proxy/adapter_responses.go` |
| 5 | L2 file monitor covers only the daemon's start directory | Sensitive writes in other project directories are not seen by L2 | `cmd/xmond/main.go` |
| 6 | Unverified external facts: the Z.ai Gemini endpoint path (`api/geminiv1beta`), the `glm-4.5` model ID and `thinking` parameter, the `GOOGLE_GEMINI_BASE_URL` variable name, Claude Code hook input fields | The matching features may need configuration changes in a real environment | `internal/config/config.go`, `cmd/xmon/run.go` |
| 7 | Client-PID lookup for the proxy shells out to `lsof` on every request | Extra overhead under heavy request rates; not implemented on Windows | `internal/proxy/pidlookup.go` |
| 8 | The hook `post` phase only acknowledges, with no audit analysis | Tool results do not feed into decisions | `internal/hookgw` |
| 9 | Linux Landlock restricts writes only; reads and execution are unrestricted; `~/.claude` and similar must stay writable | A narrower protective surface than macOS; tamper protection for agent config still relies on L4 / hooks | `internal/enforce/landlock_linux.go` |
| 10 | `AUTH_RENAME` checks the source path only | The ESF client does not guard renames onto a protected path | `macos/XmonES/main.swift` |
| 11 | **The `proxy.fail_open` setting is read by no code** | The docs/sample say "fall back to direct when the daemon fails"; it does not. If the daemon dies, LLM requests of agents started with `xmon run` fail | `internal/config/config.go`, `cmd/xmon/run.go` |
| 12 | OpenCode through the proxy has no built-in profile and is unverified | `xmon run --agent opencode` only sets `OPENAI_BASE_URL`; OpenCode takes its endpoint from the provider settings in `opencode.json`. For OpenCode the native hook plugin is the only reliable path today | `cmd/xmon/run.go` |
| 13 | Account quota was never run against the real endpoint with real credentials | The client is tested against a local fake server; `/api/oauth/usage` is a non-public endpoint that can change | `internal/usage` |

## Next steps (suggested priority)

**P0 — affects usability**
1. Make the proxy truly streaming: have the adapters read from an `io.Reader`, emit text events immediately and buffer only `tool_use` blocks (gap 1).
2. SSE keep-alive while waiting for an approval (gap 2).

**P1 — deliver what is claimed**
3. OpenAI Responses streaming interception (gap 4).
4. Make L2 follow each session's project root (gap 5).
5. Run a real integration pass with Claude Code / Gemini CLI / Codex and confirm the external facts in gap 6.
6. On a Linux host, run `go test ./internal/enforce/` and an end-to-end `xmon run --sandbox`; get the bpftrace probe running.
7. Tooling for the GUI tiers: a config installer for clients that accept a custom endpoint (e.g. Cursor); system proxy + selective MITM (with certificate-pinning detection and automatic downgrade).

**P2 — enhancements**
8. Verify on real Windows (Sysmon probe, firewall lock).
9. Apply for the Apple ES entitlement and verify `XmonES` on hardware.
10. Linux BPF-LSM.
11. Session replay, GLM reports, SIEM export, central management.

## Phase log

| Phase | Content |
|---|---|
| Design | Studied cc-monitor and ArgusBPF, reviewed the requirements (fixing a dozen-plus issues such as "intercept the request rather than the response") and produced DESIGN.md |
| Core implementation | Event model, rule engine (ported from cc-monitor), shell parsing, cross-workspace detection, decision engine, GLM, DLP, store and hash chain, approval console |
| Interception layers | L4 proxy (Anthropic / OpenAI Chat / Responses / Gemini), L4b hook, L3 process tree, L2 file, cross-verification |
| L1 collection | bpftrace / eslogger+nettop / Sysmon subprocess backends (the macOS nettop and Windows parts were done in parallel by a sub-agent) |
| Experience and ecosystem | Web UI, CLI, GUI client recognition and capability tiers, read-only CC-Monitor import |
| Rename and bilingual | Unified as X-Monitor / `xmon` / `~/.xmon`; README and Web UI in Chinese and English |
| Multi-AI and visuals | Session list and heartbeat, detected AI, OpenCode plugin, 10 themes, dataviz palette validation (below) |
| Kernel-level enforcement | Static policy, macOS sandbox (tested), Linux Landlock, kill-after-exec, Windows firewall rules, ESF AUTH client, `tracked-roots.json` |

## Main problems fixed in this phase

All of these were found by actually running it; each has a regression test. **Do not revert them**:

- **L2 file-monitor feedback loop**: watching its own `~/.xmon` produced a million events. It now ignores its own files, debounces the same path for 500 ms, rate-limits globally (one `fs_event_storm` event when exceeded), and the daemon announces its own config writes.
- **Session attribution broken**: the `RootPID` sent by `xmon run` was silently dropped. `internal/ctlproto` now holds the shared types and the daemon decodes strictly.
- **L3 counted the daemon's own `ps` polling as an agent child process**: the daemon's whole subtree is now excluded.
- **Blank Web UI without a token**: it now shows "Unauthorized" with a token field; the token is kept in localStorage and removed from the address bar.
- **Overview numbers that could not be clicked**: all of them drill down now, and `TestEveryOverviewNumberMatchesItsDrillDown` guarantees "card number = rows in the list".
- **`todowrite` classified as a file write** and **OpenCode tool names / field aliases**: fixed in `toolclass`.
- **An agent's helper process counted as a second agent** (OpenCode's resident `opencode.exe serve`): children of the same agent join the parent's tree.
- **Live hook-reported sessions labelled "imported / ended"**: `hook` and `imported` are now distinct.

## Palette validation (dataviz)

The chart categorical colours (`--cat-1..6`) come in a light and a dark set, validated with dataviz's `validate_palette.js` on the surfaces they are actually drawn on: the light set passes on the "Standard" panel colour and on white; the dark set passes on the panel colours of dark / dracula / midnight / ocean / forest / sunset / rose; **on Nord's mid-tone panel (#3b4252) the contrast check is WARN (<3:1)**, made up for by bars that carry text labels and by tables. KPI numbers are plain ink, and state is shown by an icon + text chip rather than colour alone.

## Sources and licensing

Ported from [cc-monitor](https://github.com/cn0xroot/cc-monitor) (MIT): the rule set, shell segment parsing, cross-workspace detection, the approval and rule-merge approach, the cross-verification idea, and the **operation timeline / session flow chart / heartbeat indicator / theme palettes / OpenCode plugin protocol** (`web/timeline.js`, `internal/agentcfg` and `internal/sessionview` are ports or rewrites of its design). Design ideas (agent signatures, collection fallback, event model) are borrowed from [ArgusBPF](https://github.com/cn0xroot/ArgusBPF): that repository ships no license file, so **none of its code was copied** and the matching implementations are rewrites. See [NOTICE](./NOTICE).
