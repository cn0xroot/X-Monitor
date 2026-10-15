[中文](./USAGE.md) | **English**

# X-Monitor User Guide

This guide covers how to use it. For architecture and design trade-offs see [DESIGN.md](./DESIGN.md); for how far each part has been verified and the known gaps see [PROGRESS.en.md](./PROGRESS.en.md). Anything that has **not been verified in a real environment** is stated as such here.

## 1. What it is

X-Monitor adds a checkpoint between an AI coding assistant (Claude Code, Codex, Gemini CLI, OpenCode, …) and the actions it wants to take: dangerous commands, sensitive file reads and writes, exfiltration, supply-chain installs, persistence backdoors, and attempts to evade the monitor itself. An action that hits a rule can be **blocked beforehand**, held for **human confirmation**, or just **logged**. Every event goes into a hash-chained audit database on this machine; the dashboard listens on `127.0.0.1` only and needs a token. Telemetry is off by default and data stays local.

## 2. Install and start

Needs Go 1.26 or newer (pure Go, no cgo).

```sh
make build            # produces bin/xmond  bin/xmon  bin/xmon-hook
export PATH="$PWD/bin:$PATH"
xmon start            # start the daemon xmond (in the background)
xmon status           # daemon, proxy address, dashboard address, rule count
xmon ui --open        # print and open the dashboard URL with its token
xmon doctor           # self-check, and list the AI running on this host with the next step for each
```

- `xmon stop` stops the daemon; `xmon start --foreground` runs it in the foreground (for debugging).
- The data directory is `~/.xmon` (change it with `XMON_HOME`). The token is in `~/.xmon/token`.
- `make cross` checks that all four platforms (linux amd64/arm64, darwin arm64, windows amd64) compile; `make test` runs the tests.

## 3. First, understand "managed"

An AI is in one of three states in X-Monitor, shown on the dashboard under Overview → Detected AI and on the Sessions page:

| State | Meaning | What it can do |
|---|---|---|
| **Managed** | Started through `xmon run` | `xmon run` injects a `BASE_URL` pointing at the local proxy, so every tool call goes through the L4 proxy and is blocked beforehand in the response stream; a sandbox can be stacked on top |
| **Hook-guarded** | Not started with `xmon run`, but a native hook is installed (Claude Code hooks / the OpenCode plugin) and its reports have actually arrived | Every tool call is vetted by `xmon-hook` first and can be blocked beforehand, without the proxy |
| **Unmanaged** | Only seen by the process-tree scan | **Observation** only (L3 process tree, L2 files, L1 system layer); no blocking beforehand |

Two things on the cards are easy to misread:

- **Restart needed**: the plugin file is written, but no hook report from that AI has arrived. Most AI tools load plugins/hooks only at startup, so **restart it** for the hook to take effect.
- An AI that was already running (say you opened opencode before starting X-Monitor) does not become "managed" just because monitoring was installed later: the proxy address is not in its environment. Either relaunch it with `xmon run`, or install the hook and restart it.

## 4. Connecting each AI

| AI | Recommended route | Command | Blocking depth | Verification |
|---|---|---|---|---|
| Claude Code | Proxy + native hook | `xmon run -- claude`; add the hook with `xmon install` | Blocked beforehand (the proxy rewrites the response stream; the hook runs before the call) | Protocol adapters were only verified against synthetic samples, never against a real Claude Code |
| Codex CLI | Proxy | `xmon run --agent codex -- codex` | Blocked beforehand (OpenAI Chat; **Responses streaming is passed through, not blocked**) | Same |
| Gemini CLI / Z.ai CLI | Proxy | `xmon run --agent gemini -- gemini` | Blocked beforehand (Gemini `generateContent`) | The env var name and the Z.ai endpoint path are unverified |
| Cursor (CLI), Aider, GLM, CodeGeeX | Proxy (OpenAI-compatible) | `xmon run --agent cursor -- …` (same for `aider` / `glm` / `codegeex`) | Blocked beforehand | Not tried end to end |
| **OpenCode** | **Native hook plugin** | `xmon install --agent opencode`, **then restart opencode** | Every tool call blocked beforehand (the plugin calls `xmon-hook` synchronously; exit code 2 blocks) | The real plugin was driven from node against a running daemon; **never loaded by a restarted real OpenCode** |
| Anything else | Proxy (falls back to OpenAI-compatible) | `xmon run --agent <name> -- <command>` | Depends on whether it honours `OPENAI_BASE_URL` | — |
| GUI desktop apps (Cursor desktop, Windsurf, JetBrains AI, …) | None | — | **Observe only** (certificate pinning / ignores the proxy); the Coverage page says so honestly | The tooling (a config installer, MITM) is not built |

**About OpenCode and the proxy:** OpenCode takes its endpoint from each provider's settings in `opencode.json`, not from a `BASE_URL` environment variable, and `xmon run` has no built-in profile for it (it falls back to setting only `OPENAI_BASE_URL`). So for OpenCode, **use the plugin**. Sending it through the proxy would mean pointing each provider's `baseURL` at `http://127.0.0.1:7789/p/<provider>` yourself; that route has not been verified.

Details of `xmon run`:

```sh
xmon run [--agent X] [--sandbox] -- <command…>
```

- Without `--agent` the command name is used as the agent name; an unknown name prints a notice and is treated as OpenAI-compatible.
- It starts the daemon if needed, registers a `zs_…` session, injects the proxy address into the environment (`ANTHROPIC_BASE_URL` for Claude, `OPENAI_BASE_URL` for Codex/Cursor/Aider, `GOOGLE_GEMINI_BASE_URL` for Gemini/Z.ai), and sets `XMON_SESSION` and `XMON_AGENT`.
- `--sandbox` adds kernel-level limits (section 9); if a sandbox is requested but unavailable it **refuses to start** rather than silently running without one.
- When the daemon fails, `xmon run` does not fall back to a direct connection: the config has `proxy.fail_open`, but **no code reads it** (not implemented).

## 5. Day to day

### 5.1 Intervention level

```sh
xmon mode               # show
xmon mode active        # block / confirm on a rule hit (default)
xmon mode paused        # record only; never block, never prompt — use it to watch first
xmon mode stopped       # neither intervene nor record
```

The segmented control on the dashboard overview does the same.

### 5.2 Approvals

When a "confirm" rule hits, the action pauses until you decide; if the timeout passes (default 90 s, `approval.timeout_s`) it counts as **denied**. Three ways to answer:

- the dashboard's Approvals page: allow once / allow for this session / deny;
- the command line: `xmon pending`, `xmon approve <id>`, `xmon deny <id>`;
- desktop notifications (`approval.desktop_notify: true`).

> Known gap: while waiting for an approval the proxy sends no keep-alive to the client, so the client may time out first; and since the proxy currently buffers the whole response, the agent has received nothing yet anyway (PROGRESS.en.md gaps 1 and 2).

### 5.3 Rules

92 default rules (86 ported from cc-monitor, 6 self-protection `xmon_*` rules).

```sh
xmon rules test "rm -rf ~"          # which rule a command hits, its risk and action
```

Three actions: `block`, `confirm` (human), `log` (allow and record). Your own additions and changes live in `~/.xmon/rules.json`, merged with the built-in rules and **hot-reloaded when edited**; `rules.defaults_snapshot.json` is a snapshot of the built-ins used to merge on upgrade. Rules with `downgradable: false` (self-protection, for instance) cannot be downgraded.

### 5.4 Events on the command line

```sh
xmon tail -f                  # live event stream
xmon tail --risk high         # high risk only
xmon verify                   # verify the audit hash chain (tamper evidence)
```

## 6. The dashboard, page by page

Open it with `xmon ui --open`. After the first visit with the token, the token is kept in the browser's localStorage and removed from the address bar; without a token the page shows "Unauthorized" and a token field. Top right: `⚙` appearance, `中 / EN` language.

- **Overview**: status cards (intervention level, managed sessions, pending approvals, blocked, protection layers) → **Detected AI** → 10 threat-category cards → activity → tool calls → trend → distributions. **Every number opens** the events it counted, and a test guarantees "card number = rows in the list". The "Managed sessions (running)" card opens the Sessions page.
- **Detected AI**: from the process-tree scan, every AI running on the host, marked Managed / Hook-guarded / Restart needed / Unmanaged, with blocking depth, verification status and the next command (with a copy button).
- **Approvals**: pending confirmation requests.
- **Events**: the live event table, filterable by risk. **The "Auto-scroll to latest" switch**: on, new events show at once and the view returns to the top; off, the list freezes and new events only add up to "N new events — click to show".
- **Operation timeline**: one lane per session; the colour is the worst risk in that slot, a red outline means something was blocked; click a lane or slot to see the **session operation flow** (zoom, pan, minimap, node details).
- **Sessions**: one row per monitored AI — managed sessions, unmanaged processes, hook-reported sessions, imported history — each with a **heartbeat**. A deeper colour and bigger wave mean more recent activity, and it only beats within 5 minutes. States: working / idle / awaiting approval / ended. Click a row for its events.
  - A managed session is judged alive by its root pid; a session reported only through a hook has no pid, so its liveness is a **heuristic** (the AI has a running process, or acted within 5 minutes).
- **Status**: account quota, model usage and the session board (section 7).
- **Coverage**: how deep each kind of AI can be blocked, and why.
- **Appearance (⚙)**: 10 themes (default "Standard"; light and dark), 7 interface fonts, size 12–18 px, reset. Fonts are system font names only, nothing is downloaded; a font that is not installed falls back.

## 7. The Status page and quota

Three blocks:

1. **Account quota**: the Anthropic plan's 5-hour window and weekly allowance (including per-model limits and extra spend). The bar colour scheme is selectable. **Off by default**, for the reasons below.
2. **Model usage**: audited tool calls per model, with blocked counts, sessions and agents. **Tokens are not counted** — the proxy rewrites tool calls, it does not meter usage. The model is only recorded for requests that go through the proxy (`xmon run`); hook reports do not carry it.
3. **Session status**: one card per AI: heartbeat, directory, Git branch, events and blocks, last activity; click for its events.

### Turning on account quota (optional — read the risks first)

Add to `~/.xmon/config.yaml`:

```yaml
usage:
  anthropic_enabled: true
```

then `xmon stop && xmon start`. With it on, the daemon reads the OAuth login token Claude Code keeps on this machine (Linux/other: `~/.claude/.credentials.json`; macOS also reads the keychain item `Claude Code-credentials`, and the system asks for confirmation the first time) and makes one read-only request to `api.anthropic.com/api/oauth/usage`; the result is cached for 3 minutes.

- The token is used in memory for that request only and sent only to that fixed Anthropic address (**the address is not configurable**, so editing the config cannot send the token elsewhere); it is never written to disk, logged or returned by any endpoint.
- This is the **non-public, reverse-engineered** endpoint CC-Monitor and ccstatusline use; it can change at any time, and using a subscription token from a third-party tool **may be against the provider's terms** — whether to turn it on is your call.
- An expired token is not sent; the page tells you to run a command in Claude Code to refresh it, or `/login`.
- There is no quota source other than Anthropic: other providers (Z.ai included) are not implemented, and nothing is made up.
- **Verification:** the client is tested against a local fake server (headers, parsing, caching, an expired token is not sent, errors never contain the token); it **has not been run with real credentials against the real Anthropic endpoint**, and the page rendering was checked with sample data shaped like its response.

## 8. Importing CC-Monitor

If you still run CC-Monitor (to keep handling Claude Code hooks), its audit database can be imported **read-only**:

```sh
xmon import                          # default ~/.cc-monitor/events.db
xmon import --from /path/to/events.db
xmon import -f                       # keep following in the background
```

Rows are deduplicated by their original row id, mapped into the unified event model and merged into the hash chain; the other database is never modified. Imported sessions show as "Imported" on the Sessions page and as `ext:` lanes on the timeline.

## 9. Kernel-level enforcement (optional)

The last line of defence beyond the proxy and hooks: even if an agent goes around tool calls, the system layer can still limit it.

```sh
xmon policy init            # write ~/.xmon/enforce-policy.json (editable)
xmon policy show            # the policy and the sandbox availability on this platform
xmon run --sandbox -- claude
xmon policy firewall        # generate Windows firewall (netsh) commands; prints only, runs nothing
```

| Tier | Platform | Status |
|---|---|---|
| `sandbox-exec` sandbox | macOS | **Tested** |
| Landlock | Linux | Only compiled and type-checked, **never run on Linux**; limits writes only, not reads or exec |
| Kill after exec (`probe.enforce: true`) | needs the L1 probe (root) | A millisecond window; not verified on hardware |
| Windows firewall rules | Windows | Commands are generated, **never applied** |
| macOS ESF AUTH client | macOS | Compiles and links, **cannot run without the entitlement** |
| BPF-LSM | Linux | **Not built** |

L1 system-layer collection (bpftrace / eslogger+nettop / Sysmon) is controlled by `probe.enabled` (`auto` | `off`) and needs root.

## 10. Configuration reference

File: `~/.xmon/config.yaml`; see [config.sample.yaml](./config.sample.yaml). Restart `xmond` after changes (the rules file is the exception: it hot-reloads).

| Key | Default | Meaning |
|---|---|---|
| `mode` | `active` | `active` / `paused` / `stopped` |
| `ui_addr` | `127.0.0.1:7788` | Dashboard; a non-loopback address requires the token |
| `proxy_addr` | `127.0.0.1:7789` | The LLM proxy |
| `proxy.fail_open` | `false` | **Not implemented**: the setting exists but no code uses it |
| `proxy.dlp_action` | `alert` | When credentials are about to reach the model: `alert` / `redact` |
| `proxy.routes.<name>` | see code | Override a provider's upstream URL |
| `proxy.confirm_ping_s` | `10` | **Not implemented**: keep-alive while awaiting approval; no code uses it |
| `glm.enabled` | `false` | Semantic audit (L5), **off by default**; needs `ZAI_API_KEY` and sends (redacted) actions to Z.ai |
| `approval.timeout_s` | `90` | A confirmation that times out is denied |
| `approval.desktop_notify` | `true` | Desktop notifications |
| `storage.retention_days` / `max_events` | `30` / `1000000` | Retention and cap |
| `probe.enabled` / `probe.enforce` | `auto` / `false` | L1 probe and kill-after-exec |
| `usage.anthropic_enabled` | `false` | Account quota on the Status page, see section 7 |

Environment variables: `XMON_HOME` (data directory), `XMON_STRICT=1` (`xmon-hook` **denies** instead of allowing when it cannot reach the daemon), `XMON_HOOK` (overrides the `xmon-hook` path in the OpenCode plugin), `XMON_SESSION` / `XMON_AGENT` (injected by `xmon run`).

## 11. Data and privacy

Under `~/.xmon/`: `events.db` (the audit database, hash-chained), `config.yaml`, `token`, `rules.json`, `xmond.log`, `enforce-policy.json`, `tracked-roots.json`, and the local sockets `xmond.sock` / `hook.sock`.

- Data stays on this machine; with GLM and account quota off there are no outbound requests (the proxy forwarding an agent's own LLM traffic does not count).
- The dashboard binds to `127.0.0.1` only, and every API and WebSocket needs the token.
- The monitor protects its own config and data: an agent writing or deleting under `~/.xmon` is blocked outright by the `xmon_self_*` rules.

## 12. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Blank dashboard / "Unauthorized" | Missing token. Run `xmon ui --open`, or paste `~/.xmon/token` into the page's field |
| The page says it cannot reach xmond | Check `xmon status`; run `xmon start` |
| `curl` to `127.0.0.1` fails when `HTTP_PROXY` is set | Add `--noproxy '*'` or set `NO_PROXY=127.0.0.1` |
| An AI shows "Unmanaged" | See section 3: launch it with `xmon run`, or install the hook and restart it |
| It shows "Restart needed" | Restart that AI so it loads the plugin |
| The OpenCode plugin is installed but nothing is blocked | Check that `~/.config/opencode/plugins/xmon.js` exists, opencode was restarted, and the daemon is running (when the daemon is unreachable the hook allows by default; set `XMON_STRICT=1` to deny instead) |
| The "system-layer observations" number keeps growing | L3 records the whole process tree of your current AI session as observations; that is normal |
| Replies only appear after the whole generation | Known gap: the proxy buffers the whole SSE before rewriting and forwarding (PROGRESS.en.md gap 1) |
| A Unix socket path is too long | Use a shorter `XMON_HOME` (socket paths must be under 104 characters) |

## 13. What not to rely on yet

See [PROGRESS.en.md](./PROGRESS.en.md) for the full list and priorities. The most important: the protocol adapters were verified only on synthetic data; the Linux and Windows code has not run on those systems; the proxy is not streaming; GUI desktop apps are observe-only; and neither OpenCode through the proxy nor the account quota against the real endpoint has been verified.
