[中文](./README.md) | **English**

# X-Monitor

A cross-platform security monitor for AI coding assistants. It sits between the AI agent and the LLM, and at the operating-system level, to detect and block dangerous operations in real time: system destruction, data exfiltration, supply-chain attacks, persistence backdoors, and attempts to evade the monitor itself.

Design document: [DESIGN.md](./DESIGN.md) (Chinese). This project ports parts of [cc-monitor](https://github.com/cn0xroot/cc-monitor) (MIT; see [NOTICE](./NOTICE)) and borrows design ideas from [ArgusBPF](https://github.com/cn0xroot/ArgusBPF) (that repository ships no license file, so none of its code was copied).

**Detailed usage: [USAGE.en.md](./USAGE.en.md)** (install, connecting each AI, managed vs. unmanaged, every dashboard page, quota, configuration, troubleshooting).

Progress, verification status and known gaps: [PROGRESS.en.md](./PROGRESS.en.md).

## Why you need it

AI coding assistants run commands, read and write files, and make network requests on their own. If one is hijacked by prompt injection, or a dependency or script is malicious, it can `rm -rf`, send your `.env` or SSH private key to an external server, install a malicious package via `curl | bash`, or plant a crontab / git-hook backdoor. X-Monitor steps in before those operations actually happen.

## Five-layer architecture (the four lower layers need no privileges and run everywhere)

| Layer | Role | Cross-platform | Privileges | Blocking |
|---|---|---|---|---|
| L5 Intent | GLM semantic audit: understand intent, resolve false positives, spot unknown threats | ✅ | none | semantic |
| L4 Communication | Intercept tool calls between agent and LLM; rewrite the response stream to block ahead of execution | ✅ | none | request-level |
| L4b Hook | Agents with native hooks (e.g. Claude Code) are intercepted directly | ✅ | none | pre-execution |
| L3 Process | Process-tree tracking, session attribution | ✅ | none | monitor only |
| L2 File | Sensitive-file / workspace change monitoring | ✅ | none | monitor only |
| L1 System | eBPF / eslogger / Sysmon kernel events and bypass cross-checking; optional kernel-level enforcement (below) | per platform | root | enhancement |

The core decision happens in **L4 response-stream rewriting**: the tool call an agent is about to run appears in the stream the LLM returns. The proxy buffers it and hands it to the decision engine. If allowed, it is forwarded unchanged; if blocked, it is replaced by an explanatory message and `stop_reason` is changed to end the turn. The agent sees no error, the model sees why the call was refused, and the session continues.

## Quick start

```sh
make build          # produces bin/xmond bin/xmon bin/xmon-hook (pure Go, no cgo)
./bin/xmon start    # start the daemon

# Launch any agent under management (proxy env vars injected automatically)
./bin/xmon run -- claude
./bin/xmon run --agent codex -- codex
./bin/xmon run --agent gemini -- gemini     # the Z.ai CLI is also Gemini CLI

# Open the dashboard (the terminal prints a URL that includes the token)
open http://127.0.0.1:7788/?token=...
```

Claude Code can also install native hooks (best blocking experience; deduplicated against the proxy by `tool_call_id`):

```sh
./bin/xmon install            # writes Pre/PostToolUse into ~/.claude/settings.json
```

## CLI

```
xmon start|stop|status            daemon
xmon run [--agent X] [--sandbox] -- <cmd…>   launch an agent under management (--sandbox: kernel sandbox)
xmon install [--agent X]          register hooks (claude-code | opencode; restart OpenCode afterwards)
xmon tail [-f] [--risk high]      live event stream (WebSocket)
xmon rules test "<command>"       see which rule a command hits
xmon approve <id> | deny <id>     handle approvals
xmon pending                      list pending approvals
xmon mode active|paused|stopped   intervention level
xmon verify                       verify the audit hash chain
xmon import [--from <db>] [-f]     read-only import of a CC-Monitor events.db into the unified dashboard
xmon policy init|show|firewall    kernel-enforcement policy (create / inspect / Windows firewall rules)
xmon doctor                       self-check (daemon / token / proxy / GLM / running AI and their hook status)
xmon ui [--open]                  print / open the dashboard URL with its token
```

### Running alongside CC-Monitor

X-Monitor's rules, shell parsing, cross-workspace detection and approval console were ported from [CC-Monitor](https://github.com/cn0xroot/cc-monitor) (MIT; see NOTICE). If you still run CC-Monitor (to keep handling Claude Code hooks), `xmon import` imports its audit database **read-only** (default `~/.cc-monitor/events.db`), mapping events into X-Monitor's unified event model and hash-chained audit log. Rows are deduplicated by their original row id, and `-f` keeps following new events in the background. CC-Monitor's database is never modified.

## Dashboard

Open it with `xmon ui --open`. Six tabs: Overview, Approvals, Events, Operation timeline, **Sessions**, Coverage. The top right switches between Chinese and English; the ⚙ **Appearance** dialog (as in CC-Monitor) picks one of **10 themes** (default "Standard", light and dark), the interface font (7 choices, system font names only) and the size (12–18px). The Events page has an "Auto-scroll to latest" switch: when off, the list freezes and new events only add to a counter.

- **Detected AI**: from the process-tree scan, lists **every** AI running on the host (not only Claude Code), says whether it is managed or not, how deep interception goes, whether its hook is installed, and the next command to run.
- **Sessions + heartbeat**: one row per AI — sessions managed by `xmon run`, unmanaged processes, hook-reported sessions, and imported history. A deeper colour and bigger wave mean more recent activity, and it only beats within 5 minutes; states are working / idle / awaiting approval / ended. Click a row to see its events.
- **Every number on the overview opens** the events it counted. It listens on 127.0.0.1 only and needs the token.

## Supported agents

Claude Code, **OpenCode**, Codex, Cursor, Gemini CLI, the **Z.ai CLI (= Gemini CLI)**, GLM / CodeGeeX, Aider, Antigravity, Grok CLI, and more (the process-recognition table carries all of CC-Monitor's agent definitions; Claude Code and OpenCode also have a native hook, the rest are intercepted through the proxy via `xmon run`, and an agent that is recognised but unmanaged is only observed through the process tree). Rules are written against **canonical tool classes** (`exec.shell`, `fs.write`, `net.fetch`, …); each agent's raw tool names are mapped by adapters, so "supports any agent" is an architectural property rather than something hard-coded per agent.

Implemented protocol adapters: Anthropic Messages, OpenAI Chat Completions (including GLM / Zhipu / DeepSeek-compatible APIs), OpenAI Responses, and **Google Gemini `generateContent`**.

## Decision engine

Rule fast path (<1 ms, 92 default rules including self-protection) → session correlation (e.g. "read a sensitive file, then connect out" escalates) → decision cache → GLM semantic analysis. The merge matrix guarantees that **GLM can escalate any verdict, but can only relax "confirm" to "allow" under controlled conditions, and can never override a rule's block**. Content sent to GLM is redacted by DLP first, and cloud analysis is off by default and must be enabled explicitly.

## Privacy

All data stays on your machine by default (SQLite plus a tamper-evident hash chain) and the code contains no telemetry. The dashboard binds to `127.0.0.1` only and requires a token. GLM cloud analysis is the only optional outbound path, and content is redacted before it is sent.

## Platform support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| L4 proxy / L4b hooks / L3 process / L2 file / L5 GLM | ✅ | ✅ | ✅ |
| L1 collection (optional, privileged) | bpftrace (eBPF), needs root | eslogger (exec) + nettop (network), needs root | Sysmon event log; needs administrator and Sysmon installed |

L1 is an optional enhancement. When it is unavailable, the four core layers keep working and the dashboard shows the degraded state.

## Kernel-level enforcement (L1)

Regex rules cannot run inside a kernel, so the kernel layer uses a **static policy** (`~/.xmon/enforce-policy.json`: paths that must not be written, paths that must not be read, programs that must not be executed). Create it with `xmon policy init` and edit it by hand. There are several mechanisms, and **their verification status is stated honestly**:

| Mechanism | Platform | What it does | Verification status |
|---|---|---|---|
| Managed sandbox `xmon run --sandbox` | macOS: `sandbox-exec`; Linux: Landlock (kernel ≥ 5.13) | **Kernel-enforced** limits on the agent's whole process tree; denial is deterministic (not a kill after the fact). macOS: no writes to credentials / shell startup files / the monitor's own directory, no reads of the monitor token, no execution of `nc` and similar. Linux (Landlock): **restricts writes only** — writes are allowed only beneath whitelisted roots such as the project and temp directories; reads and execution are not restricted | macOS: **tested** (unit test runs the real sandbox, plus an end-to-end run). Linux: implemented, cross-compiles and passes vet, ships with a test that runs automatically on Linux, but **has not yet been run on a Linux host** |
| Kill after exec `probe.enforce: true` | Linux / macOS / Windows (depends on the L1 probe) | When the probe sees a program the policy forbids being executed inside a managed process tree, it terminates it. Only acts on managed process trees and also works on already-running agents. **There is a millisecond window** (the program has started before it is killed) | Policy matching and the kill logic are tested against a real process; integration with a privileged probe is **not verified** |
| Windows firewall lock | Windows | `xmon policy firewall` generates `netsh` rules that confine named agent programs to loopback (i.e. only reachable through the X-Monitor proxy), preventing a direct connection to an LLM that would bypass L4. It only prints by default; `--apply` executes | Command generation is tested; **never applied on Windows** |
| macOS ESF AUTH | macOS | `macos/XmonES`: an Endpoint Security AUTH client that can synchronously deny exec / open / unlink / rename | Source type-checks and compiles and links; **needs Apple's ES entitlement to run and has never been executed** (see `macos/XmonES/README.md`) |
| Linux BPF-LSM | Linux | — | **Not implemented** (compiling and verifying it needs the target kernel's BTF / `vmlinux.h` and clang on Linux; Landlock covers managed mode for now) |

Note: a sandbox denial **cannot be approved by the user at run time** (unlike an L4 "confirm"), so the default policy only covers locations an agent has no legitimate reason to write. In Landlock mode on Linux, agent state directories such as `~/.claude` must remain writable (Landlock cannot carve exceptions out of a granted directory); protection against tampering with their config files stays with the L4 / hook rules.

## License

Proprietary — All Rights Reserved. Portions ported from cc-monitor / ArgusBPF are covered by NOTICE (MIT).
