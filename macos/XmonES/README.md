# XmonES — Endpoint Security AUTH client (experimental)

**Status: compiles and links; has never been run with the entitlement.** Treat
it as a reference implementation of DESIGN.md §11.2, not a shipped feature.

## What it does

Subscribes to `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_UNLINK` and `AUTH_RENAME` and
denies, **only for processes descending from a root pid in
`~/.xmon/tracked-roots.json`** (written by `xmond` for live `xmon run`
sessions), whatever `~/.xmon/enforce-policy.json` forbids. ES events are
system-wide; the ancestry check is what keeps it from touching your own
processes. Both files are re-read every second.

Known gaps: `AUTH_RENAME` checks the source path only (not the destination);
no network filtering (ESF has no TCP-connect event; that needs a
NetworkExtension content filter).

## Build

```sh
make es-client        # from the repository root; writes bin/xmon-es
# equivalent:
swiftc macos/XmonES/main.swift -o bin/xmon-es -lEndpointSecurity -lbsm
```

`-lbsm` is required for `audit_token_to_pid`; EndpointSecurity is linked as a
library (`-lEndpointSecurity`), not as a framework.

## Why it doesn't just run

`es_new_client` fails unless **all** of these hold:

1. The binary carries the `com.apple.developer.endpoint-security.client`
   entitlement — Apple grants it by request; apply early, review takes weeks.
2. It is code-signed (and notarized for distribution).
3. It runs as root.
4. The host app / terminal has Full Disk Access.

Without them it exits with `es_new_client failed (N)` (5 = not privileged).

## Safe rollout

ES AUTH handlers must answer before `msg->deadline` or the system kills the
client. The handler only does in-memory lookups, but test under load before
relying on it, and keep `xmon run --sandbox` (sandbox-exec) as the primary
managed-mode control — it needs no entitlement.
