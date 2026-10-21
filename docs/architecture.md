# Architecture and trust boundaries

Status: development alpha, protocol version 1.

## Repository boundary

This repository owns the portable `openmaskit_connector` package, the
`openmaskit-connector` executable, host-side launch approval, the outbound
bridge and the private relay image. The macOS companion owns its native UI and
the local OpenMaskit/Presidio lifecycle. The connector repository has no Docker
lifecycle manager and does not modify the OpenMaskit fork.

The relay presents ordinary MCP Streamable HTTP. OpenMaskit's existing HTTP
target support is sufficient; no private fork transport is needed.

```text
AI client <-> OpenMaskit <-> private relay MCP endpoint
                                ^
                                | authenticated outbound WebSocket
                                |
                       host connector <-> locally approved stdio MCP
```

The companion passes its existing `~/.openmaskit-companion/` state directory
explicitly when it starts the connector. Standalone use defaults to
`~/.openmaskit-connector/`. This separation avoids changing established
companion pairing/profile state. No state is silently migrated.

## Pairing and permissions

Pairing is initiated by a locally authorized relay administrator. Pairing codes
have 144 bits of entropy, expire in 120 seconds, are stored hashed in memory and
are consumed once. The public pairing endpoint is rate limited globally. Each
paired connector receives a separate 256-bit token; only its hash is retained
by the relay. Revoking a token closes its live channel and every session. Relay
restarts invalidate pending pairing codes but preserve paired identities.

The proxy credential is distinct from relay-admin and connector credentials.
OpenMaskit stores its proxy header through its normal encrypted HTTP
configuration path. Relay requests with a browser Origin are rejected. MCP
Host validation uses the SDK's DNS-rebinding protection. The relay and
connector HTTP endpoints are loopback-only in this release. Local HTTPS/WSS is supported with an explicitly provisioned certificate and
trusted CA. Pairing and the host channel verify CA trust, hostname, expiry and
TLS 1.2 minimum; neither falls back to HTTP after a TLS error. The trust file
comes from local pairing configuration, never a relay frame. Existing HTTP
pairings retain their legacy behavior until explicitly upgraded. Remote TLS
deployments still require a separate design and acceptance.

The host stores exact absolute executable paths, argument arrays, environment
and working directories in a private file. A relay peer can select only a
locally approved profile; it cannot supply executable commands, paths,
environment overrides or working directories. Profiles are loaded once per
connection. Child stderr is discarded and MCP payloads are never logged. State
is permission-protected, not independently encrypted; OS keychain storage is
planned. The connector is not a sandbox for approved MCP programs.

## Messages and lifecycle

The hello frame contains protocol version and approved profile IDs/display
names only. Relay open frames name a profile and a fresh random session ID.
Message frames carry validated complete MCP JSON-RPC objects; close/closed
terminate a session. The SDK handles public Streamable HTTP session semantics.
Bidirectional requests, responses, notifications and cancellation cross the
bridge. Neither side fabricates MCP initialization capabilities.

Limits: 1 MiB messages, 32 queued messages per session, four sessions per
computer, 32 profiles per connector, 16 paired computers, 64 active profile
managers per relay process, and 300-second idle HTTP sessions. No persisted
payload queue or replay exists after reconnection. An interrupted call has an
uncertain outcome; callers must not automatically retry side-effecting tools.
Disconnect terminates child processes and wakes outstanding HTTP sessions.
Failures must never bypass OpenMaskit's privacy checks or connect AI clients
directly to raw MCP servers.

## Container fixture boundary

`tests/fixtures/compose.yaml` and its matching `release.json` support synthetic
container acceptance only. The fixture runs the relay alongside OpenMaskit and
Presidio in a disposable Compose project, with isolated synthetic state and
loopback-bound ports. It is not a user installation recipe and does not adopt,
stop or remove other Compose projects. No Docker socket is mounted into any
container. The companion remains responsible for any product-managed stack.

No automatic installation, login item, updater or scheduled task is enabled.
