# OpenMaskit Connector

OpenMaskit Connector is a portable host-side connector for locally approved MCP
servers, paired with a private relay that exposes those servers to OpenMaskit
through its existing Streamable HTTP support. It is a separate project and is
not an OpenMaskit distribution or an upstream-endorsed product.

**Development alpha.** Protocol version 1 and the relay are under active
validation. Releases are not a substitute for review of the local MCP programs
you approve. The connector does not sandbox those programs.

The connector opens an authenticated outbound WebSocket to the relay. It does
not expose an inbound service on the host. AI clients connect to OpenMaskit;
they do not connect directly to this relay. OpenMaskit applies its configured
privacy checks to the forwarded MCP traffic.

## Use with the macOS companion

The OpenMaskit Companion project owns the native macOS manager and its managed
OpenMaskit/Presidio installation. It consumes a pinned connector release and
passes the existing `~/.openmaskit-companion/` directory explicitly, preserving
the user's pairing and approved profiles. The standalone connector defaults to
`~/.openmaskit-connector/`; it does not manage Docker, OpenMaskit or Presidio.

## Run from source

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```sh
uv sync --frozen
uv run --frozen openmaskit-connector --help
```

Use `--home /absolute/path` before a command to select a private state
directory. State directories are mode 0700 and credential files mode 0600 on
POSIX. Protect the selected directory with appropriate account permissions on
other platforms.

Pairing requires a short-lived code created by the relay's local administrator.
The code is single-use and expires after two minutes. The `pair` command prompts
for it. A paired connector receives a per-device credential; the relay retains
only its hash.

## Approve a local MCP

Create a private JSON profile and review it locally. It contains an absolute
`command` path, an `args` array, and optional `env` and `cwd` values. Then approve
it explicitly and run the connector:

```sh
uv run openmaskit-connector approve my-mcp --name 'My local MCP' --profile /absolute/path/profile.json
uv run openmaskit-connector connect
```

The program runs with your user permissions. The connector does not install the
MCP server or its dependencies. Profile changes apply on the next connector
connection; stop the connector first for immediate local removal. Revoking a
paired identity closes its active channel and sessions.

The companion's manager registers an approved profile in OpenMaskit using the
relay's standard HTTP endpoint and the existing OpenMaskit HTTP MCP support. The
standalone connector does not install or configure OpenMaskit, Presidio or any
other application.

## Security and acceptance

See [architecture and trust boundaries](docs/architecture.md),
[development and acceptance](docs/development.md),
[security checks](docs/security-checks.md), and the
[Intel macOS dependency build](docs/intel-wheel.md).

### Verified local TLS

A relay can serve HTTPS and secure WebSockets using an administrator-provisioned
certificate and private key:

```sh
openmaskit-connector relay --state /absolute/path/relay.json --tls-cert /absolute/path/server.pem --tls-key /absolute/path/server.key
openmaskit-connector pair --endpoint https://127.0.0.1:9495 --ca-file /absolute/path/relay-ca.pem
```

The CA certificate is selected locally, saved with the private pairing state,
and reused for the secure WebSocket connection. Certificate trust, hostname and
expiry are verified; TLS 1.2 or newer is required. There is no insecure fallback
or option to disable verification. The server requires both TLS files.
The Companion manages certificate provisioning for its own Docker installation;
standalone administrators supply their own certificate and trust file. Existing
HTTP loopback pairings remain supported for compatibility and require an explicit
transport upgrade to gain encryption. HTTPS still accepts loopback endpoints
only; this does not enable remote deployments.

Host launch settings never come from the relay. MCP messages are not logged or
persisted for replay. A disconnect can leave a side-effecting call's outcome
uncertain; callers must not automatically retry such calls. The relay uses
loopback-only published ports in this release. Remote TLS deployments require a
separate design and acceptance.

GitHub validation covers Linux, Windows and Apple Silicon/Intel macOS connector
builds. Container acceptance uses synthetic data and a disposable Compose
project. It does not use a user's mailbox or manage their installed services.
There is no automatic local installation, login startup or automatic updater.
