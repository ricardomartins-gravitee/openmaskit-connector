# Working on OpenMaskit Connector

This repository contains the portable host connector and its private relay. It is
independent of OpenMaskit and its companion macOS manager. OpenMaskit remains the
original application and its existing fork must not be renamed. Read
`README.md` and `docs/architecture.md` before changing protocols, pairing, state,
or deployment behavior.

- Keep commands, credentials, logs, runtime files and backups out of Git. Use
  synthetic fixtures only. Private development state belongs in ignored
  `.runtime/`.
- MCP launch commands, absolute executable paths, arguments, environment and
  working directories are approved locally. Never accept them from relay
  messages or a paired peer.
- Invoke child processes with argument arrays, bounded output and timeouts; never
  use a shell. Discard child stderr and never log MCP payloads or credentials.
- Preserve complete MCP messages and bidirectional requests, responses,
  notifications and cancellation. Never replay a tool call after disconnect.
- The relay exposes standard MCP Streamable HTTP and an authenticated outbound
  WebSocket channel. Keep host endpoints loopback-only in this release.
- Do not add Docker lifecycle management, mount a Docker socket, or modify other
  Compose projects. Container fixtures exist only for synthetic acceptance.
- Keep the connector independently runnable. The macOS companion may consume a
  pinned connector dependency and pass the existing companion state directory;
  do not silently migrate or replace that state.
- No automatic local installation, login item, updater or scheduled task is
  enabled. Releases require verified compatible artifacts.
- Use synthetic acceptance tests. Never invoke a user's real mailbox tools.
