# Development and acceptance

Install the locked development dependencies and run the portable checks:

```sh
uv sync --frozen --group dev
uv run --frozen --no-sync --no-build pytest
uv run --frozen --no-sync --no-build ruff check src scripts tests
uv run --frozen --no-sync --no-build ruff format --check src scripts tests
uv run --frozen --no-sync --no-build bandit --recursive src
uv run --frozen --no-sync --no-build pytest --cov=openmaskit_connector --cov-branch --cov-report=xml
```

The test suite uses isolated temporary state, synthetic MCP servers and
ephemeral loopback ports. It covers pairing replay, expiry and revocation;
browser-Origin rejection; secret redaction; strict local launch approval;
complete MCP round trips; bidirectional requests and notifications; disconnect
cleanup; message limits; and refusal to execute commands or settings supplied
by a relay peer.

The validation workflow builds and tests the connector on Linux, Windows, Apple
Silicon macOS and Intel macOS. It also builds the Linux relay image for amd64
and arm64, scans the images, and runs synthetic container acceptance. Swift app
lint and native macOS UI tests belong to the separate companion repository.

## Container acceptance

The fixture at `tests/fixtures/compose.yaml` runs a disposable, isolated stack
using its matching fixture `release.json`. Acceptance verifies that an approved
synthetic MCP can be reached through the relay and OpenMaskit, and that
OpenMaskit and Presidio perform masking and alias reversal. It must use only
synthetic data, verify credentials are not exposed, and remove only the
disposable project it created. It must not inspect or modify a user's existing
Docker projects or mailbox data. Source tests alone do not establish that a
release image is safe to deploy.

The companion manager owns product installation, setup and service lifecycle.
This repository's acceptance fixture is not an installation command and does
not provide product lifecycle management.

## Native dependency builds

Intel macOS currently needs a verified cryptography wheel with statically linked
OpenSSL. Follow the [Intel dependency build](intel-wheel.md). CI restores a
matching verified wheel or builds it from pinned sources on a miss. Consumers
verify provenance and hashes, then install the wheel without source builds.
No installation path compiles dependencies on the user's computer.
