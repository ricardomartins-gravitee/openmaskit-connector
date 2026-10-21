# Security checks

Security and quality gates are defined in this repository's GitHub Actions
workflows. They scan the repository and its full Git history, audit locked
runtime and development dependencies, lint and analyze Python, and enforce
branch coverage. Container images are scanned before synthetic acceptance and
publication. HIGH and CRITICAL findings block release; scanner or report
failures fail closed.

The full-history Gitleaks scan uses upstream default rules, full redaction and
no baseline. Trivy scans tracked repository content for vulnerabilities,
misconfigurations and secrets. Reports that can contain source excerpts remain
in ephemeral runner storage; logs expose only validated finding summaries.
Generated private runtime directories are excluded.

The quality workflow runs Ruff linting and formatting, Bandit against
production Python, and pytest coverage including branches with an enforced 80%
overall floor. `pip-audit` checks the exact locked runtime and development
dependencies with hashes. Intel macOS builds use the
[verified native dependency workflow](intel-wheel.md). Native wheel and
container scans run before downstream tests and publication.

GitHub Actions are pinned to reviewed immutable revisions. Workflow linting
checks workflow syntax and shell scripts. CI jobs receive only the permissions
needed for their work; pull requests cannot publish images or native dependency
releases. Images are published only after platform tests, security and quality
gates, and synthetic container acceptance pass.

These controls do not make an approved MCP safe or sandbox it. Review every
local profile and executable path before approval. Never put credentials,
private runtime state, real MCP payloads or real mailbox data in fixtures or
logs. Container acceptance uses synthetic data and a disposable project; it
must not touch a user's existing services.

## Local checks

Run Trivy against a clean checkout and keep its potentially sensitive report
private:

```sh
trivy repo --scanners vuln,misconfig,secret \
  --severity HIGH,CRITICAL --exit-code 1 \
  --format json --output /tmp/trivy-report.json .
```

Run Gitleaks across all available history. A shallow clone cannot provide the
same history coverage:

```sh
gitleaks git --redact=100 --report-format=json \
  --report-path /tmp/gitleaks-report.json --no-banner .
```

Rotate and remove any confirmed credential; do not treat an ignore entry as
remediation. Scanners do not replace local credential generation or access
controls.
