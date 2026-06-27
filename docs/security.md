# Security Design

SGAI is a security tool, so it is built to be safe to point at untrusted code.
This document explains the design choices a judge or user should know about.

## Sandboxed file access

Every filesystem tool in the MCP server (`list_source_files`, `read_source_file`)
routes through `sandbox.safe_resolve` (`src/sgai/mcp_server/sandbox.py`), which:

- fully resolves the requested path (so `../../etc/passwd` and symlinks cannot
  escape), and
- rejects anything that resolves outside the allow-listed scan root.

The scan root is the only directory a tool can ever read. This is unit-tested in
`tests/test_sandbox.py`.

## Least-privilege agents

Each specialist agent is bound to the MCP server with a per-agent `tool_filter`
(`src/sgai/agents/security_tools.py`), so an agent only receives the specific
tools it needs — the dependency auditor cannot run static analysis, the static
analyzer cannot make network calls, and so on.

## Stateless request handling

The HTTP service (`src/sgai/api.py`) keeps **no state between requests**:

- Submitted `requirements.txt` content and pasted code are written to a
  throwaway `tempfile.TemporaryDirectory`, audited through the sandboxed tools,
  and deleted when the request ends.
- A `github_url` is shallow-cloned into a temp dir and removed after the scan.
- Nothing the user submits is logged or persisted.

(Scan *memory* — the new/fixed/still-open history — is keyed only by repository
identity for local CLI use and lives under `~/.sgai/`; the stateless web request
path stores findings metadata for URL targets only, never pasted code.)

## Secrets

- **No API keys, tokens, or passwords are committed.** `.env` is git-ignored;
  only `.env.example` (with placeholders) is tracked.
- All secrets are read from environment variables (`GOOGLE_API_KEY`,
  `GITHUB_TOKEN`).
- The strings that look like secrets in `examples/` (`supersecret123`,
  `ghp_demo_...`) are **intentional vulnerable fixtures** for the analyzers to
  flag — they are not real.

## The Gemini key is optional

- The **deterministic scan works with no API key at all** — CVE lookups (OSV.dev)
  and Bandit/Semgrep need no Gemini.
- The Gemini key only powers the optional `--explain` agent-narrated report, and
  the service degrades gracefully to the deterministic report if the key is
  missing or rate-limited.

## GitHub PR creation is opt-in and local-only

- `sgai fix` is a **dry run by default**; it only prints proposed upgrades.
- Opening a real PR (`--open-pr`) requires a local repository you own and a
  scoped `GITHUB_TOKEN` (single-repo `pull_request` write is enough). It is never
  triggered automatically and is disabled for remote-URL targets.

## Input validation

OSV/Bandit/Semgrep output is normalized and de-duplicated before scoring
(`src/sgai/risk.py`), and manifest parsing tolerates malformed input by skipping
unparseable entries rather than failing the scan.
