---
name: sgai-security-review
description: >
  Audit a repository or code snippet for known-vulnerable dependencies (via
  OSV.dev) and unsafe code patterns (Bandit, Semgrep) across Python, JavaScript,
  Go, and Rust. Produces a prioritized security report, SARIF, or a remediation
  pull request. Use when asked to review code security, check dependencies for
  CVEs, harden a repo, or explain/fix vulnerabilities.
---

# SGAI — Security Review Skill

SGAI is a multi-agent security reviewer, usable as a CLI (an "Agents CLI"), an
MCP server (security tools for any agent), or an HTTP service.

## When to use

- "Is this repo / dependency vulnerable?"
- "Audit this codebase and tell me what to fix first."
- "Open a PR that patches the vulnerable dependencies."
- "Give me a SARIF report for GitHub code scanning."

## How to invoke (CLI)

```bash
# Audit a local path or any public GitHub repo (no API key needed):
sgai scan <path|github-url>

# Add multi-language code analysis, a narrated report, or SARIF:
sgai scan <target> --deep
sgai scan <target> --explain
sgai scan <target> --sarif out.sarif

# Propose dependency upgrades (dry run) or open a remediation PR:
sgai fix <target>
sgai fix . --open-pr

# Memory — track a target across scans:
sgai scan <target>              # records a baseline / diffs against the last scan
sgai history <target>           # show the scan timeline (new/fixed over time)
sgai accept <target> <id>       # mark a finding as an accepted risk
sgai scan <target> --no-memory  # one-off scan, don't record
```

## Memory

SGAI remembers every scan of a target and, on each subsequent scan, reports what
is **new**, **fixed**, or **still open** since last time — and suppresses
findings marked as accepted risks. Use this when asked "what changed?", "is this
getting better or worse?", or "ignore this known issue". History is stored under
`~/.sgai/` (override with `$SGAI_HOME`).

## How to invoke (MCP tools)

Run `python -m sgai.mcp_server.server` and an agent gains these tools:

| Tool | Purpose |
|---|---|
| `scan_manifest` | Audit a dependency manifest (PyPI/npm/Go/crates.io) against OSV.dev |
| `scan_dependency` | Check a single package for CVEs |
| `run_static_analysis` | Bandit static analysis (Python) |
| `run_semgrep` | Multi-language static analysis |
| `list_source_files` / `read_source_file` | Sandboxed source access |

See [docs/integrations.md](docs/integrations.md) to wire the MCP server into
Antigravity, Claude Code, the Gemini CLI, or any MCP-compatible agent.

## Output

A severity-ranked report (Markdown), structured findings (JSON over HTTP), SARIF
2.1.0, or a remediation pull request.
