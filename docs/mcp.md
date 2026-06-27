# MCP Server Reference

SGAI's security capabilities are a standalone **MCP server**
(`src/sgai/mcp_server/server.py`, built on FastMCP). The SGAI agents call it as
tools, and so can any MCP-compatible client. For wiring it into Antigravity /
Claude Code / the Gemini CLI, see [integrations.md](integrations.md); this page
documents the tool contracts.

## Run it

```bash
uv run python -m sgai.mcp_server.server      # stdio transport
```

## Tools

Every tool that touches the filesystem takes a `root` that acts as a sandbox
boundary — paths are fully resolved and anything outside `root` is rejected
(see [security.md](security.md)).

| Tool | Signature | Returns |
|---|---|---|
| `scan_dependency` | `(name, version, ecosystem="PyPI")` | OSV.dev advisories for one package |
| `scan_requirements_file` | `(path, root)` | Vulnerable PyPI pins in a `requirements.txt` |
| `scan_manifest` | `(path, root)` | Vulnerable deps in any supported manifest (PyPI/npm/Go/crates.io) |
| `run_static_analysis` | `(path, root)` | Bandit findings (Python) |
| `run_semgrep` | `(path, root)` | Semgrep findings (multi-language; skips gracefully if Semgrep is unavailable) |
| `list_source_files` | `(root)` | Sandboxed list of source files (`.py/.js/.ts/.go/.rs/.java`) |
| `read_source_file` | `(path, root)` | Contents of one file within `root` |

### Output shape

Dependency tools return `{"vulnerable": [{package, version, ecosystem, vuln_ids:[...]}], ...}`.
Static tools return `{"findings": [{test_id/check_id, severity, file, line, issue/message}], "count": N}`.
These are normalized into SGAI `Finding` objects by `src/sgai/risk.py`.

## Least privilege

When the agents connect (`src/sgai/agents/security_tools.py`), each agent gets a
filtered subset of these tools via a per-agent `tool_filter` — e.g. the
dependency auditor sees only the OSV tools, the static analyzer only the
Bandit/Semgrep tools. The MCP boundary is what makes that isolation enforceable.

## Quick programmatic check (no agent, no key)

```python
from sgai.mcp_server import server
print(server.run_static_analysis(".", "examples/kaggle_demo_repo")["count"])
print(server.list_source_files("examples/kaggle_demo_repo")["files"])
```
