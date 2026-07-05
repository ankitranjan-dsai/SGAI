# Integrations

SGAI is designed to plug into other agents and tools. Its security toolbox is an
MCP server, so any MCP-compatible agentic IDE — **Antigravity**, Claude Code, the
Gemini CLI — can call it.

## Install as a CLI tool (an "Agents CLI")

```bash
# from the repo root, install the `sgai` command globally:
uv tool install .
# or with pipx:
pipx install .

sgai scan https://github.com/owner/repo
```

## Use SGAI's MCP server from an agentic IDE

SGAI exposes its security tools over MCP. Point your agent at the server with a
standard MCP config:

```json
{
  "mcpServers": {
    "sgai-security": {
      "command": "uv",
      "args": ["run", "python", "-m", "sgai.mcp_server.server"],
      "cwd": "/absolute/path/to/sgai"
    }
  }
}
```

- **Antigravity:** add the block above to your MCP servers configuration. The
  Antigravity agent can then call `scan_manifest`, `run_semgrep`, etc. as tools
  while it works on your code.
- **Claude Code:** save the block as `.mcp.json` in your project, or run
  `claude mcp add sgai-security -- uv run python -m sgai.mcp_server.server`.
- **Gemini CLI / other MCP clients:** use the same command/args.

Once connected, the agent has SGAI's CVE lookups and static-analysis tools
available natively — no extra glue code.

### VS Code

VS Code (1.102+) supports MCP servers natively. Add `.vscode/mcp.json` to your
project and Copilot Chat's agent mode gains SGAI's tools:

```json
{
  "servers": {
    "sgai-security": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "python", "-m", "sgai.mcp_server.server"],
      "cwd": "/absolute/path/to/sgai"
    }
  }
}
```

For a one-keystroke audit without MCP, wire the CLI into `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "SGAI: scan workspace",
      "type": "shell",
      "command": "sgai scan ${workspaceFolder}",
      "problemMatcher": []
    },
    {
      "label": "SGAI: policy gate",
      "type": "shell",
      "command": "sgai check ${workspaceFolder}",
      "group": "test"
    }
  ]
}
```

### Run the MCP server as a shared network service

By default the server speaks stdio (each client spawns its own subprocess).
For one shared instance that multiple IDE clients or remote agents can query,
serve it over the network:

```bash
uv run python -m sgai.mcp_server.server --transport streamable-http --host 0.0.0.0 --port 8765
# legacy SSE clients:
uv run python -m sgai.mcp_server.server --transport sse --port 8765
```

Then point clients at `http://<host>:8765/mcp` (streamable HTTP) instead of a
command. The sandbox rules are unchanged — every tool call still resolves paths
inside the `root` it is given.

## Pre-commit hook

The repo ships a [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) that
runs the policy gate before every commit:

```bash
uv tool install pre-commit   # or: pipx install pre-commit
pre-commit install
```

Any `.sgai/policy.yml` violation now blocks the commit locally — the same check
CI enforces on the pull request.

## Continuous integration (GitHub Actions)

Three workflows ship with the repo:

- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every push and
  pull request: it installs dependencies with `uv` on Python 3.11, runs the test
  suite (`uv run pytest -q`), lints with `ruff`, and dogfoods `sgai check .` on
  the repo itself.
- [`.github/workflows/sgai-security.yml`](../.github/workflows/sgai-security.yml)
  audits every pull request with SGAI itself, uploads SARIF to the repository's
  Security tab, and then runs `sgai check .` as the merge gate — a policy
  violation blocks the PR.
- [`.github/workflows/sgai-dependency-audit.yml`](../.github/workflows/sgai-dependency-audit.yml)
  re-audits every pinned dependency weekly and opens an upgrade PR
  (`sgai fix --open-pr`) when a new CVE lands.
