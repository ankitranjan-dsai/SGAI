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

## Run SGAI in CI (GitHub Actions)

The workflow in [`.github/workflows/sgai-security.yml`](../.github/workflows/sgai-security.yml)
audits every pull request and uploads SARIF to the repository's Security tab, so
SGAI becomes part of your DevSecOps pipeline.
