"""Connects the agents to the SGAI security MCP server.

Each specialist agent receives a *filtered* view of the security toolbox — it
sees only the tools it needs and nothing else. That least-privilege tool access
is part of SGAI's security posture: the dependency agent cannot read source
files, the scanner cannot run shell-backed analysis, and so on.

The server is launched over stdio using the current interpreter, so it runs in
the same virtual environment as the agents.
"""

from __future__ import annotations

import sys

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from mcp import StdioServerParameters

# Tool names exposed by sgai.mcp_server.server, grouped by the agent that needs
# them. Used as MCPToolset filters to enforce least-privilege tool access.
SCANNER_TOOLS = ["list_source_files", "read_source_file"]
DEPENDENCY_TOOLS = ["scan_dependency", "scan_requirements_file"]
STATIC_ANALYSIS_TOOLS = ["run_static_analysis", "list_source_files"]


def build_security_toolset(tool_filter: list[str] | None = None) -> MCPToolset:
    """Build an MCPToolset bound to the SGAI security server.

    Args:
        tool_filter: Optional allow-list of tool names. When given, the agent
            only sees those tools — enforcing least privilege.

    Returns:
        A configured ``MCPToolset`` that launches the security server on demand.
    """
    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=sys.executable,
                args=["-m", "sgai.mcp_server.server"],
            )
        ),
        tool_filter=tool_filter,
    )
