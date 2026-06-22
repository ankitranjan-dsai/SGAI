"""Central configuration for SGAI.

Values are read from the environment (see ``.env.example``). Keeping them in one
place makes the agents and the MCP server easy to configure and test.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

# Model the ADK agents run on. Gemini Flash is fast and cheap, which suits the
# fan-out pattern where several agents run in parallel.
MODEL: str = os.getenv("SGAI_MODEL", "gemini-2.0-flash")

# Least-privilege GitHub token. Only used if PR creation is enabled; scope it to
# a single repo with pull-request write access and nothing else.
GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN") or None

# OSV.dev public vulnerability database endpoints (no auth required).
OSV_QUERY_URL: str = "https://api.osv.dev/v1/query"
OSV_QUERY_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"

# Network timeout (seconds) for outbound calls to OSV.dev.
HTTP_TIMEOUT: float = 20.0
