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
MODEL: str = os.getenv("SGAI_MODEL", "gemini-2.5-flash")

# Least-privilege GitHub token. Only used if PR creation is enabled; scope it to
# a single repo with pull-request write access and nothing else.
GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN") or None

# OSV.dev public vulnerability database endpoints (no auth required).
OSV_QUERY_URL: str = "https://api.osv.dev/v1/query"
OSV_QUERY_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL: str = "https://api.osv.dev/v1/vulns"

# Network timeout (seconds) for outbound calls to OSV.dev.
HTTP_TIMEOUT: float = 20.0

# Directories that never contain first-party code: virtualenvs, dependency
# trees and build output. Every scanner must skip these — a vulnerability in a
# vendored dependency belongs to the dependency scan (which reads manifests and
# reports the *package*), not to static analysis of the user's source. Without
# this, `sgai scan` on a repo with a local virtualenv drowns real findings in
# thousands of third-party hits.
SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".venv", "venv", ".uv", "__pycache__",
    "node_modules", "dist", "build", "target",
})

# Glob patterns for the same set, for tools like Bandit that take path globs
# rather than being handed an explicit file list.
SKIP_DIR_GLOBS: tuple[str, ...] = tuple(f"*/{d}/*" for d in sorted(SKIP_DIRS))

# SGAI's own Markdown report quotes the findings it discovers, secrets and all.
# It defaults to being written *into the directory being scanned*, so leaving it
# readable makes each run ingest the previous run's output — findings breed and
# `sgai check` fails on its own report. Skip it by name.
GENERATED_REPORT_NAMES: frozenset[str] = frozenset({"sgai_report.md"})
