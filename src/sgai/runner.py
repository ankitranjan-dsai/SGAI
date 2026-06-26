"""Deterministic scan runner for SGAI.

Orchestrates a full audit without requiring an LLM: discover dependency
manifests and source, call the security tools, then score and report. This is
what `sgai scan` runs, and it doubles as a reliable fallback for the
agent-driven pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sgai.mcp_server import server
from sgai.models import Finding
from sgai.report import build_markdown_report
from sgai.risk import assess

# Keep CLI output clean — silence per-request HTTP info logs.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Directories that never contain auditable project source.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}


async def run_scan(repo: str, label: str | None = None) -> tuple[list[Finding], str]:
    """Run a full deterministic audit of ``repo``.

    Args:
        repo: Path to the repository or directory to audit.
        label: Display name for the report header (e.g. a GitHub URL); defaults
            to ``repo``.

    Returns:
        A tuple of (ranked findings, Markdown report).
    """
    root = Path(repo).resolve()

    # 1. Audit every requirements manifest found under the root.
    dep_result: dict = {"vulnerable": [], "clean": [], "skipped": []}
    for manifest in sorted(root.rglob("requirements*.txt")):
        if _SKIP_DIRS & set(manifest.parts):
            continue
        res = await server.scan_requirements_file(str(manifest), str(root))
        if "vulnerable" in res:
            dep_result["vulnerable"].extend(res["vulnerable"])
            dep_result["clean"].extend(res.get("clean", []))

    # 2. Run static analysis across the whole tree.
    static_result = server.run_static_analysis(".", str(root))

    # 3. Score, de-duplicate, rank, and report.
    findings = assess(dep_result, static_result)
    report = build_markdown_report(label or repo, findings)
    return findings, report
