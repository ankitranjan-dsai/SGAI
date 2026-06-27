"""Deterministic scan runner for SGAI.

Orchestrates a full audit without requiring an LLM: discover dependency
manifests and source, call the security tools, then score and report. This is
what `sgai scan` runs, and it doubles as a reliable fallback for the
agent-driven pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from sgai.manifests import MANIFEST_GLOBS
from sgai.mcp_server import server
from sgai.models import Finding
from sgai.report import build_markdown_report
from sgai.risk import assess

if TYPE_CHECKING:
    from sgai.memory import ScanDiff, ScanMemory

# Keep CLI output clean — silence per-request HTTP info logs.
logging.getLogger("httpx").setLevel(logging.WARNING)

# Directories that never contain auditable project source.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}


def target_key(label: str | None, repo: str) -> str:
    """A stable identity for a scanned target, used as the memory key.

    Remote scans clone into a fresh temp dir each run, so we must key on the
    *label* (the GitHub URL the user gave), never the throwaway path. Local
    scans key on the resolved absolute path so the same project is tracked
    wherever it is invoked from.
    """
    if label and ("://" in label or label.count("/") == 1 and " " not in label):
        return label.rstrip("/")
    return str(Path(label or repo).resolve())


async def gather_findings(repo: str, deep: bool = False) -> list[Finding]:
    """Run the security tools over ``repo`` and return ranked findings.

    This is the pure detection step — no reporting, no memory — shared by the
    deterministic and agent paths.
    """
    root = Path(repo).resolve()

    # 1. Audit every supported dependency manifest (PyPI, npm, Go, crates.io).
    dep_result: dict = {"vulnerable": []}
    for glob in MANIFEST_GLOBS:
        for manifest in sorted(root.rglob(glob)):
            if _SKIP_DIRS & set(manifest.parts):
                continue
            res = await server.scan_manifest(str(manifest), str(root))
            dep_result["vulnerable"].extend(res.get("vulnerable", []))

    # 2. Run static analysis: Bandit (Python) always; Semgrep (multi-language) when deep.
    static_result = server.run_static_analysis(".", str(root))
    semgrep_result = server.run_semgrep(".", str(root)) if deep else None

    # 3. Score, de-duplicate, and rank.
    return assess(dep_result, static_result, semgrep_result)


async def run_scan(
    repo: str,
    label: str | None = None,
    deep: bool = False,
    memory: "ScanMemory | None" = None,
) -> tuple[list[Finding], str, "ScanDiff | None"]:
    """Run a full deterministic audit of ``repo``.

    Args:
        repo: Path to the repository or directory to audit.
        label: Display name for the report header (e.g. a GitHub URL); defaults
            to ``repo``.
        deep: Also run Semgrep multi-language static analysis (slower).
        memory: When provided, diff against the previous recorded scan, add a
            "Changes since last scan" section to the report, and record a new
            snapshot.

    Returns:
        A tuple of (ranked findings, Markdown report, diff-or-None).
    """
    findings = await gather_findings(repo, deep=deep)

    diff = None
    if memory is not None:
        key = target_key(label, repo)
        diff = memory.diff(key, findings)

    report = build_markdown_report(label or repo, findings, diff=diff)

    if memory is not None:
        memory.record(target_key(label, repo), findings)

    return findings, report, diff
