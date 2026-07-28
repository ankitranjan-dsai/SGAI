"""Central configuration for SGAI.

Values are read from the environment (see ``.env.example``). Keeping them in one
place makes the agents and the MCP server easy to configure and test.
"""

from __future__ import annotations

import os
from pathlib import Path

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

def skip_dir_globs(root: Path) -> tuple[str, ...]:
    """Exclusion globs for the same set, anchored at ``root``.

    For tools like Bandit that take path globs rather than an explicit file
    list. Bandit matches these with :func:`fnmatch.fnmatch`, whose ``*`` spans
    ``/`` — so an unanchored ``*/build/*`` also matches an *ancestor* of the
    scan root and excludes the entire repository. Anchoring every pattern at the
    root keeps the exclusion to real output directories; see :func:`is_skipped`,
    which enforces the same rule for the walkers.

    Two patterns per name: one for the directory at the root, one for it nested
    at any depth (``*`` spanning ``/`` covers the levels between).
    """
    return tuple(
        pattern
        for d in sorted(SKIP_DIRS)
        for pattern in (f"{root}/{d}/*", f"{root}/*/{d}/*")
    )


def is_skipped(path: Path, root: Path) -> bool:
    """Whether ``path`` sits inside a skipped directory *below* ``root``.

    Only names beneath the scan root may exclude anything. Testing an absolute
    path's ``parts`` instead lets a directory *above* the root veto the entire
    scan: a checkout at ``~/build/myrepo`` matches ``build`` for every candidate,
    so every walker yields nothing and SGAI reports a clean repository. For a
    security scanner a silent false negative is the worst possible failure, so
    the comparison is always made relative to the root.

    Paths outside ``root`` are not skipped — that is not this function's call to
    make, and callers only ever pass paths they found by walking ``root``.
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return bool(SKIP_DIRS & set(rel.parts))

# SGAI's own Markdown report quotes the findings it discovers, secrets and all.
# It defaults to being written *into the directory being scanned*, so leaving it
# readable makes each run ingest the previous run's output — findings breed and
# `sgai check` fails on its own report. Skip it by name.
GENERATED_REPORT_NAMES: frozenset[str] = frozenset({"sgai_report.md"})
