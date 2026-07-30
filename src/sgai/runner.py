"""Deterministic scan runner for SGAI.

Orchestrates a full audit without requiring an LLM: discover dependency
manifests and source, call the security tools, then score and report. This is
what `sgai scan` runs, and it doubles as a reliable fallback for the
agent-driven pipeline.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from sgai.config import is_skipped, path_excluded
from sgai.manifests import COMPOSE_GLOBS, CONTAINER_GLOBS, IAC_GLOBS, MANIFEST_GLOBS
from sgai.mcp_server import server
from sgai.models import Finding
from sgai.report import build_markdown_report
from sgai.risk import (
    apply_reachability,
    assess,
    build_import_graph,
    findings_from_container_scan,
    findings_from_secret_scan,
)

if TYPE_CHECKING:
    from sgai.memory import ScanDiff, ScanMemory

# Keep CLI output clean — silence per-request HTTP info logs.
logging.getLogger("httpx").setLevel(logging.WARNING)

log = logging.getLogger(__name__)

_FILE_LINE = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")


def _finding_paths(finding: Finding) -> list[str]:
    """The repo-relative paths a finding is attributable to.

    Static and secret findings carry ``file:line``. A dependency finding names a
    package (``PyPI:flask@0.12.2``) and is attributable to the manifest that
    pins it, which is the path a reader would have to edit.
    """
    paths: list[str] = []
    m = _FILE_LINE.match(finding.location)
    if m:
        paths.append(m.group("file"))
    if finding.manifest:
        paths.append(finding.manifest)
    return paths


def exclude_findings(
    findings: list[Finding], excludes: Sequence[str]
) -> tuple[list[Finding], int]:
    """Drop findings attributable only to an excluded path; return (kept, dropped).

    Exclusion has to be *proved*, and proved of every path the finding names.
    Two cases turn on that, and both resolve the same way — toward reporting:

    * A finding SGAI cannot place in the tree at all is kept. Dropping the
      unattributable would turn a typo in ``--exclude`` into a missed
      vulnerability.
    * A finding naming both an excluded and a non-excluded path is kept, because
      one real location is enough to owe the reader an alert.

    A silent false negative is the worst failure a scanner has, so ambiguity
    never resolves toward silence.
    """
    if not excludes:
        return findings, 0
    kept = [f for f in findings if not _is_excluded(f, excludes)]
    return kept, len(findings) - len(kept)


def _is_excluded(finding: Finding, excludes: Sequence[str]) -> bool:
    paths = _finding_paths(finding)
    return bool(paths) and all(path_excluded(p, excludes) for p in paths)


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


async def gather_findings(
    repo: str, deep: bool = False, exclude: Sequence[str] = ()
) -> list[Finding]:
    """Run the security tools over ``repo`` and return ranked findings.

    This is the pure detection step — no reporting, no memory — shared by the
    deterministic and agent paths.

    ``exclude`` names repo-relative paths whose findings are not part of this
    audit's surface. Detection still runs over them: the scan is unchanged and
    the import graph stays whole, so a production file that imports an excluded
    fixture is still scored against the real dependency set. Only the reported
    findings are narrowed, and only at the end.
    """
    root = Path(repo).resolve()

    # 1. Audit every supported dependency manifest (PyPI, npm, Go, crates.io).
    dep_result: dict = {"vulnerable": []}
    for glob in MANIFEST_GLOBS:
        for manifest in sorted(root.rglob(glob)):
            if is_skipped(manifest, root):
                continue
            res = await server.scan_manifest(str(manifest), str(root))
            # Tag each hit with its manifest so downstream stages know whether
            # the pin belongs to the production dependency set or a fixture.
            rel = manifest.relative_to(root).as_posix()
            for entry in res.get("vulnerable", []):
                entry["manifest"] = rel
            dep_result["vulnerable"].extend(res.get("vulnerable", []))

    # 2. Run static analysis: Bandit (Python) always; Semgrep (multi-language) when deep.
    static_result = server.run_static_analysis(".", str(root))
    semgrep_result = server.run_semgrep(".", str(root)) if deep else None

    # 3. Audit container/IaC manifests and hunt for leaked secrets.
    extra: list[Finding] = []
    for glob in [*CONTAINER_GLOBS, *COMPOSE_GLOBS, *IAC_GLOBS]:
        for cfg in sorted(root.rglob(glob)):
            if is_skipped(cfg, root):
                continue
            res = server.scan_dockerfile(str(cfg), str(root))
            extra += findings_from_container_scan(res, str(cfg.relative_to(root)))
    extra += findings_from_secret_scan(server.scan_secrets(".", str(root)))

    # 3b. Flag dependency names that typosquat popular packages (pre-CVE
    #     supply-chain risk; deterministic string analysis, no network).
    from sgai.typosquat import scan_typosquats

    extra += scan_typosquats(str(root))

    # 4. Score, de-duplicate, and rank everything together.
    findings = assess(dep_result, static_result, semgrep_result, extra=extra)

    # 5. Reachability: upgrade vulnerable packages the code actually imports,
    #    downgrade the ones it provably never touches.
    findings = apply_reachability(findings, build_import_graph(str(root)))

    # 6. Narrow to the audited surface, last, so every earlier stage saw the
    #    whole repository.
    findings, dropped = exclude_findings(findings, exclude)
    if dropped:
        log.info("excluded %d finding(s) under %s", dropped, ", ".join(exclude))
    return findings


async def run_scan(
    repo: str,
    label: str | None = None,
    deep: bool = False,
    memory: "ScanMemory | None" = None,
    exclude: Sequence[str] = (),
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
        exclude: Repo-relative paths outside this audit's surface; see
            :func:`gather_findings`.

    Returns:
        A tuple of (ranked findings, Markdown report, diff-or-None).
    """
    findings = await gather_findings(repo, deep=deep, exclude=exclude)

    diff = None
    if memory is not None:
        from sgai.risk import suppress_dismissed

        key = target_key(label, repo)
        # Suppress findings the team has dismissed as false positives *before*
        # diffing/recording, so a dismissed finding never reappears as "new".
        findings = suppress_dismissed(findings, memory.dismissals(key))
        diff = memory.diff(key, findings)

    report = build_markdown_report(label or repo, findings, diff=diff, repo_dir=repo)

    if memory is not None:
        memory.record(target_key(label, repo), findings)

    return findings, report, diff
