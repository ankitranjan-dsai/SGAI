"""Git-diff extraction and delta analysis for pull-request scanning.

PR scanning answers a narrower question than a full audit: *of the code this
change touches, what new security problems did it introduce?* SGAI computes the
set of added/modified lines from ``git diff`` and keeps only the findings that
land on them, so a PR is gated on its own delta rather than the repository's
pre-existing debt.

Everything here is deterministic (no LLM): ``git`` for the diff, the same
sandboxed detection tools for the findings.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 — SGAI drives git; see sgai.proc for the argv contract.
from pathlib import Path

from sgai.models import Finding
from sgai.proc import resolve_exe

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_DIFF_GIT = re.compile(r"^diff --git a/.+ b/(.+)$")


class GitDiffError(Exception):
    """Raised when a git diff cannot be produced."""


def _git(repo_dir: str, args: list[str], timeout: float = 60.0) -> str:
    try:
        proc = subprocess.run(  # nosec B603 — fixed argv list, no shell, resolved exe.
            [resolve_exe("git"), "-C", repo_dir, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise GitDiffError("git is not installed on this system") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitDiffError(f"git timed out after {timeout:.0f}s") from exc
    if proc.returncode != 0:
        raise GitDiffError(f"git {args[0]} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _diff_range(base: str, head: str | None, merge_base: bool) -> list[str]:
    """Build the git-diff revision arguments."""
    if head is None:
        return [base]  # base vs the working tree
    return [f"{base}...{head}" if merge_base else f"{base}..{head}"]


def changed_line_map(
    repo_dir: str, base: str = "HEAD", head: str | None = None, merge_base: bool = True
) -> dict[str, set[int]]:
    """Map each changed file to the set of *added/modified* line numbers (head side).

    Parses ``git diff -U0`` hunk headers; only added lines (``+``) are recorded,
    since a finding can only be *introduced* on a line the change adds. Removed
    lines cannot carry a new finding.
    """
    out = _git(repo_dir, ["diff", "--unified=0", "--no-color", *_diff_range(base, head, merge_base)])
    line_map: dict[str, set[int]] = {}
    current: str | None = None
    new_lineno = 0
    for raw in out.splitlines():
        gitm = _DIFF_GIT.match(raw)
        if gitm:
            current = gitm.group(1)
            line_map.setdefault(current, set())
            continue
        hunk = _HUNK.match(raw)
        if hunk:
            new_lineno = int(hunk.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            line_map[current].add(new_lineno)
            new_lineno += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue  # deletion: does not advance the new-file line counter
        elif not raw.startswith("\\"):
            new_lineno += 1  # unchanged context line (rare with -U0)
    return {f: lines for f, lines in line_map.items() if lines}


def changed_files(
    repo_dir: str, base: str = "HEAD", head: str | None = None, merge_base: bool = True
) -> list[str]:
    """Repo-relative paths changed between ``base`` and ``head`` (or working tree)."""
    out = _git(repo_dir, ["diff", "--name-only", *_diff_range(base, head, merge_base)])
    return [line.strip() for line in out.splitlines() if line.strip()]


def _location_file_line(location: str) -> tuple[str, int] | None:
    """Split a ``file:line`` finding location; None for non-file locations."""
    if ":" not in location:
        return None
    file, _, line = location.rpartition(":")
    if not file or not line.isdigit():
        return None
    return file, int(line)


def filter_to_delta(findings: list[Finding], line_map: dict[str, set[int]]) -> list[Finding]:
    """Keep only findings introduced on the changed lines of the diff.

    * Code/secret/container findings (``file:line``) survive when the file is in
      the diff and the line is one the change added.
    * Dependency findings (no file/line) survive when their manifest ecosystem's
      lockfile is among the changed files — a bumped or added pin.
    """
    changed = set(line_map)
    manifest_changed = _manifest_ecosystems(changed)
    delta: list[Finding] = []
    for f in findings:
        fl = _location_file_line(f.location)
        if fl is not None:
            file, line = fl
            if file in line_map and line in line_map[file]:
                delta.append(f)
        elif f.source == "dependency":
            ecosystem = f.location.split(":", 1)[0]
            if ecosystem in manifest_changed:
                delta.append(f)
    return delta


# Which OSV ecosystem each changed manifest filename implies.
_MANIFEST_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "package-lock.json": "npm",
    "go.mod": "Go",
    "cargo.lock": "crates.io",
}


def _manifest_ecosystems(files: set[str]) -> set[str]:
    ecosystems: set[str] = set()
    for f in files:
        name = Path(f).name.lower()
        if name in _MANIFEST_ECOSYSTEM:
            ecosystems.add(_MANIFEST_ECOSYSTEM[name])
        elif name.startswith("requirements") and name.endswith(".txt"):
            ecosystems.add("PyPI")
    return ecosystems


async def delta_findings(
    repo_dir: str,
    base: str = "HEAD",
    head: str | None = None,
    deep: bool = False,
    merge_base: bool = True,
) -> tuple[list[Finding], dict[str, set[int]]]:
    """Findings newly introduced by the diff between ``base`` and ``head``.

    Runs the full deterministic audit over the head tree, then filters to the
    changed lines. Returns ``(delta_findings, changed_line_map)``.
    """
    from sgai.runner import gather_findings

    line_map = changed_line_map(repo_dir, base, head, merge_base)
    all_findings = await gather_findings(repo_dir, deep=deep)
    return filter_to_delta(all_findings, line_map), line_map


def review_comments(findings: list[Finding]) -> list[dict]:
    """Render delta findings as GitHub PR review comments (``path``/``line``/``body``)."""
    comments: list[dict] = []
    for f in findings:
        fl = _location_file_line(f.location)
        if fl is None:
            continue  # dependency findings are summarized in the review body instead
        file, line = fl
        comments.append({
            "path": file,
            "line": line,
            "body": (
                f"**SGAI · {f.severity.label} · {f.id}**\n\n"
                f"{f.title}\n\n"
                f"**Fix:** {f.remediation}"
            ),
        })
    return comments
