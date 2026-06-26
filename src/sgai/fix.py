"""Automated remediation: resolve patched versions and rewrite manifests.

For each vulnerable PyPI dependency, SGAI asks OSV.dev which versions fixed the
advisories and upgrades the pin to a version that is safe against *all* of them.
The resulting changes can be previewed (dry run) or opened as a pull request.

Lockfile ecosystems (npm/Go/Rust) are reported but not auto-rewritten yet —
requirements.txt pins are the clean, unambiguous case.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
from packaging.version import InvalidVersion, Version

from sgai.config import HTTP_TIMEOUT, OSV_QUERY_URL
from sgai.manifests import parse_manifest

# Directories that never hold first-party manifests.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}


@dataclass
class Fix:
    """One proposed dependency upgrade."""

    file: str  # manifest path relative to the repo root
    package: str
    ecosystem: str
    old_version: str
    new_version: str


async def resolve_patched_version(name: str, version: str, ecosystem: str = "PyPI") -> str | None:
    """Return the lowest safe upgrade for a vulnerable package, or ``None``.

    Collects every ``fixed`` version OSV advertises for this package (ignoring
    git-commit ranges, which aren't semantic versions) and returns the highest
    one — a version at or above it is patched against all the advisories.
    """
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(
            OSV_QUERY_URL, json={"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        )
        resp.raise_for_status()
        data = resp.json()

    candidates: list[tuple[Version, str]] = []
    for vuln in data.get("vulns", []):
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue  # skip GIT commit-hash ranges
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if not fixed:
                        continue
                    try:
                        candidates.append((Version(fixed), fixed))
                    except InvalidVersion:
                        continue

    if not candidates:
        return None
    return max(candidates, key=lambda c: c[0])[1]


async def plan_fixes(repo_dir: str) -> list[Fix]:
    """Compute the upgrade plan for vulnerable PyPI pins under ``repo_dir``."""
    root = Path(repo_dir).resolve()
    fixes: list[Fix] = []
    for manifest in sorted(root.rglob("requirements*.txt")):
        if _SKIP_DIRS & set(manifest.parts):
            continue
        for pkg in parse_manifest(manifest):
            if pkg["ecosystem"] != "PyPI":
                continue
            patched = await resolve_patched_version(pkg["name"], pkg["version"], "PyPI")
            if patched and patched != pkg["version"]:
                fixes.append(
                    Fix(
                        file=str(manifest.relative_to(root)),
                        package=pkg["name"],
                        ecosystem="PyPI",
                        old_version=pkg["version"],
                        new_version=patched,
                    )
                )
    return fixes


def apply_fixes(repo_dir: str, fixes: list[Fix]) -> None:
    """Rewrite the manifests in place to apply ``fixes``."""
    root = Path(repo_dir)
    by_file: dict[str, list[Fix]] = {}
    for fx in fixes:
        by_file.setdefault(fx.file, []).append(fx)

    for file, file_fixes in by_file.items():
        path = root / file
        text = path.read_text()
        for fx in file_fixes:
            text = text.replace(
                f"{fx.package}=={fx.old_version}", f"{fx.package}=={fx.new_version}"
            )
        path.write_text(text)


def build_pr_body(fixes: list[Fix]) -> str:
    """Render the pull-request body summarizing the upgrades."""
    lines = [
        "## SGAI automated dependency security fixes",
        "",
        "Upgrades known-vulnerable dependencies to patched versions:",
        "",
        "| Package | From | To |",
        "|---|---|---|",
    ]
    for fx in fixes:
        lines.append(f"| `{fx.package}` | {fx.old_version} | {fx.new_version} |")
    lines += ["", "_Patched versions resolved from OSV.dev advisories by SGAI._"]
    return "\n".join(lines)
