"""The SGAI security MCP server.

Exposes the security capabilities the agents rely on as MCP tools:

* ``scan_dependency``        — query a single package against OSV.dev
* ``scan_requirements_file`` — audit every pin in a requirements.txt (batched)
* ``run_static_analysis``    — run Bandit over a path and return findings
* ``list_source_files``      — enumerate source files within a sandboxed root
* ``read_source_file``       — read a single source file within a sandboxed root

Run standalone with::

    uv run python -m sgai.mcp_server.server
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from sgai.config import HTTP_TIMEOUT, OSV_QUERY_BATCH_URL, OSV_QUERY_URL
from sgai.mcp_server.sandbox import SandboxError, safe_resolve

mcp = FastMCP("sgai-security-tools")

# File extensions the `list_source_files` tool surfaces for review. Bandit
# static analysis is Python-only; Semgrep (--deep) covers the rest, so we let
# agents enumerate source across the languages SGAI's dependency + Semgrep
# scanning understands.
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java"}


# --------------------------------------------------------------------------- #
# Dependency / CVE auditing (OSV.dev)
# --------------------------------------------------------------------------- #
@mcp.tool()
async def scan_dependency(name: str, version: str, ecosystem: str = "PyPI") -> dict[str, Any]:
    """Check a single dependency for known vulnerabilities via OSV.dev.

    Args:
        name: Package name, e.g. ``"jinja2"``.
        version: Exact pinned version, e.g. ``"2.11.2"``.
        ecosystem: OSV ecosystem; defaults to ``"PyPI"``.

    Returns:
        A dict with the package, its version, and a list of matched
        vulnerabilities (id, summary, and advisory aliases).
    """
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(OSV_QUERY_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()

    vulns = [
        {
            "id": v.get("id"),
            "summary": v.get("summary", ""),
            "aliases": v.get("aliases", []),
        }
        for v in data.get("vulns", [])
    ]
    return {"package": name, "version": version, "vulnerable": bool(vulns), "vulns": vulns}


@mcp.tool()
async def scan_requirements_file(path: str, root: str) -> dict[str, Any]:
    """Audit every pinned dependency in a requirements.txt file.

    Only simple ``name==version`` pins are checked (the common case). Lines that
    are comments, blank, or non-pinned are skipped and reported separately.

    Args:
        path: Path to the requirements file (absolute or relative to ``root``).
        root: Sandbox root; the file must resolve inside it.

    Returns:
        A dict listing vulnerable packages, clean packages, and skipped lines.
    """
    try:
        req_path = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}

    pins: list[tuple[str, str]] = []
    skipped: list[str] = []
    for raw in req_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "==" not in line:
            if line and not line.startswith("#"):
                skipped.append(line)
            continue
        name, _, version = line.partition("==")
        pins.append((name.strip(), version.strip().split()[0]))

    if not pins:
        return {"vulnerable": [], "clean": [], "skipped": skipped}

    queries = [{"version": v, "package": {"name": n, "ecosystem": "PyPI"}} for n, v in pins]
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(OSV_QUERY_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        results = resp.json().get("results", [])

    vulnerable, clean = [], []
    for (name, version), result in zip(pins, results):
        ids = [v.get("id") for v in result.get("vulns", [])]
        if ids:
            vulnerable.append({"package": name, "version": version, "vuln_ids": ids})
        else:
            clean.append({"package": name, "version": version})

    return {"vulnerable": vulnerable, "clean": clean, "skipped": skipped}


# OSV's querybatch accepts up to 1000 entries; stay well under and keep payloads
# small so a single large lockfile can't trip request-size limits.
_OSV_BATCH_SIZE = 100


async def _osv_query_chunk(client: httpx.AsyncClient, chunk: list[dict]) -> list[dict]:
    """Query a chunk against OSV's batch endpoint, resilient to a bad entry.

    Returns a list of per-package result dicts aligned to ``chunk``. If the batch
    request fails (e.g. one malformed pin yields a 400), it retries each package
    individually so the rest of the chunk still produces findings.
    """
    queries = [
        {"version": p["version"], "package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
        for p in chunk
    ]
    try:
        resp = await client.post(OSV_QUERY_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        return resp.json().get("results", [{}] * len(chunk))
    except httpx.HTTPError:
        results: list[dict] = []
        for q in queries:
            try:
                resp = await client.post(OSV_QUERY_URL, json=q)
                resp.raise_for_status()
                results.append(resp.json())
            except httpx.HTTPError:
                results.append({})  # skip an un-queryable package, don't fail the scan
        return results


@mcp.tool()
async def scan_manifest(path: str, root: str) -> dict[str, Any]:
    """Audit any supported dependency manifest against OSV.dev.

    Detects the ecosystem from the filename (requirements.txt → PyPI,
    package-lock.json → npm, go.mod → Go, Cargo.lock → crates.io), parses the
    pinned packages, and batch-queries OSV. This is the multi-language
    generalization of ``scan_requirements_file``.

    Args:
        path: Path to the manifest (absolute or relative to ``root``).
        root: Sandbox root; the file must resolve inside it.

    Returns:
        A dict with vulnerable packages (name, version, ecosystem, vuln_ids) and
        a count of clean ones.
    """
    from sgai.manifests import parse_manifest

    try:
        manifest_path = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}

    # Keep only pins OSV can resolve: a real name and a concrete version. Lockfiles
    # carry non-semver specifiers (file:, link:, workspace:, git+ssh://, npm aliases)
    # that OSV rejects with a 400 — drop them rather than poison the whole batch.
    packages = [
        p
        for p in parse_manifest(manifest_path)
        if p.get("name") and p.get("version") and ":" not in p["version"]
    ]
    if not packages:
        return {"vulnerable": [], "clean_count": 0, "ecosystem": None}

    vulnerable, clean_count = [], 0
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        # Chunk well under OSV's batch ceiling; a failed chunk falls back to
        # per-package queries so one bad entry can't drop the whole chunk.
        for start in range(0, len(packages), _OSV_BATCH_SIZE):
            chunk = packages[start : start + _OSV_BATCH_SIZE]
            results = await _osv_query_chunk(client, chunk)
            for pkg, result in zip(chunk, results):
                ids = [v.get("id") for v in (result or {}).get("vulns", [])]
                if ids:
                    vulnerable.append(
                        {
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "ecosystem": pkg["ecosystem"],
                            "vuln_ids": ids,
                        }
                    )
                else:
                    clean_count += 1

    return {"vulnerable": vulnerable, "clean_count": clean_count, "ecosystem": packages[0]["ecosystem"]}


# --------------------------------------------------------------------------- #
# Static analysis (Bandit)
# --------------------------------------------------------------------------- #
@mcp.tool()
def run_static_analysis(path: str, root: str) -> dict[str, Any]:
    """Run Bandit static analysis over a sandboxed path and return findings.

    Args:
        path: File or directory to analyze (absolute or relative to ``root``).
        root: Sandbox root; the target must resolve inside it.

    Returns:
        A dict with a list of findings (severity, confidence, test id, location)
        or an ``error`` key if the target is outside the sandbox.
    """
    try:
        target = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}

    proc = subprocess.run(
        ["bandit", "-r", "-f", "json", "-q", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    # Bandit exits non-zero when it finds issues; that is expected, not an error.
    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"error": "bandit produced no parseable output", "stderr": proc.stderr}

    root_resolved = Path(root).resolve()

    def _relativize(filename: str | None) -> str:
        if not filename:
            return "?"
        try:
            return str(Path(filename).resolve().relative_to(root_resolved))
        except ValueError:
            return filename

    findings = [
        {
            "test_id": r.get("test_id"),
            "issue": r.get("issue_text"),
            "severity": r.get("issue_severity"),
            "confidence": r.get("issue_confidence"),
            "file": _relativize(r.get("filename")),
            "line": r.get("line_number"),
        }
        for r in report.get("results", [])
    ]
    return {"findings": findings, "count": len(findings)}


@mcp.tool()
def run_semgrep(path: str, root: str) -> dict[str, Any]:
    """Run Semgrep multi-language static analysis (JS, Go, Java, Ruby, and more).

    Semgrep is invoked through ``uvx`` so no heavy dependency is required. If it
    is unavailable, the tool degrades gracefully and reports that it was skipped
    rather than failing the audit.

    Args:
        path: File or directory to analyze (absolute or relative to ``root``).
        root: Sandbox root; the target must resolve inside it.

    Returns:
        A dict with multi-language findings, or ``skipped: True`` when Semgrep
        could not run.
    """
    try:
        target = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}

    if shutil.which("semgrep"):
        cmd = ["semgrep"]
    elif shutil.which("uvx"):
        cmd = ["uvx", "--from", "semgrep", "semgrep"]
    else:
        return {"findings": [], "skipped": True, "reason": "semgrep/uvx not available"}

    try:
        proc = subprocess.run(
            [*cmd, "scan", "--config", "auto", "--json", "--quiet", str(target)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        report = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return {"findings": [], "skipped": True, "reason": "semgrep did not produce output"}

    root_resolved = Path(root).resolve()

    def _rel(p: str | None) -> str:
        if not p:
            return "?"
        try:
            return str(Path(p).resolve().relative_to(root_resolved))
        except ValueError:
            return p

    findings = [
        {
            "check_id": r.get("check_id", "").split(".")[-1] or r.get("check_id"),
            "message": (r.get("extra", {}) or {}).get("message", ""),
            "severity": (r.get("extra", {}) or {}).get("severity", "INFO"),
            "file": _rel(r.get("path")),
            "line": (r.get("start", {}) or {}).get("line"),
        }
        for r in report.get("results", [])
    ]
    return {"findings": findings, "count": len(findings), "skipped": False}


# --------------------------------------------------------------------------- #
# Sandboxed source access
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_source_files(root: str) -> dict[str, Any]:
    """List all source files under a sandboxed root.

    Args:
        root: Directory to enumerate. Acts as its own sandbox boundary.

    Returns:
        A dict with the resolved root and a list of relative file paths.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return {"error": f"{root!r} is not a directory"}

    files = [
        str(p.relative_to(root_path))
        for p in root_path.rglob("*")
        if p.is_file() and p.suffix in SOURCE_EXTENSIONS
    ]
    return {"root": str(root_path), "files": sorted(files), "count": len(files)}


@mcp.tool()
def read_source_file(path: str, root: str) -> dict[str, Any]:
    """Read a single source file from within a sandboxed root.

    Args:
        path: File to read (absolute or relative to ``root``).
        root: Sandbox root; the file must resolve inside it.

    Returns:
        A dict with the file content, or an ``error`` key on sandbox violation.
    """
    try:
        file_path = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}
    if not file_path.is_file():
        return {"error": f"{path!r} is not a file"}
    return {"path": str(file_path), "content": file_path.read_text()}


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
