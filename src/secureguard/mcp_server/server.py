"""The SecureGuard AI security MCP server.

Exposes the security capabilities the agents rely on as MCP tools:

* ``scan_dependency``        — query a single package against OSV.dev
* ``scan_requirements_file`` — audit every pin in a requirements.txt (batched)
* ``run_static_analysis``    — run Bandit over a path and return findings
* ``list_source_files``      — enumerate source files within a sandboxed root
* ``read_source_file``       — read a single source file within a sandboxed root

Run standalone with::

    uv run python -m secureguard.mcp_server.server
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from secureguard.config import HTTP_TIMEOUT, OSV_QUERY_BATCH_URL, OSV_QUERY_URL
from secureguard.mcp_server.sandbox import SandboxError, safe_resolve

mcp = FastMCP("secureguard-security-tools")

# File extensions we consider "source" worth scanning.
SOURCE_EXTENSIONS = {".py"}


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

    findings = [
        {
            "test_id": r.get("test_id"),
            "issue": r.get("issue_text"),
            "severity": r.get("issue_severity"),
            "confidence": r.get("issue_confidence"),
            "file": r.get("filename"),
            "line": r.get("line_number"),
        }
        for r in report.get("results", [])
    ]
    return {"findings": findings, "count": len(findings)}


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
