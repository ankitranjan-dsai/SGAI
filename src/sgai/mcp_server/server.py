"""The SGAI security MCP server.

Exposes the security capabilities the agents rely on as MCP tools:

* ``scan_dependency``        — query a single package against OSV.dev
* ``scan_requirements_file`` — audit every pin in a requirements.txt (batched)
* ``run_static_analysis``    — run Bandit over a path and return findings
* ``list_source_files``      — enumerate source files within a sandboxed root
* ``read_source_file``       — read a single source file within a sandboxed root
* ``validate_patch``         — run the target project's own tests in the sandbox
* ``scan_dockerfile``        — audit Dockerfile/compose/Terraform misconfigurations
* ``scan_secrets``           — detect leaked secrets (entropy + LLM dummy filtering)

Run standalone with::

    uv run python -m sgai.mcp_server.server
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
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
# Container & infrastructure-as-code misconfiguration scanning
# --------------------------------------------------------------------------- #
def _finding(check_id: str, title: str, severity: str, line: int, detail: str, fix: str) -> dict:
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "line": line,
        "detail": detail,
        "remediation": fix,
    }


def _scan_dockerfile_text(text: str) -> list[dict]:
    """Security findings for a Dockerfile's instructions."""
    from sgai.manifests import parse_dockerfile

    findings: list[dict] = []
    has_user = False
    last_user_root = False
    for instr in parse_dockerfile(text):
        name, arg, line = instr["instruction"], instr["argument"], instr["line"]
        if name == "FROM":
            image = arg.split(" AS ")[0].split(" as ")[0].strip()
            ref = image.split("@")[0]  # ignore digest pin for the tag check
            tag = ref.split(":", 1)[1] if ":" in ref else ""
            if image != "scratch" and (not tag or tag == "latest"):
                findings.append(_finding(
                    "SGAI-DOCKER-BASE",
                    f"Unpinned base image `{image}`",
                    "MEDIUM", line,
                    "Untagged or `:latest` base images make builds non-reproducible and "
                    "silently pull in new, possibly vulnerable, layers.",
                    "Pin the base image to an explicit version and ideally a digest "
                    "(e.g. `python:3.12-slim@sha256:…`).",
                ))
        elif name == "USER":
            has_user = True
            last_user_root = arg.strip() in ("root", "0")
        elif name == "ADD" and re.search(r"https?://", arg):
            findings.append(_finding(
                "SGAI-DOCKER-ADD-URL",
                "ADD fetches a remote URL",
                "MEDIUM", line,
                "`ADD <url>` downloads over the network with no integrity check.",
                "Use `COPY` for local files, or `RUN curl` with a verified checksum.",
            ))
        elif name == "RUN":
            if re.search(r"(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(sh|bash)", arg):
                findings.append(_finding(
                    "SGAI-DOCKER-CURL-PIPE",
                    "RUN pipes a downloaded script straight into a shell",
                    "HIGH", line,
                    "`curl … | sh` executes unverified remote code during the build.",
                    "Download to a file, verify its checksum/signature, then execute it.",
                ))
            if re.search(r"\bsudo\b", arg):
                findings.append(_finding(
                    "SGAI-DOCKER-SUDO",
                    "RUN uses sudo",
                    "LOW", line,
                    "Docker build steps already run as root; sudo adds attack surface.",
                    "Drop sudo; use the `USER` instruction to control privileges.",
                ))
        elif name in ("ENV", "ARG"):
            if re.search(r"(?i)(pass(word|wd)?|secret|api[_-]?key|token|access[_-]?key)\s*[=\s]", arg):
                findings.append(_finding(
                    "SGAI-DOCKER-SECRET-ENV",
                    f"Possible secret baked into an {name} layer",
                    "HIGH", line,
                    f"`{name}` values are stored in the image and visible via "
                    "`docker history`; secrets set this way leak to anyone with the image.",
                    "Pass secrets at runtime (BuildKit `--secret`, env at `docker run`), "
                    "never bake them into a layer.",
                ))
    if not has_user or last_user_root:
        findings.append(_finding(
            "SGAI-DOCKER-ROOT",
            "Container runs as root",
            "HIGH", 1,
            "No non-root `USER` is set (or the final USER is root), so the process "
            "runs with full container privileges — a container escape becomes host root.",
            "Create and switch to an unprivileged user: `RUN useradd -m app` then `USER app`.",
        ))
    return findings


def _scan_compose_text(text: str) -> list[dict]:
    """Security findings for a docker-compose file's services."""
    from sgai.manifests import parse_compose

    findings: list[dict] = []
    for svc in parse_compose(text).get("services", []):
        name = svc["name"]
        if svc["privileged"]:
            findings.append(_finding(
                "SGAI-COMPOSE-PRIVILEGED",
                f"Service `{name}` runs privileged",
                "HIGH", 1,
                "`privileged: true` disables almost all container isolation.",
                "Remove `privileged`; grant only the specific `cap_add` capabilities needed.",
            ))
        user = str(svc["user"]) if svc["user"] is not None else None
        if user in ("root", "0"):
            findings.append(_finding(
                "SGAI-COMPOSE-ROOT",
                f"Service `{name}` runs as root",
                "MEDIUM", 1,
                "Explicit root user removes the protection of an unprivileged runtime.",
                "Set `user:` to a non-root uid.",
            ))
        image = svc["image"]
        if image and image != "scratch":
            ref = image.split("@")[0]
            tag = ref.split(":", 1)[1] if ":" in ref else ""
            if not tag or tag == "latest":
                findings.append(_finding(
                    "SGAI-COMPOSE-BASE",
                    f"Service `{name}` uses unpinned image `{image}`",
                    "MEDIUM", 1,
                    "`:latest`/untagged images are non-reproducible.",
                    "Pin the image to an explicit version/digest.",
                ))
        caps = [str(c).upper() for c in svc["cap_add"]]
        if "ALL" in caps or "SYS_ADMIN" in caps:
            findings.append(_finding(
                "SGAI-COMPOSE-CAP",
                f"Service `{name}` adds dangerous capabilities",
                "HIGH", 1,
                "`SYS_ADMIN`/`ALL` capabilities are close to privileged mode.",
                "Grant only the minimal capabilities the workload actually needs.",
            ))
        for vol in svc["volumes"]:
            if "/var/run/docker.sock" in str(vol):
                findings.append(_finding(
                    "SGAI-COMPOSE-DOCKERSOCK",
                    f"Service `{name}` mounts the Docker socket",
                    "HIGH", 1,
                    "Mounting `/var/run/docker.sock` grants root-equivalent control of the host.",
                    "Avoid mounting the Docker socket; use a scoped API or rootless tooling.",
                ))
    return findings


def _scan_terraform_text(text: str) -> list[dict]:
    """Security findings for a Terraform file."""
    from sgai.manifests import parse_terraform

    findings: list[dict] = []
    for a in parse_terraform(text).get("assignments", []):
        key, value, line = a["key"].lower(), a["value"], a["line"]
        if value == "0.0.0.0/0" and ("cidr" in key or key in ("cidr_blocks", "cidr_block")):
            findings.append(_finding(
                "SGAI-TF-OPEN-CIDR",
                "Security group open to the entire internet (0.0.0.0/0)",
                "HIGH", line,
                "An ingress rule allowing 0.0.0.0/0 exposes the resource to the whole internet.",
                "Restrict the CIDR to known, minimal source ranges.",
            ))
        if key == "acl" and value in ("public-read", "public-read-write"):
            findings.append(_finding(
                "SGAI-TF-PUBLIC-ACL",
                f"Publicly readable resource ACL `{value}`",
                "HIGH", line,
                "A public-read ACL exposes bucket/object contents to anyone.",
                "Use a private ACL and grant access through scoped policies.",
            ))
        if re.search(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key)$", key) and value and not value.startswith("${"):
            findings.append(_finding(
                "SGAI-TF-HARDCODED-SECRET",
                f"Hardcoded secret in Terraform (`{a['key']}`)",
                "HIGH", line,
                "A credential committed to Terraform source ends up in state and version control.",
                "Reference a variable or a secrets manager (e.g. Vault, SSM) instead.",
            ))
    return findings


@mcp.tool()
def scan_dockerfile(path: str, root: str) -> dict[str, Any]:
    """Scan a Dockerfile, docker-compose file, or Terraform file for misconfigurations.

    Dispatches on the filename: Dockerfiles are checked for insecure/unpinned
    base images, root users, and remote-code build steps; compose files for
    privileged containers, root users, and Docker-socket mounts; Terraform for
    internet-open security groups, public ACLs, and hardcoded secrets.

    Args:
        path: File to scan (absolute or relative to ``root``).
        root: Sandbox root; the file must resolve inside it.

    Returns:
        ``{findings, count, kind}`` or an ``error`` on sandbox violation.
    """
    try:
        target = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}
    if not target.is_file():
        return {"error": f"{path!r} is not a file"}

    text = target.read_text()
    name = target.name.lower()
    if name.endswith(".tf"):
        kind, findings = "terraform", _scan_terraform_text(text)
    elif name.startswith("docker-compose") or name.startswith("compose"):
        kind, findings = "compose", _scan_compose_text(text)
    else:
        kind, findings = "dockerfile", _scan_dockerfile_text(text)
    return {"findings": findings, "count": len(findings), "kind": kind}


# --------------------------------------------------------------------------- #
# Secret scanning (high-entropy leaks + known token formats)
# --------------------------------------------------------------------------- #

# High-confidence provider token formats. A match here is a finding regardless
# of entropy — these shapes are unmistakable.
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws-access-key", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "GitHub personal access token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github-oauth", "GitHub OAuth token", re.compile(r"\bgho_[0-9A-Za-z]{36}\b")),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private-key", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("stripe-key", "Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
]

# Generic `name = "value"` assignments whose name looks credential-bearing.
_ASSIGN_SECRET = re.compile(
    r"""(?ix)
    \b(?P<name>\w*(?:pass(?:word|wd)?|secret|api[_-]?key|apikey|token|access[_-]?key|auth)\w*)
    \s*[:=]\s*
    (?P<q>['"])(?P<value>[^'"]{6,})(?P=q)
    """
)

# Bare high-entropy quoted strings (catches secrets with non-obvious names).
_QUOTED = re.compile(r"""(['"])(?P<value>[A-Za-z0-9+/=_\-]{20,})\1""")

_DUMMY_MARKERS = (
    "changeme", "change_me", "example", "your", "dummy", "sample", "placeholder",
    "redacted", "replace", "insert", "xxxx", "test", "fake", "notreal", "todo",
    "password", "secret", "token", "abc123", "foo", "bar", "1234", "0000",
    "<", ">", "{{", "}}", "...", "n/a", "none", "null",
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per character) of ``s``."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_dummy(value: str) -> bool:
    """Heuristic: is this an obvious placeholder rather than a real secret?"""
    lowered = value.lower()
    if len(value) < 8:
        return True
    if any(marker in lowered for marker in _DUMMY_MARKERS):
        return True
    if len(set(value)) <= 2:  # "aaaaaaaa", "xxxxxxxx"
        return True
    if re.fullmatch(r"(?:x+|0+|\*+|-+|\.+)", value):
        return True
    return False


def _find_secret_candidates(text: str, filename: str) -> list[dict]:
    """Detect candidate secrets in one file's text (pre dummy-filtering)."""
    candidates: list[dict] = []
    seen: set[tuple[int, str]] = set()

    def add(check_id: str, title: str, value: str, line: int, entropy: float) -> None:
        key = (line, value)
        if key in seen:
            return
        seen.add(key)
        masked = value[:4] + "…" + f"({len(value)} chars)" if len(value) > 4 else "****"
        candidates.append({
            "check_id": check_id, "title": title, "file": filename, "line": line,
            "value": value, "match": masked, "entropy": round(entropy, 2),
        })

    for lineno, raw in enumerate(text.splitlines(), 1):
        for check_id, title, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(raw):
                token = m.group(0)
                add(check_id, title, token, lineno, _shannon_entropy(token))
        for m in _ASSIGN_SECRET.finditer(raw):
            value = m.group("value")
            add("generic-credential", f"Hardcoded credential in `{m.group('name')}`",
                value, lineno, _shannon_entropy(value))
        for m in _QUOTED.finditer(raw):
            value = m.group("value")
            entropy = _shannon_entropy(value)
            if entropy >= 4.0 and len(value) >= 20:
                add("high-entropy-string", "High-entropy string (possible secret)",
                    value, lineno, entropy)
    return candidates


# Text file suffixes worth scanning for secrets; everything else (binaries,
# images) is skipped.
_SECRET_SCAN_SUFFIXES = {
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php", ".sh", ".env",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf", ".txt",
    ".properties", ".xml", ".gradle", ".md", "",
}
_SECRET_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv", "dist", "build"}


@mcp.tool()
def scan_secrets(path: str, root: str, use_llm: bool = False) -> dict[str, Any]:
    """Scan for leaked secrets: known token formats plus high-entropy strings.

    Every candidate is passed through a placeholder filter that discards obvious
    dummies (``changeme``, ``your-api-key``, ``xxxx``…). When ``use_llm`` is set
    and a model is configured, a second LLM pass classifies the survivors and
    drops any it judges to be example/test credentials — cutting false positives
    on realistic-looking-but-fake values. The LLM pass is best-effort: if it is
    unavailable it is skipped and detection still returns.

    Args:
        path: File or directory to scan (absolute or relative to ``root``).
        root: Sandbox root; the target must resolve inside it.
        use_llm: Enable the LLM dummy-credential verification pass.

    Returns:
        ``{findings, count, scanned_files}``. Secret values are masked in the
        output — only a prefix and length are returned, never the full secret.
    """
    try:
        target = safe_resolve(root, path)
    except SandboxError as exc:
        return {"error": str(exc)}

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [
            p for p in sorted(target.rglob("*"))
            if p.is_file()
            and p.suffix.lower() in _SECRET_SCAN_SUFFIXES
            and not _SECRET_SKIP_DIRS & set(p.parts)
        ]
    else:
        return {"error": f"{path!r} is not a file or directory"}

    root_resolved = Path(root).resolve()
    candidates: list[dict] = []
    for f in files:
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        try:
            rel = str(f.relative_to(root_resolved))
        except ValueError:
            rel = f.name
        candidates.extend(_find_secret_candidates(text, rel))

    # Stage 1 (always): drop obvious placeholders deterministically.
    real = [c for c in candidates if not _looks_like_dummy(c["value"])]

    # Stage 2 (optional): LLM verification weeds out realistic-looking dummies.
    if use_llm and real:
        real = _llm_filter_dummy_secrets(real)

    # Never leak the raw secret back to the caller.
    findings = [{k: v for k, v in c.items() if k != "value"} for c in real]
    return {"findings": findings, "count": len(findings), "scanned_files": len(files)}


def _llm_filter_dummy_secrets(
    candidates: list[dict], classifier: Callable[[list[dict]], list[bool]] | None = None
) -> list[dict]:
    """Keep only candidates an LLM judges to be *real* secrets.

    ``classifier`` returns one bool per candidate (True = real). It defaults to a
    Gemini-backed classifier; on any failure (no key, rate limit, bad output)
    the candidates are returned unchanged so detection never regresses to zero.
    """
    verifier = classifier or _gemini_secret_classifier
    try:
        verdicts = verifier(candidates)
    except Exception:  # noqa: BLE001 — LLM verification is best-effort
        return candidates
    if len(verdicts) != len(candidates):
        return candidates
    return [c for c, keep in zip(candidates, verdicts) if keep]


def _gemini_secret_classifier(candidates: list[dict]) -> list[bool]:
    """Ask the configured model which candidates are real vs. dummy secrets."""
    from google import genai

    listing = "\n".join(
        f"{i}. name={c.get('title')} value_prefix={c['value'][:6]!r} "
        f"length={len(c['value'])} entropy={c['entropy']}"
        for i, c in enumerate(candidates)
    )
    prompt = (
        "You are a secret-scanning triage assistant. For each candidate below, decide "
        "whether it is a REAL leaked credential or an obvious DUMMY/example/test value. "
        "Reply with a JSON array of booleans (true = real secret), one per candidate, "
        "in order, and nothing else.\n\n" + listing
    )
    client = genai.Client()
    from sgai.config import MODEL

    resp = client.models.generate_content(model=MODEL, contents=prompt)
    payload = (resp.text or "").strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    verdicts = json.loads(payload)
    return [bool(v) for v in verdicts]


# --------------------------------------------------------------------------- #
# Patch validation (the self-healing loop's safety net)
# --------------------------------------------------------------------------- #
@mcp.tool()
def validate_patch(root: str, path: str = ".", timeout_seconds: int = 300) -> dict[str, Any]:
    """Run the target project's own test suite inside the sandbox root.

    Used by the code-healer to prove a security patch is non-breaking: tests are
    run before and after patching, and any patch that turns a green suite red is
    rolled back. Only ``pytest`` is executed — never an arbitrary command from
    the model — and only inside the sandboxed root.

    Args:
        root: Sandbox root of the project under repair.
        path: Directory whose tests to run (relative to ``root``); defaults
            to the whole project.
        timeout_seconds: Hard cap on the test run.

    Returns:
        ``{ran, passed, exit_code, output}`` — ``ran`` is False (with a
        ``reason``) when no test suite exists, so callers can tell "no tests"
        apart from "tests failed".
    """
    try:
        target = safe_resolve(root, path)
    except SandboxError as exc:
        return {"ran": False, "passed": None, "error": str(exc)}
    if not target.is_dir():
        return {"ran": False, "passed": None, "reason": f"{path!r} is not a directory"}

    has_tests = any(
        p.name.startswith("test_") or p.name.endswith("_test.py")
        for p in target.rglob("*.py")
        if ".venv" not in p.parts and "node_modules" not in p.parts
    )
    if not has_tests:
        return {"ran": False, "passed": None, "reason": "no test files found"}

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", str(target)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(target),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ran": True, "passed": False, "reason": f"tests timed out after {timeout_seconds}s"}

    output = (proc.stdout or "") + (proc.stderr or "")
    # pytest exit code 5 means "no tests collected" — treat like "no tests".
    if proc.returncode == 5:
        return {"ran": False, "passed": None, "reason": "no tests collected"}
    return {
        "ran": True,
        "passed": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": output[-4000:],  # tail only; suites can be huge
    }


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
