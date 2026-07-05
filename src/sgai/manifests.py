"""Dependency-manifest parsers for multiple language ecosystems.

Each parser turns a lockfile/manifest into a list of ``{name, version,
ecosystem}`` packages that can be looked up in OSV.dev. This is what lets SGAI
audit JavaScript, Go, and Rust projects, not just Python.

Ecosystem strings use OSV's names: ``PyPI``, ``npm``, ``Go``, ``crates.io``.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

# Filenames SGAI knows how to audit, mapped from glob to parser. Lockfiles are
# preferred (exact, pinned versions); package.json is intentionally skipped
# because its ranges are not exact.
MANIFEST_GLOBS = [
    "requirements*.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "package-lock.json",
    "go.mod",
    "Cargo.lock",
]


def _parse_requirements(text: str) -> list[dict]:
    """requirements.txt → PyPI packages (simple ``name==version`` pins)."""
    pkgs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, _, version = line.partition("==")
        pkgs.append({"name": name.strip(), "version": version.strip().split()[0], "ecosystem": "PyPI"})
    return pkgs


# An exact PEP 508 pin: "name==1.2.3", optionally with extras and a marker.
_PEP508_PIN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._!+]+)\s*(?:;.*)?$"
)
# A Poetry exact version constraint: plain "1.2.3" or "==1.2.3" (no ^ ~ > < *).
_POETRY_EXACT = re.compile(r"^(?:==)?\s*(\d[A-Za-z0-9._!+]*)$")


def _parse_pyproject(text: str) -> list[dict]:
    """pyproject.toml → PyPI packages from exact ``==`` pins only.

    Covers PEP 621 ``[project]`` dependencies / optional-dependencies, PEP 735
    ``[dependency-groups]``, and Poetry's ``[tool.poetry.dependencies]``.
    Range constraints (``>=``, ``^``, ``~``) are not auditable against OSV —
    the resolved versions live in the lockfile, which is parsed separately.
    """
    data = tomllib.loads(text)
    pkgs: list[dict] = []

    def _from_pep508(reqs: object) -> None:
        for req in reqs if isinstance(reqs, list) else []:
            m = _PEP508_PIN.match(str(req))
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})

    project = data.get("project") or {}
    _from_pep508(project.get("dependencies"))
    for reqs in (project.get("optional-dependencies") or {}).values():
        _from_pep508(reqs)
    for reqs in (data.get("dependency-groups") or {}).values():
        _from_pep508(reqs)

    poetry = (data.get("tool") or {}).get("poetry") or {}
    for group in [poetry, *(poetry.get("group") or {}).values()]:
        for name, spec in (group.get("dependencies") or {}).items():
            if name.lower() == "python":
                continue
            version = spec.get("version") if isinstance(spec, dict) else spec
            m = _POETRY_EXACT.match(str(version or ""))
            if m:
                pkgs.append({"name": name, "version": m.group(1), "ecosystem": "PyPI"})
    return pkgs


def _parse_poetry_lock(text: str) -> list[dict]:
    """poetry.lock → PyPI packages (exact resolved versions)."""
    data = tomllib.loads(text)
    return [
        {"name": p["name"], "version": p["version"], "ecosystem": "PyPI"}
        for p in data.get("package", [])
        if p.get("name") and p.get("version")
    ]


def _parse_uv_lock(text: str) -> list[dict]:
    """uv.lock → PyPI packages. Only registry entries; the local project,
    path/git dependencies, and workspace members have no OSV identity."""
    data = tomllib.loads(text)
    return [
        {"name": p["name"], "version": p["version"], "ecosystem": "PyPI"}
        for p in data.get("package", [])
        if p.get("name") and p.get("version") and "registry" in (p.get("source") or {})
    ]


def _parse_pipfile_lock(text: str) -> list[dict]:
    """Pipfile.lock → PyPI packages from the default and develop sections."""
    data = json.loads(text)
    pkgs = []
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = (spec or {}).get("version", "")
            if version.startswith("=="):
                pkgs.append({"name": name, "version": version[2:], "ecosystem": "PyPI"})
    return pkgs


def _parse_package_lock(text: str) -> list[dict]:
    """package-lock.json → npm packages (exact versions)."""
    data = json.loads(text)
    pkgs = []
    # lockfile v2/v3: the "packages" map keyed by "node_modules/<name>".
    for key, val in (data.get("packages") or {}).items():
        if not key.startswith("node_modules/"):
            continue
        name = key.split("node_modules/")[-1]
        version = val.get("version")
        if name and version:
            pkgs.append({"name": name, "version": version, "ecosystem": "npm"})
    # lockfile v1 fallback: the "dependencies" map.
    if not pkgs:
        for name, val in (data.get("dependencies") or {}).items():
            if val.get("version"):
                pkgs.append({"name": name, "version": val["version"], "ecosystem": "npm"})
    return pkgs


_GO_REQUIRE = re.compile(r"^\s*([^\s]+)\s+v([^\s/]+)")


def _parse_go_mod(text: str) -> list[dict]:
    """go.mod → Go modules. Versions are normalized to OSV's form."""
    pkgs = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//")[0].strip()  # drop // indirect comments
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        m = _GO_REQUIRE.match(candidate)
        if m:
            module, version = m.group(1), m.group(2)
            version = version.replace("+incompatible", "")
            pkgs.append({"name": module, "version": version, "ecosystem": "Go"})
    return pkgs


def _parse_cargo_lock(text: str) -> list[dict]:
    """Cargo.lock → crates.io packages."""
    data = tomllib.loads(text)
    return [
        {"name": p["name"], "version": p["version"], "ecosystem": "crates.io"}
        for p in data.get("package", [])
        if p.get("name") and p.get("version")
    ]


def parse_manifest(path: Path) -> list[dict]:
    """Parse a manifest file into a list of packages, dispatching on its name.

    A malformed manifest yields no packages rather than an exception — one
    broken file in a scanned repo must never abort the whole audit.
    """
    name = path.name
    text = path.read_text()
    try:
        if name.startswith("requirements") and name.endswith(".txt"):
            return _parse_requirements(text)
        if name == "pyproject.toml":
            return _parse_pyproject(text)
        if name == "poetry.lock":
            return _parse_poetry_lock(text)
        if name == "uv.lock":
            return _parse_uv_lock(text)
        if name == "Pipfile.lock":
            return _parse_pipfile_lock(text)
        if name == "package-lock.json":
            return _parse_package_lock(text)
        if name == "go.mod":
            return _parse_go_mod(text)
        if name == "Cargo.lock":
            return _parse_cargo_lock(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, AttributeError):
        return []
    return []


# --------------------------------------------------------------------------- #
# Container & infrastructure-as-code parsers
#
# These describe *configuration*, not dependencies, so they return structured
# directives rather than OSV packages. The scan_dockerfile MCP tool turns them
# into security findings (insecure base images, privileged users, open CIDRs).
# --------------------------------------------------------------------------- #

# Filenames the container/IaC scanner recognizes.
CONTAINER_GLOBS = ["Dockerfile", "Dockerfile.*", "*.Dockerfile"]
COMPOSE_GLOBS = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
IAC_GLOBS = ["*.tf"]


def parse_dockerfile(text: str) -> list[dict]:
    """Dockerfile → ordered instructions ``{instruction, argument, line}``.

    Line continuations (``\\``) are folded into a single logical instruction,
    and comments/blank lines are dropped. The ``line`` is where the instruction
    began, so findings point at the real source line.
    """
    instructions: list[dict] = []
    buffer = ""
    start_line = 0
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buffer:
            if not stripped or stripped.startswith("#"):
                continue
            start_line = i
            buffer = stripped
        else:
            buffer += " " + stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        parts = buffer.split(None, 1)
        instructions.append(
            {
                "instruction": parts[0].upper(),
                "argument": parts[1].strip() if len(parts) > 1 else "",
                "line": start_line,
            }
        )
        buffer = ""
    if buffer:  # trailing instruction ending in a continuation
        parts = buffer.split(None, 1)
        instructions.append(
            {
                "instruction": parts[0].upper(),
                "argument": parts[1].strip() if len(parts) > 1 else "",
                "line": start_line,
            }
        )
    return instructions


def parse_compose(text: str) -> dict:
    """docker-compose.yml → ``{services: [...]}`` with security-relevant fields."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML ships with bandit
        return {"services": []}
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return {"services": []}
    services = []
    for name, cfg in (data.get("services") or {}).items():
        cfg = cfg or {}
        services.append(
            {
                "name": name,
                "image": cfg.get("image"),
                "privileged": bool(cfg.get("privileged", False)),
                "user": cfg.get("user"),
                "ports": cfg.get("ports") or [],
                "environment": cfg.get("environment"),
                "cap_add": cfg.get("cap_add") or [],
                "volumes": cfg.get("volumes") or [],
            }
        )
    return {"services": services}


_TF_BLOCK = re.compile(
    r"^\s*(resource|data|module|provider|variable|output)\s+(.*?)\{", re.IGNORECASE
)
_TF_ASSIGN = re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.+?)\s*$')


def parse_terraform(text: str) -> dict:
    """Terraform HCL → ``{blocks, assignments}`` via a lightweight line parser.

    Full HCL parsing needs a real grammar; for security heuristics we only need
    block headers (``resource "aws_s3_bucket" "x"``) and simple ``key = value``
    assignments, which a line scanner extracts reliably enough.
    """
    blocks: list[dict] = []
    assignments: list[dict] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split("//", 1)[0]
        block = _TF_BLOCK.search(line)
        if block:
            labels = re.findall(r'"([^"]+)"', block.group(2))
            blocks.append({"type": block.group(1).lower(), "labels": labels, "line": i})
            continue
        assign = _TF_ASSIGN.match(line)
        if assign:
            value = assign.group(2).strip().strip('"')
            assignments.append({"key": assign.group(1), "value": value, "line": i})
    return {"blocks": blocks, "assignments": assignments}
