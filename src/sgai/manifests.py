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
MANIFEST_GLOBS = ["requirements*.txt", "package-lock.json", "go.mod", "Cargo.lock"]


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
    """Parse a manifest file into a list of packages, dispatching on its name."""
    name = path.name
    text = path.read_text()
    if name.startswith("requirements") and name.endswith(".txt"):
        return _parse_requirements(text)
    if name == "package-lock.json":
        return _parse_package_lock(text)
    if name == "go.mod":
        return _parse_go_mod(text)
    if name == "Cargo.lock":
        return _parse_cargo_lock(text)
    return []
