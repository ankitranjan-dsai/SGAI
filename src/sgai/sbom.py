"""Software Bill of Materials (SBOM) export for SGAI.

Parses a repository's dependency lockfiles into a component inventory and emits
it as either **CycloneDX 1.5** or **SPDX 2.3** JSON — the two formats security
and compliance tooling consume. Detection is deterministic: the same
multi-ecosystem :func:`~sgai.manifests.parse_manifest` used by the auditor,
reused so the SBOM and the findings describe the same set of packages.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sgai.manifests import MANIFEST_GLOBS, parse_manifest

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}

# OSV ecosystem → Package-URL type.
_PURL_TYPE = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo"}

SBOM_TOOL = "SGAI"
SBOM_TOOL_VERSION = "0.1.0"


def purl(pkg: dict) -> str:
    """Package-URL for a ``{name, version, ecosystem}`` component."""
    ptype = _PURL_TYPE.get(pkg["ecosystem"], pkg["ecosystem"].lower())
    return f"pkg:{ptype}/{pkg['name']}@{pkg['version']}"


def collect_packages(repo_dir: str) -> list[dict]:
    """Every pinned dependency across the repo's lockfiles, de-duplicated.

    Returns ``{name, version, ecosystem}`` dicts sorted for stable output.
    """
    root = Path(repo_dir).resolve()
    seen: set[tuple[str, str, str]] = set()
    packages: list[dict] = []
    for glob in MANIFEST_GLOBS:
        for manifest in sorted(root.rglob(glob)):
            if _SKIP_DIRS & set(manifest.parts):
                continue
            for pkg in parse_manifest(manifest):
                key = (pkg["ecosystem"], pkg["name"], pkg["version"])
                if key in seen:
                    continue
                seen.add(key)
                packages.append(pkg)
    packages.sort(key=lambda p: (p["ecosystem"], p["name"].lower(), p["version"]))
    return packages


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _serial(name: str, packages: list[dict]) -> str:
    """Deterministic-ish urn:uuid serial number from the component set."""
    digest = hashlib.sha1((name + "|".join(purl(p) for p in packages)).encode()).hexdigest()
    return f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def to_cyclonedx(packages: list[dict], name: str = "target") -> dict:
    """Render components as a CycloneDX 1.5 JSON document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": _serial(name, packages),
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": [{"vendor": "Anthropic-hackathon", "name": SBOM_TOOL, "version": SBOM_TOOL_VERSION}],
            "component": {"type": "application", "name": name, "bom-ref": name},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": purl(p),
                "name": p["name"],
                "version": p["version"],
                "purl": purl(p),
                "properties": [{"name": "sgai:ecosystem", "value": p["ecosystem"]}],
            }
            for p in packages
        ],
    }


def to_spdx(packages: list[dict], name: str = "target") -> dict:
    """Render components as an SPDX 2.3 JSON document."""
    doc_ns = f"https://sgai.local/spdx/{name}/{hashlib.sha1(name.encode()).hexdigest()[:12]}"
    root_ref = "SPDXRef-DOCUMENT"
    root_pkg_ref = "SPDXRef-Package-root"

    def spdx_ref(p: dict) -> str:
        slug = hashlib.sha1(purl(p).encode()).hexdigest()[:16]
        return f"SPDXRef-Package-{slug}"

    spdx_packages = [{
        "SPDXID": root_pkg_ref,
        "name": name,
        "downloadLocation": "NOASSERTION",
        "versionInfo": "NOASSERTION",
    }]
    relationships = [
        {"spdxElementId": root_ref, "relationshipType": "DESCRIBES", "relatedSpdxElement": root_pkg_ref}
    ]
    for p in packages:
        ref = spdx_ref(p)
        spdx_packages.append({
            "SPDXID": ref,
            "name": p["name"],
            "versionInfo": p["version"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl(p),
            }],
        })
        relationships.append({
            "spdxElementId": root_pkg_ref,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ref,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": root_ref,
        "name": name,
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": _now(),
            "creators": [f"Tool: {SBOM_TOOL}-{SBOM_TOOL_VERSION}"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def build_sbom(repo_dir: str, fmt: str = "cyclonedx", name: str = "target") -> dict:
    """Build an SBOM for ``repo_dir`` in ``cyclonedx`` (default) or ``spdx`` format."""
    packages = collect_packages(repo_dir)
    if fmt.lower() == "spdx":
        return to_spdx(packages, name)
    return to_cyclonedx(packages, name)
