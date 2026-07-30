"""VEX (Vulnerability Exploitability eXchange) export for SGAI.

An SBOM says *what is in the build*; a VEX document says *whether the known
vulnerabilities in those components actually matter here*. SGAI already computes
this: dependency reachability tells us whether first-party code imports a
vulnerable package. This module maps that signal onto the standard VEX statuses
and emits an **OpenVEX** document.

Status mapping (deterministic, from reachability):

* reachable → ``affected`` — the vulnerable code is on an execution path.
* not reachable → ``not_affected`` (justification
  ``vulnerable_code_not_in_execute_path``) — present but unused.
* reachability unknown → ``under_investigation``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sgai.models import Finding

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"
STATUS_FIXED = "fixed"

# OSV ecosystem → Package-URL type (shared shape with the SBOM module).
_PURL_TYPE = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _product_purl(location: str) -> str | None:
    """Turn a dependency finding location (``ecosystem:name@version``) into a PURL."""
    if ":" not in location or "@" not in location:
        return None
    ecosystem, _, rest = location.partition(":")
    name, _, version = rest.partition("@")
    ptype = _PURL_TYPE.get(ecosystem, ecosystem.lower())
    return f"pkg:{ptype}/{name}@{version}"


def _status_for(finding: Finding) -> tuple[str, str | None]:
    """(status, justification) for a dependency finding from its reachability."""
    if finding.reachable is True:
        return STATUS_AFFECTED, None
    if finding.reachable is False:
        return STATUS_NOT_AFFECTED, "vulnerable_code_not_in_execute_path"
    return STATUS_UNDER_INVESTIGATION, None


def vex_statements(findings: list[Finding]) -> list[dict]:
    """Build one OpenVEX statement per (vulnerability, product) from dependency findings.

    Each advisory id a package carries becomes its own statement, so a scanner
    can look up a specific CVE and learn whether this application is affected.
    """
    statements: list[dict] = []
    for f in findings:
        if f.source != "dependency":
            continue
        product = _product_purl(f.location)
        if product is None:
            continue
        status, justification = _status_for(f)
        vuln_ids = f.references or [f.id]
        for vuln_id in vuln_ids:
            statement = {
                "vulnerability": {"name": vuln_id},
                "products": [{"@id": product}],
                "status": status,
            }
            if justification:
                statement["justification"] = justification
                statement["impact_statement"] = (
                    "First-party code does not import this package; the vulnerable "
                    "code is not on any execution path."
                )
            elif status == STATUS_AFFECTED:
                statement["action_statement"] = (
                    "First-party code imports this package — upgrade to a patched "
                    "version."
                )
            statements.append(statement)
    return statements


def build_vex(findings: list[Finding], author: str = "SGAI", target: str = "target") -> dict:
    """Assemble an OpenVEX document from a scan's dependency findings."""
    statements = vex_statements(findings)
    doc_id = "https://sgai.local/vex/" + hashlib.sha256(
        (target + _now()).encode()
    ).hexdigest()[:16]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "role": "Automated security scanner",
        "timestamp": _now(),
        "version": 1,
        "statements": statements,
    }
