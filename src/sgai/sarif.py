"""SARIF 2.1.0 output for SGAI findings.

SARIF is the standard interchange format for static-analysis results. Emitting
it lets SGAI plug into GitHub code scanning (the Security tab), IDEs, and other
tooling — a credibility and integration win.
"""

from __future__ import annotations

import json
import re

from sgai.models import Finding

_LEVEL = {
    "Critical": "error", "High": "error", "Medium": "warning",
    "Low": "note", "Info": "note", "Unknown": "note",
}
_FILE_LINE = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")
_GHSA = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/ankitranjan-dsai/SGAI"
ADVISORY_URL = "https://github.com/advisories/"
CVE_URL = "https://nvd.nist.gov/vuln/detail/"

# GitHub code scanning rejects a whole SARIF upload when any result carries no
# physical location ("locationFromSarifResult: expected at least one location"),
# so every result must resolve to some artifact. Dependency findings normally
# resolve to the manifest that pins the package; this anchors the rare finding
# that records neither a file nor a manifest to the repository root instead of
# emitting the empty array that fails the upload.
REPO_ROOT_URI = "."


def _location(finding: Finding) -> dict:
    """Build a SARIF physicalLocation. Never returns empty — see REPO_ROOT_URI.

    Static findings carry ``file:line``. Dependency findings identify a package
    rather than a source line (``PyPI:flask@0.12.2``), so they are anchored to
    the manifest that pins it — which is where a reader has to go to fix it.
    """
    m = _FILE_LINE.match(finding.location)
    if m:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": m.group("file")},
                "region": {"startLine": int(m.group("line"))},
            }
        }
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.manifest or REPO_ROOT_URI},
            "region": {"startLine": 1},
        }
    }


def _help_uri(finding: Finding) -> str:
    """A real URI for the rule's documentation.

    ``references`` mixes URLs with bare advisory ids (``GHSA-8q59-q68h-6hv4``),
    and SARIF requires ``helpUri`` to be a URI — GitHub warns on every rule that
    isn't. Prefer a reference that already is one, else synthesise the advisory
    page from the id.
    """
    for ref in finding.references:
        if isinstance(ref, str) and ref.startswith(("http://", "https://")):
            return ref
    for value in (*finding.references, finding.id):
        if not isinstance(value, str):
            continue
        if _GHSA.match(value):
            return ADVISORY_URL + value
        if _CVE.match(value):
            return CVE_URL + value
    return TOOL_URI


def to_sarif(findings: list[Finding]) -> dict:
    """Convert findings into a SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.source,
                "shortDescription": {"text": f.title[:120]},
                "helpUri": _help_uri(f),
            }
        results.append({
            "ruleId": f.id,
            "level": _LEVEL.get(f.severity.label, "warning"),
            "message": {"text": f"{f.title} ({f.location}). Fix: {f.remediation}"},
            "locations": [_location(f)],
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SGAI",
                        "informationUri": TOOL_URI,
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif_json(findings: list[Finding]) -> str:
    """SARIF document as a JSON string."""
    return json.dumps(to_sarif(findings), indent=2)
