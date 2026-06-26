"""SARIF 2.1.0 output for SGAI findings.

SARIF is the standard interchange format for static-analysis results. Emitting
it lets SGAI plug into GitHub code scanning (the Security tab), IDEs, and other
tooling — a credibility and integration win.
"""

from __future__ import annotations

import json
import re

from sgai.models import Finding

_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Unknown": "note"}
_FILE_LINE = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/ankitranjan-dsai/SGAI"


def _location(finding: Finding) -> dict | None:
    """Build a SARIF physicalLocation for code findings (``file:line``)."""
    m = _FILE_LINE.match(finding.location)
    if not m:
        return None  # dependency findings have no file/line
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": m.group("file")},
            "region": {"startLine": int(m.group("line"))},
        }
    }


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
                "helpUri": (f.references[0] if f.references else TOOL_URI),
            }
        result = {
            "ruleId": f.id,
            "level": _LEVEL.get(f.severity.label, "warning"),
            "message": {"text": f"{f.title} ({f.location}). Fix: {f.remediation}"},
        }
        loc = _location(f)
        result["locations"] = [loc] if loc else []
        results.append(result)

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
