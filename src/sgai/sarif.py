"""SARIF 2.1.0 output for SGAI findings.

SARIF is the standard interchange format for static-analysis results. Emitting
it lets SGAI plug into GitHub code scanning (the Security tab), IDEs, and other
tooling — a credibility and integration win.
"""

from __future__ import annotations

import json
import re

from sgai.models import Finding, Severity
from sgai.risk import is_test_file

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


# A test suite for a secret scanner is necessarily full of credential-shaped
# literals, and SGAI's own is no exception: documentation-style AWS keys and
# dummy passwords that exist to prove the detectors fire. (They are not quoted
# here — a live-looking token in production source is a High finding that fails
# this repo's own `no-secrets` gate, which is the system working.) They are
# genuine matches, so they stay in the SARIF: a scanner that silently drops
# its own hits is one nobody can audit. But a reader of GitHub's Security tab
# must not mistake them for a live leak, and SARIF has the exact vocabulary for
# that — `suppressions` keeps the result and records why the tool considers it
# non-actionable, instead of hiding it.
#
# `external`, not `inSource`: the judgement comes from SGAI's own classification
# (severity plus path convention), not from an annotation written in the scanned
# file. Nothing in the source claims this.
SUPPRESSION_KIND = "external"


def _fixture_credential_path(finding: Finding) -> str | None:
    """The fixture file a credential finding sits in, else ``None``.

    Two independent signals must agree before SGAI explains a credential away:

    * the secret scanner classified it as test/mock/fixture context, which is
      the only way a secret finding is scored ``Info`` rather than ``High``; and
    * the shared :func:`~sgai.risk.is_test_file` classifier agrees the path is
      test/example code.

    Either signal alone is too weak to silence a credential. A directory named
    ``tests/`` must never mute a value the scanner ranked as live, and an ``Info``
    score must never mute one sitting in a production path.
    """
    if finding.source != "secret" or finding.severity != Severity.INFO:
        return None
    m = _FILE_LINE.match(finding.location)
    if not m or not is_test_file(m.group("file")):
        return None
    return m.group("file")


def _justification(path: str) -> str:
    """Why SGAI treats this credential as non-actionable — a reviewer reads this."""
    return (
        f"Credential-shaped literal in test/fixture code ({path}). SGAI's secret "
        "scanner classified it as fixture context and scored it Info, and test "
        "paths are outside the production surface the policy gate protects. "
        "Confirm the value was never live; if it was, rotate it and replace the "
        "fixture with an obviously fake value."
    )


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
        message = f"{f.title} ({f.location}). Fix: {f.remediation}"
        fixture = _fixture_credential_path(f)
        result = {
            "ruleId": f.id,
            "level": _LEVEL.get(f.severity.label, "warning"),
            # GitHub's alert list renders the message, not the suppression, so
            # the message has to carry the verdict too — otherwise the first
            # thing a reviewer reads is still "AWS access key id".
            "message": {"text": f"Test fixture (suppressed): {message}" if fixture else message},
            "locations": [_location(f)],
        }
        if fixture:
            result["suppressions"] = [{
                "kind": SUPPRESSION_KIND,
                "status": "accepted",
                "justification": _justification(fixture),
            }]
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
