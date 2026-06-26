"""Tests for SARIF 2.1.0 output."""

import json

from sgai.models import Finding, Severity
from sgai.sarif import to_sarif, to_sarif_json


def _findings():
    return [
        Finding(id="B602", source="static", title="shell=True", severity=Severity.HIGH,
                location="app.py:18", remediation="Pass args as a list."),
        Finding(id="GHSA-x", source="dependency", title="jinja2 vuln", severity=Severity.HIGH,
                location="PyPI:jinja2@2.11.2", remediation="Upgrade.", references=["GHSA-x"]),
    ]


def test_sarif_structure_and_levels():
    doc = to_sarif(_findings())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SGAI"
    assert len(run["results"]) == 2
    assert all(r["level"] == "error" for r in run["results"])  # both HIGH


def test_sarif_code_finding_has_location_dep_does_not():
    run = to_sarif(_findings())["runs"][0]
    code = next(r for r in run["results"] if r["ruleId"] == "B602")
    dep = next(r for r in run["results"] if r["ruleId"] == "GHSA-x")
    assert code["locations"][0]["physicalLocation"]["region"]["startLine"] == 18
    assert dep["locations"] == []  # dependency finding has no file/line


def test_sarif_json_is_valid():
    parsed = json.loads(to_sarif_json(_findings()))
    assert parsed["runs"][0]["tool"]["driver"]["rules"]
