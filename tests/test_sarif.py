"""Tests for SARIF 2.1.0 output."""

import json

from sgai.models import Finding, Severity
from sgai.sarif import to_sarif, to_sarif_json


def _findings():
    return [
        Finding(id="B602", source="static", title="shell=True", severity=Severity.HIGH,
                location="app.py:18", remediation="Pass args as a list."),
        Finding(id="GHSA-jjjj-kkkk-llll", source="dependency", title="jinja2 vuln",
                severity=Severity.HIGH, location="PyPI:jinja2@2.11.2", remediation="Upgrade.",
                references=["GHSA-jjjj-kkkk-llll"], manifest="requirements.txt"),
    ]


def test_sarif_structure_and_levels():
    doc = to_sarif(_findings())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SGAI"
    assert len(run["results"]) == 2
    assert all(r["level"] == "error" for r in run["results"])  # both HIGH


def test_code_finding_points_at_its_source_line():
    run = to_sarif(_findings())["runs"][0]
    code = next(r for r in run["results"] if r["ruleId"] == "B602")
    physical = code["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "app.py"
    assert physical["region"]["startLine"] == 18


def test_dependency_finding_points_at_the_manifest_that_pins_it():
    """A dependency finding names a package, not a source line — but it still
    has a place a reader must go to fix it."""
    run = to_sarif(_findings())["runs"][0]
    dep = next(r for r in run["results"] if r["ruleId"].startswith("GHSA-"))
    assert dep["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"


def test_json_is_valid():
    parsed = json.loads(to_sarif_json(_findings()))
    assert parsed["runs"][0]["tool"]["driver"]["rules"]


# --------------------------------------------------------------------------- #
# What GitHub code scanning rejects
#
# These pin the two defects that made GitHub refuse the whole upload with
# "locationFromSarifResult: expected at least one location". A SARIF file that
# no scanning backend will accept is worse than no SARIF at all, so these
# invariants hold for *every* result, not just the ones we thought to construct.
# --------------------------------------------------------------------------- #
def test_every_result_has_at_least_one_physical_location():
    findings = _findings() + [
        # The pathological case: a dependency finding with no manifest recorded.
        Finding(id="GHSA-aaaa-bbbb-cccc", source="dependency", title="orphan",
                severity=Severity.CRITICAL, location="PyPI:orphan@1.0", remediation="Upgrade."),
    ]
    for result in to_sarif(findings)["runs"][0]["results"]:
        locations = result["locations"]
        assert locations, f"{result['ruleId']} has no location; GitHub rejects the whole file"
        uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri, f"{result['ruleId']} has a location with an empty uri"


def test_every_rule_help_uri_is_a_real_uri():
    """`references` mixes URLs with bare advisory ids; helpUri must be a URI."""
    findings = _findings() + [
        Finding(id="CVE-2021-44228", source="dependency", title="log4shell",
                severity=Severity.CRITICAL, location="Maven:log4j@2.14.1",
                remediation="Upgrade.", references=["CVE-2021-44228"], manifest="pom.xml"),
        Finding(id="B324", source="static", title="weak hash", severity=Severity.LOW,
                location="hash.py:3", remediation="Use sha256.",
                references=["https://bandit.readthedocs.io/"]),
    ]
    for rule in to_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["helpUri"].startswith(("http://", "https://")), (
            f"{rule['id']} helpUri is not a URI: {rule['helpUri']!r}"
        )


def test_advisory_ids_resolve_to_their_advisory_pages():
    findings = [
        Finding(id="GHSA-jjjj-kkkk-llll", source="dependency", title="x", severity=Severity.HIGH,
                location="PyPI:x@1", remediation="Upgrade.", references=["GHSA-jjjj-kkkk-llll"],
                manifest="requirements.txt"),
        Finding(id="CVE-2021-44228", source="dependency", title="y", severity=Severity.HIGH,
                location="Maven:y@1", remediation="Upgrade.", references=["CVE-2021-44228"],
                manifest="pom.xml"),
    ]
    uris = {r["id"]: r["helpUri"] for r in to_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]}
    assert uris["GHSA-jjjj-kkkk-llll"] == "https://github.com/advisories/GHSA-jjjj-kkkk-llll"
    assert uris["CVE-2021-44228"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_a_real_url_reference_wins_over_a_synthesised_one():
    finding = Finding(id="GHSA-jjjj-kkkk-llll", source="dependency", title="x",
                      severity=Severity.HIGH, location="PyPI:x@1", remediation="Upgrade.",
                      references=["GHSA-jjjj-kkkk-llll", "https://osv.dev/GHSA-jjjj-kkkk-llll"],
                      manifest="requirements.txt")
    rule = to_sarif([finding])["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://osv.dev/GHSA-jjjj-kkkk-llll"
