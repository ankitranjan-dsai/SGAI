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


# --------------------------------------------------------------------------- #
# Fixture credentials
#
# A test suite for a secret scanner is full of credential-shaped literals, and
# SGAI's own is no exception: documentation-style AWS keys and dummy passwords
# live in the fixtures a few files over. Those results stay in the SARIF — a
# scanner that hides its own matches is not one you can audit — but they must
# not read as a live leak in a Security tab. SARIF says
# that with `suppressions`: the result stands, annotated with why the tool
# considers it non-actionable.
#
# The suppression needs *both* signals to agree: the secret scanner's own
# fixture classification (Info) and the shared test-path classifier. Either one
# alone would let a live production credential be explained away.
# --------------------------------------------------------------------------- #
def _suppressions(result: dict) -> list[dict]:
    return result.get("suppressions", [])


def _secret(location, severity=Severity.INFO, check_id="aws-access-key"):
    return Finding(
        id=check_id, source="secret", title="AWS access key id", severity=severity,
        location=location, remediation="Appears to be test/fixture data.",
    )


def test_a_fixture_credential_is_suppressed_with_a_justification():
    result = to_sarif([_secret("tests/test_scan_scoping.py:22")])["runs"][0]["results"][0]
    suppressions = _suppressions(result)
    assert suppressions, "fixture credential was not marked suppressed"
    assert suppressions[0]["kind"] in ("inSource", "external")  # the SARIF enum
    assert "tests/test_scan_scoping.py" in suppressions[0]["justification"], (
        "the justification must name the fixture it is justifying"
    )


def test_suppressing_never_drops_a_result():
    """Option 3, not option 2: the Security tab shows it, dismissed with a reason."""
    findings = _findings() + [
        _secret("tests/test_phase3_secrets.py:46", check_id="generic-credential"),
        _secret("examples/vulnerable_app/app.py:7"),
    ]
    run = to_sarif(findings)["runs"][0]
    assert len(run["results"]) == len(findings)
    assert sum(1 for r in run["results"] if _suppressions(r)) == 2


def test_a_production_credential_is_never_suppressed():
    result = to_sarif([_secret("src/sgai/api.py:31", severity=Severity.HIGH)])["runs"][0]["results"][0]
    assert not _suppressions(result)


def test_a_credential_the_scanner_scored_as_live_is_never_suppressed():
    """A test path alone is not enough: if the scanner did not classify the
    value as fixture data, a directory name must not silence it."""
    result = to_sarif([_secret("tests/fixtures/prod_dump.py:3", severity=Severity.HIGH)])["runs"][0]["results"][0]
    assert not _suppressions(result)


def test_an_info_credential_outside_a_test_path_is_never_suppressed():
    result = to_sarif([_secret("src/sgai/config.py:12")])["runs"][0]["results"][0]
    assert not _suppressions(result)


def test_other_findings_in_test_paths_are_not_suppressed():
    """Only credential findings are fixture-explainable. A `shell=True` in a
    test helper is a real unsafe pattern and keeps its own alert."""
    finding = Finding(id="B602", source="static", title="shell=True", severity=Severity.INFO,
                      location="tests/helpers/run.py:9", remediation="Pass args as a list.")
    assert not _suppressions(to_sarif([finding])["runs"][0]["results"][0])


def test_a_suppressed_result_reads_as_a_fixture_at_a_glance():
    """GitHub's alert list shows the message, not the suppression — so the
    message itself has to say what this is."""
    result = to_sarif([_secret("tests/test_scan_scoping.py:22")])["runs"][0]["results"][0]
    assert result["message"]["text"].lower().startswith("test fixture")
    assert "AWS access key id" in result["message"]["text"]  # the finding survives intact
