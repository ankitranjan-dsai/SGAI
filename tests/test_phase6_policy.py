"""Phase 6: policy-as-code engine, /scan/check gate, sgai check CLI."""

from fastapi.testclient import TestClient

from sgai.api import app
from sgai.cli import main as cli_main
from sgai.models import Finding, Severity
from sgai.policy import (
    Policy,
    check,
    evaluate_policies,
    load_policies,
    parse_policies,
)

client = TestClient(app)


def _f(source, severity, location, id="X") -> Finding:
    return Finding(id=id, source=source, title="t", severity=severity, location=location)


# --------------------------------------------------------------------------- #
# Individual policies
# --------------------------------------------------------------------------- #
def test_no_critical_in_production_fails_on_prod_critical():
    findings = [_f("static", Severity.CRITICAL, "app.py:3")]
    result = evaluate_policies(findings, [Policy("no-critical-in-production", {})])
    assert result.passed is False
    assert result.violations[0].policy == "no-critical-in-production"


def test_no_critical_in_production_ignores_test_files():
    findings = [_f("static", Severity.CRITICAL, "tests/test_app.py:3")]
    result = evaluate_policies(findings, [Policy("no-critical-in-production", {})])
    assert result.passed is True


def test_no_critical_can_be_disabled():
    findings = [_f("static", Severity.CRITICAL, "app.py:3")]
    result = evaluate_policies(findings, [Policy("no-critical-in-production", {"enabled": False})])
    assert result.passed is True


def test_max_unpatched_cves():
    findings = [
        _f("dependency", Severity.HIGH, "PyPI:a@1"),
        _f("dependency", Severity.HIGH, "PyPI:b@1"),
        _f("dependency", Severity.HIGH, "PyPI:c@1"),
    ]
    assert evaluate_policies(findings, [Policy("max-unpatched-cves", {"max": 2})]).passed is False
    assert evaluate_policies(findings, [Policy("max-unpatched-cves", {"max": 5})]).passed is True


def test_max_unpatched_cves_reachable_only():
    findings = [
        _f("dependency", Severity.HIGH, "PyPI:a@1"),
        _f("dependency", Severity.HIGH, "PyPI:b@1"),
    ]
    findings[0].reachable = True
    result = evaluate_policies(
        findings, [Policy("max-unpatched-cves", {"max": 0, "reachable_only": True})]
    )
    assert result.passed is False
    assert result.violations[0].findings == ["PyPI:a@1"]


def test_fail_on_severity():
    findings = [_f("static", Severity.HIGH, "app.py:1")]
    assert evaluate_policies(findings, [Policy("fail-on-severity", {"severity": "high"})]).passed is False
    assert evaluate_policies(findings, [Policy("fail-on-severity", {"severity": "critical"})]).passed is True


def test_no_secrets_policy():
    prod = [_f("secret", Severity.HIGH, "app.py:1")]
    test = [_f("secret", Severity.INFO, "tests/conf.py:1")]
    assert evaluate_policies(prod, [Policy("no-secrets", {})]).passed is False
    assert evaluate_policies(test, [Policy("no-secrets", {})]).passed is True  # Info < HIGH floor


def test_multiple_violations_reported():
    findings = [
        _f("static", Severity.CRITICAL, "app.py:3"),
        _f("dependency", Severity.HIGH, "PyPI:a@1"),
    ]
    result = evaluate_policies(findings, [
        Policy("no-critical-in-production", {}),
        Policy("max-unpatched-cves", {"max": 0}),
    ])
    assert result.passed is False
    assert {v.policy for v in result.violations} == {"no-critical-in-production", "max-unpatched-cves"}


# --------------------------------------------------------------------------- #
# Loading & parsing
# --------------------------------------------------------------------------- #
def test_parse_mapping_form():
    policies = parse_policies({"policies": {"max-unpatched-cves": {"max": 3}}})
    assert policies == [Policy("max-unpatched-cves", {"max": 3})]


def test_parse_list_form():
    policies = parse_policies({"policies": [{"rule": "fail-on-severity", "severity": "medium"}]})
    assert policies[0].rule == "fail-on-severity"
    assert policies[0].options == {"severity": "medium"}


def test_parse_drops_unknown_rules():
    assert parse_policies({"policies": {"not-a-real-policy": {}}}) == []


def test_load_policies_from_file(tmp_path):
    sgai_dir = tmp_path / ".sgai"
    sgai_dir.mkdir()
    (sgai_dir / "policy.yml").write_text("policies:\n  max-unpatched-cves:\n    max: 7\n")
    policies = load_policies(str(tmp_path))
    assert policies == [Policy("max-unpatched-cves", {"max": 7})]


def test_load_policies_default_when_absent(tmp_path):
    policies = load_policies(str(tmp_path))
    assert policies == [Policy("no-critical-in-production", {"enabled": True})]


def test_load_policies_default_on_malformed(tmp_path):
    sgai_dir = tmp_path / ".sgai"
    sgai_dir.mkdir()
    (sgai_dir / "policy.yml").write_text("{ not: valid: yaml:")
    assert load_policies(str(tmp_path))[0].rule == "no-critical-in-production"


def test_check_convenience(tmp_path):
    result = check([_f("static", Severity.CRITICAL, "app.py:1")], str(tmp_path))
    assert result.passed is False  # default policy catches it


# --------------------------------------------------------------------------- #
# API gate
# --------------------------------------------------------------------------- #
def test_scan_check_passes_clean_code():
    resp = client.post("/scan/check", json={"code": "x = 1\ny = x + 2\n"})
    assert resp.status_code == 200
    assert resp.json()["passed"] is True


def test_scan_check_fails_with_inline_policy():
    resp = client.post("/scan/check", json={
        "code": "import subprocess\nsubprocess.call(cmd, shell=True)\n",
        "policy": "policies:\n  fail-on-severity:\n    severity: low\n",
    })
    body = resp.json()
    assert body["passed"] is False
    assert body["finding_count"] >= 1
    assert "fail-on-severity" in body["evaluated"]


def test_scan_check_rejects_bad_policy_yaml():
    resp = client.post("/scan/check", json={"code": "x = 1\n", "policy": "a: b: c:"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# CLI gate — exit codes for CI
# --------------------------------------------------------------------------- #
def test_cli_check_passes(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert cli_main(["check", str(tmp_path)]) == 0


def test_cli_check_fails_nonzero(tmp_path, monkeypatch):
    # Force a Critical production finding, then confirm the gate returns 1.
    import sgai.cli as cli

    def fake_gather(repo_dir, deep=False):
        async def _co():
            return [_f("static", Severity.CRITICAL, "app.py:1")]
        return _co()

    monkeypatch.setattr(cli, "gather_findings", fake_gather, raising=False)
    monkeypatch.setattr("sgai.runner.gather_findings", fake_gather)
    assert cli_main(["check", str(tmp_path)]) == 1
