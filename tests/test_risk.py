"""Tests for the deterministic risk-scoring core."""

from sgai.models import Severity
from sgai.risk import (
    assess,
    deduplicate,
    findings_from_dependency_scan,
    findings_from_static_analysis,
    score_findings,
    severity_counts,
)

STATIC_RESULT = {
    "findings": [
        {"test_id": "B602", "issue": "shell=True", "severity": "HIGH", "confidence": "HIGH", "file": "app.py", "line": 18},
        {"test_id": "B101", "issue": "assert used", "severity": "LOW", "confidence": "HIGH", "file": "app.py", "line": 33},
    ]
}

DEP_RESULT = {
    "vulnerable": [
        {"package": "jinja2", "version": "2.11.2", "vuln_ids": ["GHSA-aaaa", "GHSA-bbbb"]},
    ],
    "clean": [],
}


def test_static_findings_normalized():
    findings = findings_from_static_analysis(STATIC_RESULT)
    assert len(findings) == 2
    high = next(f for f in findings if f.id == "B602")
    assert high.severity == Severity.HIGH
    assert high.location == "app.py:18"
    assert "shell=True" in high.remediation


def test_dependency_findings_default_high():
    findings = findings_from_dependency_scan(DEP_RESULT)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].location == "PyPI:jinja2@2.11.2"
    assert findings[0].references == ["GHSA-aaaa", "GHSA-bbbb"]


def test_scoring_orders_high_before_low():
    ranked = score_findings(findings_from_static_analysis(STATIC_RESULT))
    assert ranked[0].severity == Severity.HIGH
    assert ranked[-1].severity == Severity.LOW
    assert ranked[0].risk_score > ranked[-1].risk_score


def test_deduplicate_keeps_highest_severity():
    from sgai.models import Finding

    dupes = [
        Finding(id="B602", source="static", title="x", severity=Severity.LOW, location="app.py:18"),
        Finding(id="B602", source="static", title="x", severity=Severity.HIGH, location="app.py:18"),
    ]
    out = deduplicate(dupes)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_assess_combines_and_ranks():
    findings = assess(DEP_RESULT, STATIC_RESULT)
    assert len(findings) == 3
    # ranked highest-first; first finding outranks the last
    assert findings[0].risk_score >= findings[-1].risk_score
    counts = severity_counts(findings)
    assert counts[Severity.HIGH] == 2  # one dep + one static
