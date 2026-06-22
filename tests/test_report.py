"""Tests for Markdown report generation."""

from sgai.models import Finding, Severity
from sgai.report import build_markdown_report


def test_empty_report_says_clean():
    md = build_markdown_report("examples/app", [])
    assert "No vulnerabilities found" in md
    assert "examples/app" in md


def test_report_contains_summary_and_findings():
    findings = [
        Finding(
            id="B602",
            source="static",
            title="subprocess with shell=True",
            severity=Severity.HIGH,
            location="app.py:18",
            detail="shell injection risk",
            remediation="Pass args as a list.",
        ),
        Finding(
            id="GHSA-aaaa",
            source="dependency",
            title="jinja2 2.11.2 has 2 known vulnerabilities",
            severity=Severity.HIGH,
            location="jinja2==2.11.2",
            remediation="Upgrade jinja2.",
            references=["GHSA-aaaa", "GHSA-bbbb"],
        ),
    ]
    md = build_markdown_report("examples/app", findings)
    assert "## Summary" in md
    assert "## Findings" in md
    assert "## Remediation" in md
    assert "app.py:18" in md
    assert "jinja2==2.11.2" in md
    assert "GHSA-bbbb" in md  # advisory references rendered
    assert "Total findings:** 2" in md


def test_pipe_in_title_is_escaped():
    findings = [
        Finding(id="X", source="static", title="a | b", severity=Severity.LOW, location="f.py:1"),
    ]
    md = build_markdown_report("t", findings)
    assert "a \\| b" in md
