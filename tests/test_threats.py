"""Tests for exploit-chain threat modeling (offline)."""

from sgai.models import Finding, Severity
from sgai.threats import (
    capabilities_of,
    detect_exploit_chains,
    render_threat_section,
)


def _static(test_id: str, title: str, line: int, severity=Severity.HIGH) -> Finding:
    return Finding(
        id=test_id, source="static", title=title, severity=severity, location=f"app.py:{line}"
    )


def test_capabilities_from_bandit_ids():
    assert "code_execution" in capabilities_of(_static("B307", "eval used", 1))
    assert "secret_exposure" in capabilities_of(_static("B105", "hardcoded password", 1))
    assert "command_injection" in capabilities_of(_static("B602", "shell=True", 1))


def test_capabilities_from_keywords():
    f = Finding(
        id="python.lang.security.path-traversal",
        source="semgrep",
        title="Potential path traversal via os.path.join",
        severity=Severity.HIGH,
        location="views.py:20",
    )
    assert "path_traversal" in capabilities_of(f)


def test_path_traversal_plus_secret_forms_chain():
    traversal = Finding(
        id="path-traversal", source="semgrep", title="Path traversal in file read",
        severity=Severity.HIGH, location="views.py:20",
    )
    secret = _static("B105", "Hardcoded API key", 5)

    chains = detect_exploit_chains([traversal, secret])

    names = [c.name for c in chains]
    assert "Path traversal → credential disclosure" in names
    chain = next(c for c in chains if c.name == "Path traversal → credential disclosure")
    assert len(chain.findings) == 2
    # Chain severity is bumped above its worst link.
    assert chain.severity == Severity.CRITICAL


def test_code_exec_plus_secret_chain():
    chains = detect_exploit_chains([
        _static("B307", "eval of user input", 11),
        _static("B105", "hardcoded secret", 5),
    ])
    assert any(c.name == "Arbitrary code execution → credential exfiltration" for c in chains)


def test_single_finding_forms_no_chain():
    # One finding can't be a chain — chains require >= 2 distinct links.
    assert detect_exploit_chains([_static("B105", "hardcoded secret", 5)]) == []


def test_reachable_dependency_plus_code_exec_chain():
    dep = Finding(
        id="GHSA-xxxx", source="dependency", title="jinja2 has known vulnerabilities",
        severity=Severity.CRITICAL, location="PyPI:jinja2@2.11.2", reachable=True,
    )
    chains = detect_exploit_chains([dep, _static("B602", "subprocess shell=True", 9)])
    assert any(c.name == "Reachable vulnerable dependency → code execution" for c in chains)


def test_distinct_findings_required_per_slot():
    # A single hardcoded-secret finding cannot fill two secret slots; with only
    # one finding present, no two-slot chain should match.
    chains = detect_exploit_chains([_static("B105", "hardcoded secret", 5)])
    assert chains == []


def test_mermaid_output_is_wellformed():
    chains = detect_exploit_chains([
        _static("B307", 'eval("payload") of user input', 11),
        _static("B105", 'API_KEY = "abc"  # [secret]', 5),
    ])
    assert chains
    mermaid = chains[0].mermaid()
    assert mermaid.startswith("graph LR")
    assert "attacker([" in mermaid
    assert "impact[[" in mermaid
    assert mermaid.count("-->") == len(chains[0].findings) + 1
    # Mermaid-breaking characters must be stripped from labels.
    for bad in ['"payload"', "[secret]", "eval("]:
        assert bad not in mermaid


def test_render_threat_section_has_mermaid_fence():
    chains = detect_exploit_chains([
        _static("path-traversal", "path traversal", 20),
        _static("B105", "hardcoded secret", 5),
    ])
    md = "\n".join(render_threat_section(chains))
    assert "## Threat Model & Exploit Chains" in md
    assert "```mermaid" in md
    assert "```" in md.split("```mermaid", 1)[1]  # fence is closed


def test_render_empty_when_no_chains():
    assert render_threat_section([]) == []


def test_report_includes_threat_section():
    from sgai.report import build_markdown_report

    findings = [
        _static("path-traversal", "path traversal in download", 20),
        _static("B105", "Hardcoded API password", 5),
    ]
    report = build_markdown_report("demo", findings)
    assert "Threat Model & Exploit Chains" in report
    assert "```mermaid" in report
