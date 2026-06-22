"""Risk scoring and normalization for SGAI.

Turns the raw output of the security MCP tools into a unified, de-duplicated,
risk-ranked list of :class:`~sgai.models.Finding` objects. This is the
deterministic core the report builder and the LLM agents both consume.
"""

from __future__ import annotations

from sgai.models import Finding, Severity

# Bandit reports severity as a string; map it to our normalized scale.
_BANDIT_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

# Confidence weights, used only to break ties between equal-severity findings.
_CONFIDENCE_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Concise remediation guidance for the Bandit tests our example surface triggers.
# Extend as coverage grows; unmapped tests fall back to the issue text.
_STATIC_REMEDIATION = {
    "B602": "Avoid shell=True; pass arguments as a list to subprocess.",
    "B307": "Replace eval() with ast.literal_eval() or an explicit parser.",
    "B506": "Use yaml.safe_load() instead of yaml.load().",
    "B105": "Move secrets to environment variables or a secrets manager.",
    "B101": "Do not rely on assert for security checks; raise explicitly.",
    "B404": "Review subprocess usage; ensure inputs are validated.",
}


def findings_from_static_analysis(result: dict) -> list[Finding]:
    """Convert ``run_static_analysis`` output into normalized findings."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        test_id = r.get("test_id", "?")
        severity = _BANDIT_SEVERITY.get((r.get("severity") or "").upper(), Severity.UNKNOWN)
        location = f"{r.get('file', '?')}:{r.get('line', '?')}"
        findings.append(
            Finding(
                id=test_id,
                source="static",
                title=r.get("issue", "Static analysis finding"),
                severity=severity,
                location=location,
                detail=r.get("issue", ""),
                remediation=_STATIC_REMEDIATION.get(test_id, "Review and remediate the flagged pattern."),
                confidence=(r.get("confidence") or "").upper(),
            )
        )
    return findings


def findings_from_dependency_scan(result: dict) -> list[Finding]:
    """Convert ``scan_requirements_file`` output into normalized findings.

    The batch OSV query returns advisory IDs without CVSS, so a known CVE in a
    pinned dependency is treated as HIGH by default — a defensible floor, since
    an unpatched, publicly disclosed vulnerability is shipping in the build.
    """
    findings: list[Finding] = []
    for v in result.get("vulnerable", []):
        package, version = v.get("package", "?"), v.get("version", "?")
        ids = v.get("vuln_ids", [])
        findings.append(
            Finding(
                id=ids[0] if ids else f"{package}-vuln",
                source="dependency",
                title=f"{package} {version} has {len(ids)} known vulnerabilit"
                + ("y" if len(ids) == 1 else "ies"),
                severity=Severity.HIGH,
                location=f"{package}=={version}",
                detail="Advisories: " + ", ".join(ids),
                remediation=f"Upgrade {package} to a patched version; review {ids[0] if ids else 'the advisories'}.",
                references=ids,
            )
        )
    return findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Drop duplicate findings, keeping the highest-severity instance.

    Two findings are duplicates when they share an id and a location.
    """
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.id, f.location)
        if key not in best or f.severity > best[key].severity:
            best[key] = f
    return list(best.values())


def score_findings(findings: list[Finding]) -> list[Finding]:
    """Assign a risk score to each finding and return them ranked, highest first.

    The score is ``severity * 10`` plus a small confidence weight, so severity
    dominates while confidence breaks ties between equal-severity findings.
    """
    for f in findings:
        f.risk_score = int(f.severity) * 10 + _CONFIDENCE_WEIGHT.get(f.confidence, 0)
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings by severity (only severities that appear)."""
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[0], reverse=True))


def assess(dependency_result: dict, static_result: dict) -> list[Finding]:
    """Full deterministic assessment: normalize, de-duplicate, and rank.

    Args:
        dependency_result: Output of the MCP ``scan_requirements_file`` tool.
        static_result: Output of the MCP ``run_static_analysis`` tool.

    Returns:
        Risk-ranked, de-duplicated findings (highest risk first).
    """
    findings = findings_from_dependency_scan(dependency_result)
    findings += findings_from_static_analysis(static_result)
    return score_findings(deduplicate(findings))
