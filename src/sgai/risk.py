"""Risk scoring and normalization for SGAI.

Turns the raw output of the security MCP tools into a unified, de-duplicated,
risk-ranked list of :class:`~sgai.models.Finding` objects. This is the
deterministic core the report builder and the LLM agents both consume.

It also performs *dependency reachability analysis*: a static call graph of
first-party imports decides whether a vulnerable package is actually used by
the code. Reachable vulnerabilities get upgraded (they are exploitable today);
unreached ones get downgraded (real, but not on any execution path).
"""

from __future__ import annotations

import ast
from pathlib import Path

from sgai.models import Finding, Severity

# Bandit reports severity as a string; map it to our normalized scale.
_BANDIT_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

# Confidence weights, used only to break ties between equal-severity findings.
_CONFIDENCE_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Semgrep severities map onto our normalized scale.
_SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# Named severities used by the container/IaC scanner.
_NAMED_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

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


def findings_from_semgrep(result: dict) -> list[Finding]:
    """Convert ``run_semgrep`` output into normalized findings (multi-language)."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        check_id = r.get("check_id") or "semgrep"
        severity = _SEMGREP_SEVERITY.get((r.get("severity") or "").upper(), Severity.LOW)
        message = (r.get("message") or check_id).strip()
        findings.append(
            Finding(
                id=check_id,
                source="semgrep",
                title=message[:140],
                severity=severity,
                location=f"{r.get('file', '?')}:{r.get('line', '?')}",
                detail=message,
                remediation="Review and fix the flagged pattern (see the Semgrep rule).",
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
        ecosystem = v.get("ecosystem", "PyPI")
        ids = v.get("vuln_ids", [])
        findings.append(
            Finding(
                id=ids[0] if ids else f"{package}-vuln",
                source="dependency",
                title=f"{package} {version} ({ecosystem}) has {len(ids)} known vulnerabilit"
                + ("y" if len(ids) == 1 else "ies"),
                severity=Severity.HIGH,
                location=f"{ecosystem}:{package}@{version}",
                detail="Advisories: " + ", ".join(ids),
                remediation=f"Upgrade {package} to a patched version; review {ids[0] if ids else 'the advisories'}.",
                references=ids,
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Dependency reachability
# --------------------------------------------------------------------------- #

# Directories that never hold first-party source.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".uv"}

# PyPI distribution names whose import name differs beyond simple normalization.
_PACKAGE_MODULE_ALIASES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "msgpack-python": "msgpack",
    "attrs": "attr",
    "setuptools": "pkg_resources",
}


def build_import_graph(repo_dir: str) -> dict[str, set[str]]:
    """Static call graph of first-party imports: file → top-level modules it imports.

    Every ``.py`` file under ``repo_dir`` (excluding vendored/venv dirs) is
    parsed with :mod:`ast`; ``import x.y`` and ``from x.y import z`` both
    contribute the top-level name ``x``. Files that don't parse are skipped —
    reachability must never crash a scan.
    """
    root = Path(repo_dir).resolve()
    graph: dict[str, set[str]] = {}
    for py in sorted(root.rglob("*.py")):
        if _SKIP_DIRS & set(py.parts):
            continue
        try:
            tree = ast.parse(py.read_text())
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module.split(".")[0])
        if modules:
            graph[str(py.relative_to(root))] = modules
    return graph


def _module_candidates(package: str) -> set[str]:
    """Import names a PyPI distribution plausibly installs under."""
    lowered = package.lower()
    candidates = {lowered, lowered.replace("-", "_")}
    if lowered in _PACKAGE_MODULE_ALIASES:
        candidates.add(_PACKAGE_MODULE_ALIASES[lowered].lower())
    return candidates


def apply_reachability(findings: list[Finding], graph: dict[str, set[str]]) -> list[Finding]:
    """Adjust dependency findings by whether their package is actually imported.

    A vulnerable package that first-party code imports is *reachable*: its
    severity is upgraded one level (an attacker can hit the vulnerable code
    path today). One that is never imported is downgraded one level — the CVE
    is real, but it sits in an unused dependency. Only PyPI findings are
    adjusted; the import graph says nothing about npm/Go/Rust packages.

    Returns the findings re-scored and re-ranked.
    """
    imported = {m.lower() for modules in graph.values() for m in modules}
    for f in findings:
        if f.source != "dependency":
            continue
        ecosystem, _, rest = f.location.partition(":")
        if ecosystem != "PyPI":
            continue
        package = rest.partition("@")[0]
        f.reachable = bool(_module_candidates(package) & imported)
        if f.reachable:
            f.severity = Severity(min(int(f.severity) + 1, int(Severity.CRITICAL)))
            f.confidence = "HIGH"
            f.detail = (f.detail + " " if f.detail else "") + (
                "Reachability: first-party code imports this package — "
                "the vulnerable code is on an execution path."
            )
        else:
            f.severity = Severity(max(int(f.severity) - 1, int(Severity.LOW)))
            f.confidence = "LOW"
            f.detail = (f.detail + " " if f.detail else "") + (
                "Reachability: no first-party import of this package found — "
                "likely an unused dependency (still worth removing or upgrading)."
            )
    return score_findings(findings)


def findings_from_container_scan(result: dict, location_file: str) -> list[Finding]:
    """Convert ``scan_dockerfile`` output into normalized findings."""
    findings: list[Finding] = []
    for r in result.get("findings", []):
        severity = _NAMED_SEVERITY.get((r.get("severity") or "").upper(), Severity.MEDIUM)
        findings.append(
            Finding(
                id=r.get("check_id", "SGAI-CONTAINER"),
                source="container",
                title=r.get("title", "Container misconfiguration"),
                severity=severity,
                location=f"{location_file}:{r.get('line', '?')}",
                detail=r.get("detail", ""),
                remediation=r.get("remediation", "Review the flagged configuration."),
            )
        )
    return findings


def findings_from_secret_scan(result: dict) -> list[Finding]:
    """Convert ``scan_secrets`` output into normalized findings (always HIGH).

    A live credential in source is directly exploitable, so leaked secrets floor
    at HIGH regardless of which detector caught them.
    """
    findings: list[Finding] = []
    for r in result.get("findings", []):
        entropy = r.get("entropy")
        detail = r.get("title", "Potential secret")
        if entropy is not None:
            detail += f" (masked: {r.get('match', '****')}, entropy {entropy})"
        findings.append(
            Finding(
                id=r.get("check_id", "SGAI-SECRET"),
                source="secret",
                title=r.get("title", "Potential leaked secret"),
                severity=Severity.HIGH,
                location=f"{r.get('file', '?')}:{r.get('line', '?')}",
                detail=detail,
                remediation=(
                    "Remove the secret from source, rotate it immediately, and load it "
                    "from an environment variable or secrets manager."
                ),
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


def assess(
    dependency_result: dict,
    static_result: dict,
    semgrep_result: dict | None = None,
    extra: list[Finding] | None = None,
) -> list[Finding]:
    """Full deterministic assessment: normalize, de-duplicate, and rank.

    Args:
        dependency_result: Output of the MCP ``scan_manifest`` tool.
        static_result: Output of the MCP ``run_static_analysis`` tool.
        semgrep_result: Optional output of the MCP ``run_semgrep`` tool.
        extra: Already-normalized findings from other scanners (container/IaC
            misconfigurations, leaked secrets) to fold into the same ranking.

    Returns:
        Risk-ranked, de-duplicated findings (highest risk first).
    """
    findings = findings_from_dependency_scan(dependency_result)
    findings += findings_from_static_analysis(static_result)
    if semgrep_result:
        findings += findings_from_semgrep(semgrep_result)
    if extra:
        findings += extra
    return score_findings(deduplicate(findings))
