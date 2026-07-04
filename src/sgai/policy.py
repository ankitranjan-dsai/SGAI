"""Policy-as-Code engine for SGAI — CI/CD security gates.

A *policy* is a declarative rule that a scan's findings must satisfy for a build
to pass. Policies live in ``.sgai/policy.yml`` at the repo root and are checked
deterministically (no LLM) against the same normalized :class:`~sgai.models.Finding`
list every other SGAI feature consumes. The engine returns structured
violations; the CLI (``sgai check``) turns a non-empty violation set into a
non-zero exit code so it can gate a CI merge.

Example ``.sgai/policy.yml``::

    policies:
      no-critical-in-production:
        enabled: true
      max-unpatched-cves:
        max: 5
      fail-on-severity:
        severity: high
      no-secrets:
        enabled: true

When the file is absent, a conservative default policy applies: no Critical
finding on a production (non-test) file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sgai.models import Finding, Severity
from sgai.risk import is_test_file

POLICY_RELPATH = Path(".sgai") / "policy.yml"

_SEVERITY_BY_NAME = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass(frozen=True)
class Policy:
    """One configured policy: a rule id plus its options."""

    rule: str
    options: dict = field(default_factory=dict)


@dataclass
class Violation:
    """A single policy failure, JSON-friendly for the API and CI logs."""

    policy: str
    message: str
    findings: list[str] = field(default_factory=list)  # offending locations

    def to_dict(self) -> dict:
        return {"policy": self.policy, "message": self.message, "findings": self.findings}


@dataclass
class PolicyResult:
    """The outcome of evaluating every policy against a finding set."""

    passed: bool
    violations: list[Violation] = field(default_factory=list)
    evaluated: list[str] = field(default_factory=list)  # policy rule ids that ran

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "evaluated": self.evaluated,
        }


# The default policy applied when no .sgai/policy.yml is present.
_DEFAULT_POLICIES = [Policy("no-critical-in-production", {"enabled": True})]


def _is_production_code(finding: Finding) -> bool:
    """A code finding on a non-test source file (dependency findings excluded)."""
    if ":" not in finding.location:
        return False
    file = finding.location.rsplit(":", 1)[0]
    return not is_test_file(file)


# --------------------------------------------------------------------------- #
# Built-in policy evaluators. Each returns a Violation or None.
# --------------------------------------------------------------------------- #
def _p_no_critical_in_production(opts: dict, findings: list[Finding]) -> Violation | None:
    if opts.get("enabled") is False:
        return None
    offenders = [
        f.location
        for f in findings
        if f.severity >= Severity.CRITICAL and _is_production_code(f)
    ]
    if offenders:
        return Violation(
            "no-critical-in-production",
            f"{len(offenders)} Critical finding(s) on production code paths.",
            offenders,
        )
    return None


def _p_max_unpatched_cves(opts: dict, findings: list[Finding]) -> Violation | None:
    limit = int(opts.get("max", 0))
    cves = [f for f in findings if f.source == "dependency"]
    # Optionally restrict the count to reachable dependencies only.
    if opts.get("reachable_only"):
        cves = [f for f in cves if f.reachable]
    if len(cves) > limit:
        return Violation(
            "max-unpatched-cves",
            f"{len(cves)} unpatched dependency vulnerabilit"
            f"{'y' if len(cves) == 1 else 'ies'} exceed the limit of {limit}.",
            [f.location for f in cves],
        )
    return None


def _p_fail_on_severity(opts: dict, findings: list[Finding]) -> Violation | None:
    threshold = _SEVERITY_BY_NAME.get(str(opts.get("severity", "high")).lower())
    if threshold is None:
        return None
    offenders = [f.location for f in findings if f.severity >= threshold]
    if offenders:
        return Violation(
            "fail-on-severity",
            f"{len(offenders)} finding(s) at or above {threshold.label} severity.",
            offenders,
        )
    return None


def _p_no_secrets(opts: dict, findings: list[Finding]) -> Violation | None:
    if opts.get("enabled") is False:
        return None
    # By default only production secrets (HIGH+); test-fixture secrets are Info.
    floor = _SEVERITY_BY_NAME.get(str(opts.get("min_severity", "high")).lower(), Severity.HIGH)
    offenders = [f.location for f in findings if f.source == "secret" and f.severity >= floor]
    if offenders:
        return Violation(
            "no-secrets",
            f"{len(offenders)} leaked secret(s) at or above {floor.label} severity.",
            offenders,
        )
    return None


def _p_max_total_findings(opts: dict, findings: list[Finding]) -> Violation | None:
    limit = int(opts.get("max", 0))
    if len(findings) > limit:
        return Violation(
            "max-total-findings",
            f"{len(findings)} total findings exceed the limit of {limit}.",
            [f.location for f in findings],
        )
    return None


_EVALUATORS = {
    "no-critical-in-production": _p_no_critical_in_production,
    "max-unpatched-cves": _p_max_unpatched_cves,
    "fail-on-severity": _p_fail_on_severity,
    "no-secrets": _p_no_secrets,
    "max-total-findings": _p_max_total_findings,
}


def parse_policies(data: dict) -> list[Policy]:
    """Turn parsed ``policy.yml`` data into a list of :class:`Policy`.

    Accepts either a mapping (``{rule: options}``) or a list of
    ``{rule: ..., ...opts}`` entries under a top-level ``policies`` key.
    Unknown rule ids are dropped so a typo can't silently pass everything.
    """
    raw = (data or {}).get("policies", data or {})
    policies: list[Policy] = []
    if isinstance(raw, dict):
        for rule, opts in raw.items():
            if rule in _EVALUATORS:
                policies.append(Policy(rule, opts if isinstance(opts, dict) else {}))
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            rule = entry.get("rule") or entry.get("id")
            if rule in _EVALUATORS:
                opts = {k: v for k, v in entry.items() if k not in ("rule", "id")}
                policies.append(Policy(rule, opts))
    return policies


def load_policies(repo_dir: str) -> list[Policy]:
    """Load policies from ``<repo_dir>/.sgai/policy.yml``.

    Returns the built-in default policy set when the file is missing or
    unparseable — a broken policy file must never silently disable the gate.
    """
    path = Path(repo_dir) / POLICY_RELPATH
    if not path.is_file():
        return list(_DEFAULT_POLICIES)
    try:
        import yaml

        data = yaml.safe_load(path.read_text()) or {}
    except Exception:  # noqa: BLE001 — malformed YAML falls back to defaults
        return list(_DEFAULT_POLICIES)
    policies = parse_policies(data)
    return policies or list(_DEFAULT_POLICIES)


def evaluate_policies(findings: list[Finding], policies: list[Policy]) -> PolicyResult:
    """Check ``findings`` against every configured policy."""
    violations: list[Violation] = []
    evaluated: list[str] = []
    for policy in policies:
        evaluator = _EVALUATORS.get(policy.rule)
        if evaluator is None:
            continue
        evaluated.append(policy.rule)
        violation = evaluator(policy.options, findings)
        if violation is not None:
            violations.append(violation)
    return PolicyResult(passed=not violations, violations=violations, evaluated=evaluated)


def check(findings: list[Finding], repo_dir: str) -> PolicyResult:
    """Convenience: load a repo's policies and evaluate its findings."""
    return evaluate_policies(findings, load_policies(repo_dir))
