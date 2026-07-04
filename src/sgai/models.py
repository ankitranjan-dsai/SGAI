"""Shared data models for SGAI findings.

A *finding* is one security issue, whether it came from the dependency auditor
(a CVE in a pinned package) or the static analyzer (an unsafe code pattern).
Both are normalized into the same :class:`Finding` shape so risk scoring and
reporting can treat them uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Normalized severity. Ordered so findings sort by importance.

    ``INFO`` marks findings that are real matches but carry no production risk
    (e.g. a credential-shaped string inside a test fixture).
    """

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    """One normalized security finding."""

    id: str
    source: str  # "dependency" or "static"
    title: str
    severity: Severity
    location: str  # e.g. "jinja2==2.11.2" or "app.py:18"
    detail: str = ""
    remediation: str = ""
    confidence: str = ""  # static-analysis confidence, when available
    references: list[str] = field(default_factory=list)
    risk_score: int = 0
    # Dependency reachability: True when first-party code imports the vulnerable
    # package, False when it provably doesn't, None when not analyzed. The bool
    # is kept for back-compat; ``reachability`` carries the finer distinction.
    reachable: bool | None = None
    # Finer-grained reachability: "production" (imported by shipping code),
    # "test_only" (imported only by test/fixture code), "unreached" (never
    # imported), or None when not analyzed.
    reachability: str | None = None
    # Secret findings only: how urgently the credential must be rotated
    # ("immediate", "high", "medium", "low"); None for non-secret findings.
    rotation_urgency: str | None = None
    # True when the finding sits in an internet-facing file (an API route,
    # handler, or entry point) — an attacker can reach it without a foothold.
    internet_facing: bool = False
    # Dependency findings only: repo-relative path of the manifest that pins
    # the vulnerable package (e.g. "requirements.txt"). A pin that lives only
    # in a test/example manifest is not part of the production dependency set.
    manifest: str = ""
