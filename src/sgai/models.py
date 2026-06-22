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
    """Normalized severity. Ordered so findings sort by importance."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

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
