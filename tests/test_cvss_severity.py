"""Tests for CVSS-based dependency severity mapping.

The OSV batch query only returns advisory IDs; the scanner enriches each
package with a severity derived from the full OSV records (CVSS vector when
present, the database's own label otherwise). These tests cover the derivation
and how the risk normalizer consumes it — no network involved.
"""

from sgai.models import Severity
from sgai.mcp_server.server import _worst_advisory_severity, severity_from_osv_record
from sgai.risk import findings_from_dependency_scan


def test_cvss_v3_vector_maps_to_qualitative_bands():
    critical = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert severity_from_osv_record(critical) == ("CRITICAL", 9.8)

    medium = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}
    label, score = severity_from_osv_record(medium)
    assert label == "MEDIUM"
    assert 4.0 <= score < 7.0


def test_cvss_v4_preferred_over_v3():
    record = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        ]
    }
    assert severity_from_osv_record(record) == ("CRITICAL", 9.3)


def test_database_label_fallback_maps_moderate_to_medium():
    record = {"severity": [], "database_specific": {"severity": "MODERATE"}}
    assert severity_from_osv_record(record) == ("MEDIUM", None)


def test_unparseable_vector_falls_back_to_label():
    record = {
        "severity": [{"type": "CVSS_V3", "score": "not-a-vector"}],
        "database_specific": {"severity": "LOW"},
    }
    assert severity_from_osv_record(record) == ("LOW", None)


def test_no_severity_signal_yields_none():
    assert severity_from_osv_record({}) == (None, None)


def test_worst_advisory_wins_and_keeps_max_score():
    severity_map = {
        "GHSA-low": ("LOW", 2.1),
        "GHSA-high-a": ("HIGH", 7.5),
        "GHSA-high-b": ("HIGH", 8.2),
        "GHSA-unknown": (None, None),
    }
    label, score = _worst_advisory_severity(
        ["GHSA-low", "GHSA-high-a", "GHSA-high-b", "GHSA-unknown"], severity_map
    )
    assert label == "HIGH"
    assert score == 8.2


def test_dependency_finding_uses_enriched_severity():
    result = {
        "vulnerable": [
            {
                "package": "requests",
                "version": "2.19.0",
                "vuln_ids": ["GHSA-x84v-xcm2-53pg"],
                "severity": "MEDIUM",
                "cvss_score": 5.9,
            }
        ]
    }
    findings = findings_from_dependency_scan(result)
    assert findings[0].severity == Severity.MEDIUM
    assert "CVSS 5.9" in findings[0].detail


def test_dependency_finding_without_enrichment_defaults_high():
    result = {"vulnerable": [{"package": "left", "version": "1.0", "vuln_ids": ["PYSEC-0"]}]}
    findings = findings_from_dependency_scan(result)
    assert findings[0].severity == Severity.HIGH
