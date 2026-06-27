"""Tests for SGAI's Sessions & Memory layer."""

from types import SimpleNamespace

import pytest

from sgai.memory import ScanMemory, fingerprint
from sgai.models import Finding, Severity
from sgai.report import build_markdown_report


def _f(id: str, location: str, severity: Severity = Severity.HIGH, source: str = "dependency") -> Finding:
    return Finding(id=id, source=source, title=f"{id} issue", severity=severity, location=location)


@pytest.fixture
def mem(tmp_path):
    return ScanMemory(path=tmp_path / "memory.json")


def test_fingerprint_is_stable_and_distinct():
    a = _f("CVE-1", "PyPI:jinja2@2.11.2")
    b = _f("CVE-1", "PyPI:jinja2@2.11.2")
    c = _f("CVE-1", "PyPI:jinja2@3.0.0")  # upgraded version -> different identity
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(c)


def test_first_scan_is_baseline(mem):
    diff = mem.diff("repo", [_f("CVE-1", "PyPI:jinja2@2.11.2")])
    assert diff.is_first_scan
    assert diff.new == [] and diff.resolved == []  # nothing to compare against yet


def test_diff_detects_new_resolved_and_persisting(mem):
    first = [_f("CVE-1", "PyPI:jinja2@2.11.2"), _f("CVE-2", "PyPI:flask@1.0")]
    mem.diff("repo", first)
    mem.record("repo", first)

    # jinja2 fixed (gone), flask still there, requests newly vulnerable.
    second = [_f("CVE-2", "PyPI:flask@1.0"), _f("CVE-3", "PyPI:requests@2.0")]
    diff = mem.diff("repo", second)

    assert not diff.is_first_scan
    assert {f.id for f in diff.new} == {"CVE-3"}
    assert {f.id for f in diff.persisting} == {"CVE-2"}
    assert {m["id"] for m in diff.resolved} == {"CVE-1"}
    assert diff.has_changes


def test_accepted_risk_is_not_reported_as_new(mem):
    base = [_f("CVE-0", "PyPI:base@1")]
    mem.record("repo", base)  # baseline that does NOT contain CVE-1

    finding = _f("CVE-1", "PyPI:jinja2@2.11.2")
    mem.accept("repo", fingerprint(finding), reason="patch scheduled Q3")

    # CVE-1 is genuinely new vs. the baseline, but it's accepted -> not flagged.
    diff = mem.diff("repo", base + [finding])
    assert "CVE-1" not in {f.id for f in diff.new}
    assert len(diff.accepted) == 1
    assert mem.accepted("repo")[fingerprint(finding)]["reason"] == "patch scheduled Q3"

    # Removing the acceptance makes it surface as new again.
    assert mem.unaccept("repo", fingerprint(finding)) is True
    assert "CVE-1" in {f.id for f in mem.diff("repo", base + [finding]).new}


def test_persistence_round_trip(tmp_path):
    path = tmp_path / "memory.json"
    findings = [_f("CVE-1", "PyPI:jinja2@2.11.2")]
    ScanMemory(path=path).record("repo", findings)

    reopened = ScanMemory(path=path)  # fresh instance, same file
    assert len(reopened.history("repo")) == 1
    assert reopened.last_snapshot("repo").top_severity == "High"
    # A second process sees the prior scan and diffs against it.
    diff = reopened.diff("repo", [])
    assert {m["id"] for m in diff.resolved} == {"CVE-1"}


def test_history_and_forget(mem):
    mem.record("repo", [_f("CVE-1", "PyPI:a@1")])
    mem.record("repo", [_f("CVE-1", "PyPI:a@1"), _f("CVE-2", "PyPI:b@1")])
    assert len(mem.history("repo")) == 2
    assert mem.forget("repo") is True
    assert mem.history("repo") == []


def test_report_includes_changes_section(mem):
    first = [_f("CVE-1", "PyPI:jinja2@2.11.2")]
    mem.record("repo", first)
    second = [_f("CVE-2", "PyPI:requests@2.0")]
    diff = mem.diff("repo", second)

    md = build_markdown_report("repo", second, diff=diff)
    assert "## Changes since last scan" in md
    assert "New:** 1" in md
    assert "Fixed:** 1" in md


def test_report_first_scan_section(mem):
    findings = [_f("CVE-1", "PyPI:jinja2@2.11.2")]
    diff = mem.diff("repo", findings)
    md = build_markdown_report("repo", findings, diff=diff)
    assert "First recorded scan" in md


async def test_adk_memory_service_add_and_search(tmp_path):
    from google.genai import types

    from sgai.memory import SgaiMemoryService

    svc = SgaiMemoryService(path=tmp_path / "adk_memory.json")
    event = SimpleNamespace(
        author="report_writer_agent",
        content=types.Content(role="model", parts=[types.Part(text="jinja2 is vulnerable")]),
    )
    session = SimpleNamespace(app_name="sgai", user_id="user", events=[event])

    await svc.add_session_to_memory(session)
    hit = await svc.search_memory(app_name="sgai", user_id="user", query="jinja2")
    assert hit.memories and "jinja2" in hit.memories[0].content.parts[0].text

    miss = await svc.search_memory(app_name="sgai", user_id="user", query="kubernetes")
    assert miss.memories == []

    # Persisted to disk: a fresh instance still finds it.
    reopened = SgaiMemoryService(path=tmp_path / "adk_memory.json")
    again = await reopened.search_memory(app_name="sgai", user_id="user", query="jinja2")
    assert again.memories
