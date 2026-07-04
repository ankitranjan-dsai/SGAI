"""Phase 9: false-positive dismissals — storage, suppression, endpoints."""

from fastapi.testclient import TestClient

from sgai.api import app
from sgai.memory import ScanMemory, fingerprint
from sgai.models import Finding, Severity
from sgai.risk import is_finding_dismissed, suppress_dismissed

client = TestClient(app)


def _f(source, id, location, sev=Severity.HIGH):
    return Finding(id=id, source=source, title="t", severity=sev, location=location)


# --------------------------------------------------------------------------- #
# ScanMemory dismissal storage
# --------------------------------------------------------------------------- #
def test_dismiss_by_fingerprint(tmp_path):
    mem = ScanMemory(path=tmp_path / "m.json")
    f = _f("static", "B307", "app.py:3")
    fp = mem.dismiss("t", finding_fp=fingerprint(f), reason="test-only path")
    assert fp == fingerprint(f)
    assert fingerprint(f) in mem.dismissals("t")["fingerprints"]
    # Persisted across instances.
    assert fingerprint(f) in ScanMemory(path=tmp_path / "m.json").dismissals("t")["fingerprints"]


def test_dismiss_by_pattern(tmp_path):
    mem = ScanMemory(path=tmp_path / "m.json")
    pid = mem.dismiss("t", pattern={"finding_id": "B101", "location_glob": "tests/*"})
    patterns = mem.dismissals("t")["patterns"]
    assert len(patterns) == 1
    assert patterns[0]["id"] == pid


def test_dismiss_pattern_dedupes(tmp_path):
    mem = ScanMemory(path=tmp_path / "m.json")
    mem.dismiss("t", pattern={"finding_id": "B101"})
    mem.dismiss("t", pattern={"finding_id": "B101"})
    assert len(mem.dismissals("t")["patterns"]) == 1


def test_undismiss(tmp_path):
    mem = ScanMemory(path=tmp_path / "m.json")
    f = _f("static", "B307", "app.py:3")
    mem.dismiss("t", finding_fp=fingerprint(f))
    assert mem.undismiss("t", finding_fp=fingerprint(f)) is True
    assert mem.undismiss("t", finding_fp=fingerprint(f)) is False
    assert mem.dismissals("t")["fingerprints"] == {}


def test_dismiss_requires_input(tmp_path):
    mem = ScanMemory(path=tmp_path / "m.json")
    try:
        mem.dismiss("t")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_dismissals_do_not_disturb_fingerprint_format(tmp_path):
    """The source:id:location diff format is unchanged by dismissal storage."""
    mem = ScanMemory(path=tmp_path / "m.json")
    f = _f("static", "B307", "app.py:3")
    mem.record("t", [f])
    mem.dismiss("t", finding_fp=fingerprint(f))
    snap = mem.last_snapshot("t")
    assert fingerprint(f) == "static:B307:app.py:3"
    assert fingerprint(f) in snap.findings


# --------------------------------------------------------------------------- #
# Suppression in risk.py
# --------------------------------------------------------------------------- #
def test_suppress_by_fingerprint():
    keep = _f("static", "B307", "app.py:3")
    drop = _f("static", "B105", "app.py:9")
    dismissals = {"fingerprints": {"static:B105:app.py:9": {"reason": ""}}, "patterns": []}
    out = suppress_dismissed([keep, drop], dismissals)
    assert out == [keep]


def test_suppress_by_pattern_id_and_source():
    a = _f("secret", "aws-key", "tests/conf.py:1")
    b = _f("secret", "aws-key", "app.py:1")
    dismissals = {"fingerprints": {}, "patterns": [
        {"id": "p1", "source": "secret", "location_glob": "tests/*"}
    ]}
    out = suppress_dismissed([a, b], dismissals)
    assert out == [b]  # only the tests/ one is suppressed


def test_suppress_by_finding_id_glob():
    a = _f("static", "B101", "x/test_a.py:1")
    b = _f("static", "B101", "src/app.py:1")
    dismissals = {"fingerprints": {}, "patterns": [
        {"id": "p", "finding_id": "B101", "location_glob": "*test*"}
    ]}
    assert suppress_dismissed([a, b], dismissals) == [b]


def test_empty_dismissals_no_op():
    findings = [_f("static", "B307", "app.py:3")]
    assert suppress_dismissed(findings, {"fingerprints": {}, "patterns": []}) == findings
    assert suppress_dismissed(findings, {}) == findings


def test_is_finding_dismissed_pattern_requires_all_keys():
    f = _f("static", "B307", "app.py:3")
    # source matches but finding_id doesn't → not dismissed
    d = {"fingerprints": {}, "patterns": [{"source": "static", "finding_id": "B999"}]}
    assert is_finding_dismissed(f, d) is False


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
def test_dismiss_undismiss_endpoints(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")

    d = client.post("/dismiss", json={
        "target": "repo", "fingerprint": "static:B307:app.py:3", "reason": "false positive",
    })
    assert d.status_code == 200
    assert d.json()["dismissed"] == "static:B307:app.py:3"
    assert "static:B307:app.py:3" in d.json()["dismissals"]["fingerprints"]

    u = client.post("/undismiss", json={"target": "repo", "fingerprint": "static:B307:app.py:3"})
    assert u.json()["removed"] is True


def test_dismiss_pattern_endpoint(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")
    resp = client.post("/dismiss", json={
        "target": "repo", "pattern": {"finding_id": "B101", "location_glob": "tests/*"},
    })
    assert resp.status_code == 200
    assert resp.json()["dismissals"]["patterns"][0]["finding_id"] == "B101"


def test_dismiss_requires_input_endpoint():
    assert client.post("/dismiss", json={"target": "repo"}).status_code == 400


def test_dismissal_suppresses_in_run_scan(tmp_path):
    """End-to-end: a dismissed finding is gone from the next scan's results."""
    import asyncio

    from sgai.runner import run_scan, target_key

    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.call(c, shell=True)\n")
    mem = ScanMemory(path=tmp_path / "m.json")
    key = target_key(str(tmp_path), str(tmp_path))

    findings, _report, _diff = asyncio.run(run_scan(str(tmp_path), label=str(tmp_path), memory=mem))
    assert findings, "expected at least one finding before dismissal"
    target_fp = fingerprint(findings[0])

    mem.dismiss(key, finding_fp=target_fp, reason="false positive")
    findings2, _r2, _d2 = asyncio.run(run_scan(str(tmp_path), label=str(tmp_path), memory=mem))
    assert all(fingerprint(f) != target_fp for f in findings2)
