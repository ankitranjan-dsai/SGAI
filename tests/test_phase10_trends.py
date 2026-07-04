"""Phase 10: GET /trends time-series + Trends tab UI wiring."""

from fastapi.testclient import TestClient

from sgai.api import app
from sgai.memory import ScanMemory
from sgai.models import Finding, Severity

client = TestClient(app)


def _f(id, sev, location):
    return Finding(id=id, source="static", title="t", severity=sev, location=location)


def test_trends_lists_targets(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")
    mem = ScanMemory(path=tmp_path / "m.json")
    mem.record("repo-a", [_f("B307", Severity.HIGH, "app.py:1")])
    mem.record("repo-b", [])

    resp = client.get("/trends")
    assert resp.status_code == 200
    assert set(resp.json()["targets"]) == {"repo-a", "repo-b"}


def test_trends_series_for_target(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")
    mem = ScanMemory(path=tmp_path / "m.json")
    mem.record("repo", [
        _f("B307", Severity.CRITICAL, "app.py:1"),
        _f("B105", Severity.HIGH, "app.py:2"),
    ])
    mem.record("repo", [_f("B105", Severity.HIGH, "app.py:2")])  # one fixed

    resp = client.get("/trends", params={"target": "repo"})
    body = resp.json()
    assert body["target"] == "repo"
    assert len(body["points"]) == 2
    assert body["points"][0]["finding_count"] == 2
    assert body["points"][1]["finding_count"] == 1
    # Per-severity breakdown is present for the chart's stacked view.
    assert body["points"][0]["by_severity"].get("Critical") == 1
    assert all("risk_score" in p and "top_severity" in p for p in body["points"])


def test_trends_unknown_target_is_empty(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")
    resp = client.get("/trends", params={"target": "never-scanned"})
    assert resp.json()["points"] == []


def test_trends_points_chronological(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "m.json")
    mem = ScanMemory(path=tmp_path / "m.json")
    for _ in range(3):
        mem.record("repo", [_f("B307", Severity.HIGH, "app.py:1")])
    ats = [p["at"] for p in client.get("/trends", params={"target": "repo"}).json()["points"]]
    assert ats == sorted(ats)


# --------------------------------------------------------------------------- #
# UI wiring
# --------------------------------------------------------------------------- #
def test_index_has_trends_tab():
    html = client.get("/").text
    assert 'data-tab="trends"' in html
    assert "chart.js" in html.lower()          # Chart.js CDN
    assert "loadTrend" in html                 # trend loader
    assert 'id="trendChart"' in html           # canvas


def test_index_has_all_four_tabs():
    html = client.get("/").text
    for tab in ("Scan Results", "Code Playground", "Interactive Agent Chat", "Trends"):
        assert tab in html
