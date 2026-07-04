"""Phase 5: multi-file heal, chat persistence, UI wiring (offline)."""

import re

from fastapi.testclient import TestClient

from sgai.api import app
from sgai.memory import ScanMemory

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Multi-file heal endpoint
# --------------------------------------------------------------------------- #
def test_heal_multi_returns_per_file_patches():
    resp = client.post("/heal/multi", json={"files": {
        "a.py": "import yaml\nd = yaml.load(raw)\n",
        "b.py": "v = eval(expr)\n",
    }})
    assert resp.status_code == 200
    body = resp.json()
    assert body["patch_count"] == 2
    by_path = {f["path"]: f for f in body["files"]}
    assert "yaml.safe_load" in by_path["a.py"]["patched"]
    assert "ast.literal_eval" in by_path["b.py"]["patched"]
    assert by_path["a.py"]["diff"]


def test_heal_multi_clean_files():
    resp = client.post("/heal/multi", json={"files": {"a.py": "x = 1\n"}})
    body = resp.json()
    assert body["patch_count"] == 0
    assert body["files"][0]["patched"] == "x = 1\n"


def test_heal_multi_rejects_sandbox_escape():
    """A path that escapes the sandbox is skipped, not written."""
    resp = client.post("/heal/multi", json={"files": {
        "../evil.py": "import yaml\nyaml.load(x)\n",
        "ok.py": "v = eval(x)\n",
    }})
    body = resp.json()
    paths = {f["path"] for f in body["files"]}
    assert "ok.py" in paths
    assert not any("evil" in p for p in paths)


def test_heal_multi_nested_paths():
    resp = client.post("/heal/multi", json={"files": {
        "src/app.py": "import yaml\nd = yaml.load(r)\n",
    }})
    body = resp.json()
    assert body["files"][0]["path"] == "src/app.py"
    assert "yaml.safe_load" in body["files"][0]["patched"]


# --------------------------------------------------------------------------- #
# Chat session persistence in ScanMemory
# --------------------------------------------------------------------------- #
def test_scanmemory_chat_roundtrip(tmp_path):
    mem = ScanMemory(path=tmp_path / "mem.json")
    mem.append_chat("repo-x", "user", "why is eval unsafe?")
    mem.append_chat("repo-x", "assistant", "it executes arbitrary code")
    session = mem.chat_session("repo-x")
    assert [m["role"] for m in session] == ["user", "assistant"]
    assert all("at" in m for m in session)
    # A fresh instance reads the same persisted transcript.
    assert len(ScanMemory(path=tmp_path / "mem.json").chat_session("repo-x")) == 2


def test_scanmemory_save_and_clear(tmp_path):
    mem = ScanMemory(path=tmp_path / "mem.json")
    mem.save_chat_session("t", [{"role": "user", "content": "hi"}])
    assert len(mem.chat_session("t")) == 1
    assert mem.clear_chat("t") is True
    assert mem.chat_session("t") == []
    assert mem.clear_chat("t") is False  # nothing left to clear


def test_chat_persistence_does_not_disturb_fingerprints(tmp_path):
    """Chat storage must not alter the source:id:location diff format."""
    from sgai.memory import fingerprint
    from sgai.models import Finding, Severity

    mem = ScanMemory(path=tmp_path / "mem.json")
    f = Finding(id="B307", source="static", title="eval", severity=Severity.HIGH,
                location="app.py:3")
    mem.record("t", [f])
    mem.append_chat("t", "user", "hello")
    snap = mem.last_snapshot("t")
    assert fingerprint(f) in snap.findings  # unchanged fingerprint key


def test_chat_session_endpoints(tmp_path, monkeypatch):
    import sgai.memory as memory_mod

    monkeypatch.setattr(memory_mod, "default_memory_path", lambda: tmp_path / "mem.json")

    save = client.post("/chat/session", json={
        "target": "repo-y",
        "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
    })
    assert save.status_code == 200
    assert save.json()["saved"] == 2

    got = client.get("/chat/session", params={"target": "repo-y"})
    assert got.status_code == 200
    assert [m["role"] for m in got.json()["messages"]] == ["user", "assistant"]

    cleared = client.delete("/chat/session", params={"target": "repo-y"})
    assert cleared.json()["cleared"] is True
    assert client.get("/chat/session", params={"target": "repo-y"}).json()["messages"] == []


# --------------------------------------------------------------------------- #
# UI wiring
# --------------------------------------------------------------------------- #
def test_index_has_copilot_wiring():
    html = client.get("/").text
    assert "seedChatFromFinding" in html      # clickable finding → chat
    assert "card clickable" in html
    assert "commit-patch" in html or "/commit-patch" in html
    assert "Commit patch" in html             # commit button label
    assert "multiFile" in html                # multi-file toggle
    assert "loadChatSession" in html          # chat persistence
    assert "/heal/multi" in html              # multi-file endpoint call


def test_index_still_has_three_tabs():
    html = client.get("/").text
    for tab in ("Scan Results", "Code Playground", "Interactive Agent Chat"):
        assert tab in html
