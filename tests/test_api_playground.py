"""Tests for the Code Playground /heal, SSE /chat, and WS /chat/ws endpoints (offline).

These exercise the deterministic paths only — no Gemini key is configured in
tests, so the chat endpoint falls back to SGAI's local patch engine.
"""

import json

from fastapi.testclient import TestClient

from sgai.api import app

client = TestClient(app)

VULN = "import yaml\ndata = yaml.load(raw)\neval(expr)\n"


def test_heal_returns_patches_and_diff():
    resp = client.post("/heal", json={"code": VULN})
    assert resp.status_code == 200
    body = resp.json()
    assert body["original"] == VULN
    assert "yaml.safe_load(raw)" in body["patched"]
    assert "ast.literal_eval(expr)" in body["patched"]
    assert body["diff"]  # a unified diff was produced
    rules = {p["rule"] for p in body["patches"]}
    assert {"B506", "B307"} <= rules


def test_heal_clean_code_no_patches():
    resp = client.post("/heal", json={"code": "x = 1\ny = x + 2\n"})
    body = resp.json()
    assert body["patches"] == []
    assert body["patched"] == "x = 1\ny = x + 2\n"


def test_chat_streams_sse_fallback():
    resp = client.post(
        "/chat", json={"code": VULN, "message": "what would you change?", "history": []}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")

    frames = [f for f in resp.text.split("\n\n") if f.strip()]
    events = [json.loads(f[len("data: "):]) for f in frames if f.startswith("data: ")]
    kinds = [e["event"] for e in events]
    assert kinds[0] == "start"
    assert kinds[-1] == "done"
    assert any(e["event"] == "token" for e in events)

    reply = "".join(e.get("text", "") for e in events if e["event"] == "token")
    assert "safe_load" in reply or "yaml" in reply.lower()


def test_chat_apply_intent_returns_patched_code():
    resp = client.post(
        "/chat", json={"code": VULN, "message": "apply the fix", "history": []}
    )
    frames = [f for f in resp.text.split("\n\n") if f.startswith("data: ")]
    done = json.loads(frames[-1][len("data: "):])
    assert done["event"] == "done"
    assert done["applied_patch"] is True
    assert "yaml.safe_load" in done["patched"]


def test_chat_no_patchable_code():
    resp = client.post(
        "/chat", json={"code": "x = 1\n", "message": "apply", "history": []}
    )
    frames = [f for f in resp.text.split("\n\n") if f.startswith("data: ")]
    done = json.loads(frames[-1][len("data: "):])
    assert done["applied_patch"] is False


def _ws_turn(ws, payload: dict) -> list[dict]:
    """Send one chat turn and collect frames through the ``done`` frame."""
    ws.send_json(payload)
    frames = []
    while True:
        frame = ws.receive_json()
        frames.append(frame)
        if frame["event"] == "done":
            return frames


def test_chat_ws_streams_and_holds_history():
    with client.websocket_connect("/chat/ws") as ws:
        frames = _ws_turn(ws, {"code": VULN, "message": "what would you change?"})
        kinds = [f["event"] for f in frames]
        assert kinds[0] == "start"
        assert kinds[-1] == "done"
        assert any(k == "token" for k in kinds)

        # Follow-up on the same connection — no new POST, no resent history.
        frames = _ws_turn(ws, {"code": VULN, "message": "apply the fix"})
        done = frames[-1]
        assert done["applied_patch"] is True
        assert "yaml.safe_load" in done["patched"]


def test_chat_ws_rejects_non_json():
    with client.websocket_connect("/chat/ws") as ws:
        ws.send_text("not json")
        assert ws.receive_json()["event"] == "error"
        # The socket stays usable after a bad frame.
        frames = _ws_turn(ws, {"code": "x = 1\n", "message": "apply"})
        assert frames[-1]["applied_patch"] is False


def test_index_serves_three_tabs():
    resp = client.get("/")
    assert resp.status_code == 200
    for tab in ("Scan Results", "Code Playground", "Interactive Agent Chat"):
        assert tab in resp.text
