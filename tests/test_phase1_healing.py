"""Phase 1: multi-language validation, binary-search rollback, commit-patch."""

import json

import pytest
from fastapi.testclient import TestClient

from sgai.api import app
from sgai.fix import (
    DiffApplyError,
    _PATCH_RULES,
    _bisect_breaking_targets,
    _targets_from_findings,
    apply_unified_diff,
    heal,
)
from sgai.mcp_server import server
from sgai.mcp_server.server import _detect_test_frameworks, validate_patch
from sgai.models import Finding, Severity

client = TestClient(app)


def _finding(rule: str, file: str, line: int) -> Finding:
    return Finding(
        id=rule,
        source="static",
        title=f"{rule} finding",
        severity=Severity.HIGH,
        location=f"{file}:{line}",
    )


# --------------------------------------------------------------------------- #
# Multi-language test framework detection
# --------------------------------------------------------------------------- #
def test_detects_pytest(tmp_path):
    (tmp_path / "test_x.py").write_text("def test_x():\n    assert True\n")
    names = [f["framework"] for f in _detect_test_frameworks(tmp_path)]
    assert names == ["pytest"]


def test_detects_npm_with_real_test_script(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "node t.js"}}))
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/fake")
    names = [f["framework"] for f in _detect_test_frameworks(tmp_path)]
    assert "npm" in names


def test_skips_npm_placeholder_script(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}})
    )
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/fake")
    assert _detect_test_frameworks(tmp_path) == []


def test_detects_go_and_cargo(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.com/x\n")
    (tmp_path / "x_test.go").write_text("package x\n")
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/fake")
    names = {f["framework"] for f in _detect_test_frameworks(tmp_path)}
    assert names == {"go", "cargo"}


def test_go_without_test_files_not_detected(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.com/x\n")
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/fake")
    assert _detect_test_frameworks(tmp_path) == []


def test_missing_runner_binary_not_detected(tmp_path, monkeypatch):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    monkeypatch.setattr(server.shutil, "which", lambda _: None)
    assert _detect_test_frameworks(tmp_path) == []


def test_validate_patch_reports_frameworks(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    result = validate_patch(str(tmp_path))
    assert result["passed"] is True
    assert result["frameworks"][0]["framework"] == "pytest"


def test_validate_patch_timeout_is_capped(tmp_path, monkeypatch):
    """Even a caller-supplied huge timeout is clamped to the hard ceiling."""
    seen = {}

    def fake_run(cmd, cwd, timeout):
        seen["timeout"] = timeout
        return {"ran": True, "passed": True, "exit_code": 0, "output": ""}

    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    monkeypatch.setattr(server, "_run_test_command", fake_run)
    validate_patch(str(tmp_path), timeout_seconds=99999)
    assert seen["timeout"] == server._TEST_TIMEOUT_CEILING


def test_validate_patch_hanging_suite_times_out(tmp_path):
    (tmp_path / "test_hang.py").write_text(
        "import time\n\ndef test_hang():\n    time.sleep(60)\n"
    )
    result = validate_patch(str(tmp_path), timeout_seconds=1)
    assert result["ran"] is True
    assert result["passed"] is False
    assert "timed out" in result["frameworks"][0]["reason"]


# --------------------------------------------------------------------------- #
# Confidence scoring & ordering
# --------------------------------------------------------------------------- #
def test_all_rules_have_confidence_in_range():
    for rule in _PATCH_RULES.values():
        assert 0.0 <= rule.confidence <= 1.0


def test_targets_sorted_by_confidence():
    findings = [
        _finding("B307", "a.py", 1),  # 0.55
        _finding("B506", "a.py", 2),  # 0.95
        _finding("B501", "a.py", 3),  # 0.9
    ]
    rules = [t[2] for t in _targets_from_findings(findings)]
    assert rules == ["B506", "B501", "B307"]


def test_code_patch_carries_confidence(tmp_path):
    from sgai.fix import build_patch_plan

    (tmp_path / "a.py").write_text("import yaml\nd = yaml.load(x)\n")
    plan = build_patch_plan(str(tmp_path), [("a.py", 2, "B506")])
    assert plan.patches[0].confidence == pytest.approx(0.95)


# --------------------------------------------------------------------------- #
# Binary-search rollback
# --------------------------------------------------------------------------- #
def test_bisect_finds_single_breaking_patch():
    calls = []

    def passes(subset):
        calls.append(list(subset))
        return ("bad.py", 1, "B307") not in subset

    targets = [(f"f{i}.py", 1, "B506") for i in range(7)] + [("bad.py", 1, "B307")]
    kept, dropped = _bisect_breaking_targets(".", targets, [], passes)
    assert dropped == [("bad.py", 1, "B307")]
    assert len(kept) == 7
    # Far fewer runs than one-at-a-time rollback over 8 targets would need
    # in the worst case, and logarithmic in the clean-patch count.
    assert len(calls) <= 8


def test_bisect_finds_multiple_breaking_patches():
    bad = {("b1.py", 1, "B307"), ("b2.py", 1, "B105")}

    def passes(subset):
        return not bad & set(subset)

    targets = [(f"f{i}.py", 1, "B506") for i in range(6)]
    targets[1] = ("b1.py", 1, "B307")
    targets[4] = ("b2.py", 1, "B105")
    kept, dropped = _bisect_breaking_targets(".", targets, [], passes)
    assert set(dropped) == bad
    assert len(kept) == 4


def test_bisect_all_breaking():
    kept, dropped = _bisect_breaking_targets(".", [("a.py", 1, "B307")], [], lambda s: not s)
    assert kept == []
    assert dropped == [("a.py", 1, "B307")]


async def test_heal_binary_search_keeps_good_patches(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\n"
        "N = 5\n"
        "\n"
        "def load(raw):\n"
        "    return yaml.load(raw, Loader=yaml.FullLoader)\n"
        "\n"
        "def compute(expr):\n"
        "    return eval(expr)\n"
    )
    (tmp_path / "test_app.py").write_text(
        "from app import compute, load\n"
        "\n"
        "def test_load():\n"
        "    assert load('k: 1') == {'k': 1}\n"
        "\n"
        "def test_compute_uses_globals():\n"
        "    assert compute('N + 1') == 6\n"
    )
    findings = [_finding("B506", "app.py", 5), _finding("B307", "app.py", 8)]
    result = await heal(str(tmp_path), findings=findings)

    assert result.tests_passed is True
    assert [p.rule for p in result.applied] == ["B506"]
    assert [p.rule for p in result.rejected] == ["B307"]
    assert "binary search" in result.detail


# --------------------------------------------------------------------------- #
# Unified diff application
# --------------------------------------------------------------------------- #
ORIGINAL = "a\nb\nc\nd\n"


def test_apply_unified_diff_roundtrip():
    import difflib

    new = "a\nB\nc\nd\ne\n"
    diff = "".join(
        difflib.unified_diff(
            ORIGINAL.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile="a/x",
            tofile="b/x",
        )
    )
    assert apply_unified_diff(ORIGINAL, diff) == new


def test_apply_unified_diff_rejects_stale_diff():
    diff = "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-zzz\n+yyy\n a\n"
    with pytest.raises(DiffApplyError):
        apply_unified_diff(ORIGINAL, diff)


def test_apply_unified_diff_requires_hunks():
    with pytest.raises(DiffApplyError):
        apply_unified_diff(ORIGINAL, "not a diff")


# --------------------------------------------------------------------------- #
# POST /commit-patch
# --------------------------------------------------------------------------- #
def test_commit_patch_writes_diff_inside_sandbox(tmp_path):
    import difflib

    (tmp_path / "app.py").write_text("x = eval(s)\n")
    new = "import ast\nx = ast.literal_eval(s)\n"
    diff = "".join(
        difflib.unified_diff(
            ["x = eval(s)\n"], new.splitlines(keepends=True), "a/app.py", "b/app.py"
        )
    )
    resp = client.post(
        "/commit-patch",
        json={"root": str(tmp_path), "file_path": "app.py", "diff": diff, "run_tests": False},
    )
    assert resp.status_code == 200
    assert resp.json()["committed"] is True
    assert (tmp_path / "app.py").read_text() == new


def test_commit_patch_blocks_path_traversal(tmp_path):
    resp = client.post(
        "/commit-patch",
        json={"root": str(tmp_path), "file_path": "../evil.py", "content": "boom"},
    )
    assert resp.status_code == 400


def test_commit_patch_rejects_stale_diff(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    diff = "@@ -1,1 +1,1 @@\n-y = 2\n+y = 3\n"
    resp = client.post(
        "/commit-patch",
        json={"root": str(tmp_path), "file_path": "app.py", "diff": diff},
    )
    assert resp.status_code == 409


def test_commit_patch_runs_validation(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    resp = client.post(
        "/commit-patch",
        json={"root": str(tmp_path), "file_path": "app.py", "content": "x = 1\n"},
    )
    assert resp.status_code == 200
    assert resp.json()["validation"]["passed"] is True


def test_commit_patch_refuses_broad_roots():
    resp = client.post(
        "/commit-patch", json={"root": "/", "file_path": "etc/passwd", "content": "x"}
    )
    assert resp.status_code == 400
