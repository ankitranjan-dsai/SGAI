"""Tests for the self-healing code patcher (offline)."""

import ast

from sgai.fix import (
    build_patch_plan,
    heal,
    plan_code_patches,
    rollback_patch_plan,
)
from sgai.mcp_server import server
from sgai.models import Finding, Severity


def _finding(rule: str, file: str, line: int) -> Finding:
    return Finding(
        id=rule,
        source="static",
        title=f"{rule} finding",
        severity=Severity.HIGH,
        location=f"{file}:{line}",
    )


VULNERABLE = """\
import subprocess
import yaml
import hashlib

API_PASSWORD = "supersecret123"


def run(user_input, raw, expr, pw):
    subprocess.call(user_input, shell=True)
    data = yaml.load(raw)
    value = eval(expr)
    digest = hashlib.md5(pw.encode())
    return data, value, digest
"""


def test_plan_patches_all_rules(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE)
    findings = [
        _finding("B105", "app.py", 5),
        _finding("B602", "app.py", 9),
        _finding("B506", "app.py", 10),
        _finding("B307", "app.py", 11),
        _finding("B324", "app.py", 12),
    ]
    plan = plan_code_patches(str(tmp_path), findings)

    assert len(plan.patches) == 5
    patched = plan.new_contents["app.py"]
    assert 'API_PASSWORD = os.environ.get("API_PASSWORD", "")' in patched
    assert "subprocess.call(shlex.split(user_input))" in patched
    assert "yaml.safe_load(raw)" in patched
    assert "ast.literal_eval(expr)" in patched
    assert "hashlib.sha256(pw.encode())" in patched
    # Required stdlib imports were inserted exactly where needed.
    assert "import os\n" in patched
    assert "import shlex\n" in patched
    assert "import ast\n" in patched
    # The patched file is still valid Python.
    ast.parse(patched)


def test_patched_file_behaves(tmp_path):
    """The healed module must import and run — patches are non-breaking."""
    (tmp_path / "app.py").write_text(VULNERABLE)
    findings = [_finding("B506", "app.py", 10), _finding("B307", "app.py", 11)]
    plan = plan_code_patches(str(tmp_path), findings)

    ns: dict = {}
    exec(compile(plan.new_contents["app.py"], "app.py", "exec"), ns)
    data, value, _ = ns["run"]("echo hi", "key: 1", "[1, 2]", "pw")
    assert data == {"key": 1}
    assert value == [1, 2]


def test_semgrep_alias_ids_map_to_rules(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\nd = yaml.load(raw)\n")
    findings = [
        Finding(
            id="python.lang.security.deserialization.avoid-yaml-load",
            source="semgrep",
            title="yaml.load is unsafe",
            severity=Severity.HIGH,
            location="app.py:2",
        )
    ]
    plan = plan_code_patches(str(tmp_path), findings)
    assert len(plan.patches) == 1
    assert "yaml.safe_load(raw)" in plan.new_contents["app.py"]


def test_unpatchable_or_mismatched_lines_are_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\ny = 2\n")
    findings = [_finding("B506", "app.py", 1), _finding("B999", "app.py", 2)]
    plan = plan_code_patches(str(tmp_path), findings)
    assert plan.patches == []


def test_syntax_error_files_never_patched(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n    yaml.load(x)\n")
    plan = plan_code_patches(str(tmp_path), [_finding("B506", "broken.py", 2)])
    assert plan.patches == []


def test_method_eval_not_rewritten(tmp_path):
    (tmp_path / "model.py").write_text("model.eval()\nresult = eval(expr)\n")
    plan = build_patch_plan(str(tmp_path), [("model.py", 1, "B307"), ("model.py", 2, "B307")])
    assert len(plan.patches) == 1
    assert plan.patches[0].line == 2


def test_rollback_restores_originals(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE)
    plan = build_patch_plan(str(tmp_path), [("app.py", 10, "B506")])
    (tmp_path / "app.py").write_text(plan.new_contents["app.py"])
    rollback_patch_plan(str(tmp_path), plan)
    assert (tmp_path / "app.py").read_text() == VULNERABLE


def test_validate_patch_respects_sandbox(tmp_path):
    result = server.validate_patch(str(tmp_path), "../outside")
    assert "outside the sandbox" in result.get("error", "")


def test_validate_patch_reports_no_tests(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    result = server.validate_patch(str(tmp_path))
    assert result["ran"] is False
    assert result["passed"] is None


def test_validate_patch_runs_passing_suite(tmp_path):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    result = server.validate_patch(str(tmp_path))
    assert result["ran"] is True
    assert result["passed"] is True


async def test_heal_keeps_patches_when_tests_pass(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\n\ndef load(raw):\n    return yaml.load(raw, Loader=yaml.FullLoader)\n"
    )
    (tmp_path / "test_app.py").write_text(
        "from app import load\n\ndef test_load():\n    assert load('k: 1') == {'k': 1}\n"
    )
    findings = [_finding("B506", "app.py", 4)]
    result = await heal(str(tmp_path), findings=findings)

    assert result.tests_passed is True
    assert len(result.applied) == 1
    assert result.rejected == []
    assert "yaml.safe_load" in (tmp_path / "app.py").read_text()


async def test_heal_rolls_back_breaking_patch(tmp_path):
    # This project's test asserts on eval's ability to resolve names, so the
    # ast.literal_eval patch breaks it — the healer must roll that patch back
    # while keeping the independent yaml patch.
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
    healed = (tmp_path / "app.py").read_text()
    assert "yaml.safe_load(raw)" in healed
    assert "return eval(expr)" in healed  # the breaking patch was rolled back


async def test_heal_skips_validation_when_baseline_red(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\n\ndef load(raw):\n    return yaml.load(raw)\n")
    (tmp_path / "test_broken.py").write_text("def test_broken():\n    assert False\n")
    findings = [_finding("B506", "app.py", 4)]
    result = await heal(str(tmp_path), findings=findings)

    assert result.tests_passed is None
    assert len(result.applied) == 1
    assert "already failing" in result.detail
