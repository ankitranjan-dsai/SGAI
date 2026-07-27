"""Scan scoping: what the scanners must refuse to look at.

These are regression tests for a class of bug that made `sgai scan` unusable on
any repo with a local virtualenv. The scanners walked everything — dependency
trees, build output, and SGAI's own report — so real findings were buried under
thousands of third-party hits, and `sgai check` failed on noise. None of the
existing suite caught it, because every test scanned a purpose-built fixture
tree that happened to contain no virtualenv.
"""

from pathlib import Path

from sgai.config import GENERATED_REPORT_NAMES, SKIP_DIRS
from sgai.mcp_server.server import (
    _is_test_only_noise,
    list_source_files,
    run_static_analysis,
    scan_secrets,
)

# A plausible secret, so we can tell "was this file read?" from "was it clean?".
SECRET_LINE = 'aws_key = "AKIAIOSFODNN7EXPMPL1"\n'


def _repo(tmp_path: Path) -> Path:
    """A repo with one real source file plus the usual uninteresting noise."""
    (tmp_path / "app.py").write_text(f"import os\n{SECRET_LINE}")

    vendored = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages" / "dep"
    vendored.mkdir(parents=True)
    (vendored / "vendored.py").write_text(f"import hashlib\n{SECRET_LINE}")

    node = tmp_path / "node_modules" / "pkg"
    node.mkdir(parents=True)
    (node / "index.js").write_text(SECRET_LINE)

    return tmp_path


# --------------------------------------------------------------------------- #
# The shared constant
# --------------------------------------------------------------------------- #
def test_skip_dirs_covers_the_usual_suspects():
    # Each of these has burned us: virtualenvs and node_modules are dependency
    # trees, the rest is build output.
    for name in (".venv", "venv", "node_modules", "__pycache__", ".git", "dist", "build", "target"):
        assert name in SKIP_DIRS


# --------------------------------------------------------------------------- #
# Static analysis
# --------------------------------------------------------------------------- #
def test_bandit_ignores_vendored_code(tmp_path):
    root = _repo(tmp_path)
    (root / ".venv" / "unsafe.py").write_text("import subprocess\nsubprocess.call('ls', shell=True)\n")
    (root / "unsafe.py").write_text("import subprocess\nsubprocess.call('ls', shell=True)\n")

    result = run_static_analysis(str(root), str(root))

    files = {f["file"] for f in result.get("findings", [])}
    assert "unsafe.py" in files, "first-party finding should still be reported"
    assert not any(".venv" in f for f in files), f"vendored code leaked in: {files}"


def test_list_source_files_skips_dependency_trees(tmp_path):
    root = _repo(tmp_path)

    listed = list_source_files(str(root))["files"]

    assert "app.py" in listed
    assert not any(".venv" in f or "node_modules" in f for f in listed)


# --------------------------------------------------------------------------- #
# Secret scanning
# --------------------------------------------------------------------------- #
def test_secret_scan_skips_vendored_code(tmp_path):
    root = _repo(tmp_path)

    locations = {c["file"] for c in scan_secrets(str(root), str(root))["findings"]}

    assert "app.py" in locations
    assert not any(".venv" in loc or "node_modules" in loc for loc in locations)


def test_secret_scan_ignores_sgai_own_report(tmp_path):
    """The report quotes the secrets it finds and is written into the scanned
    directory, so reading it back makes every run ingest the last one."""
    root = tmp_path
    (root / "app.py").write_text(SECRET_LINE)
    for name in GENERATED_REPORT_NAMES:
        (root / name).write_text(f"# SGAI Security Report\n\n| 1 | secret | {SECRET_LINE} |\n")

    locations = {c["file"] for c in scan_secrets(str(root), str(root))["findings"]}

    assert "app.py" in locations
    assert not (locations & GENERATED_REPORT_NAMES), f"report was re-ingested: {locations}"


# --------------------------------------------------------------------------- #
# Test-only rule noise
# --------------------------------------------------------------------------- #
def test_assert_is_noise_in_tests_but_real_in_source():
    # `python -O` strips asserts, so B101 is a genuine (low) finding in shipped
    # code — we only want it silenced under test paths.
    assert _is_test_only_noise("B101", "tests/test_thing.py")
    assert _is_test_only_noise("B101", "src/pkg/tests/test_thing.py")
    assert _is_test_only_noise("B101", "conftest.py")

    assert not _is_test_only_noise("B101", "src/sgai/runner.py")
    assert not _is_test_only_noise("B602", "tests/test_thing.py"), (
        "shell-injection in a test file is still worth reporting"
    )
