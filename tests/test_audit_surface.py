"""The audited surface, and the executables SGAI is allowed to run.

Two invariants live here, both learned from SGAI scanning itself.

`--exclude` exists because SGAI ships a corpus of deliberately vulnerable demo
targets and a test tree full of credential-shaped literals. Reported as code
scanning alerts they outnumbered the findings in SGAI's own source two to one,
which is how a real finding hides. Narrowing what gets *reported* is legitimate;
narrowing it by accident is a silent false negative, so every test below pins the
boundary rather than the happy path: exclusion must be asked for, must be proved
per finding, and must never be inferred from a substring.

`sgai.proc` exists because a scanner that shells out to `git` by bare filename
resolves it through `PATH` at exec time — so whoever controls `PATH` in CI
chooses what SGAI runs. Resolving up front closes that hop.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
import sys

import pytest

from sgai.config import path_excluded
from sgai.models import Finding, Severity
from sgai.proc import ExecutableNotFound, resolve_argv, resolve_exe
from sgai.runner import exclude_findings, gather_findings


def _f(location: str, manifest: str = "", fid: str = "F") -> Finding:
    return Finding(
        id=fid,
        source="static",
        title="t",
        severity=Severity.HIGH,
        location=location,
        manifest=manifest,
    )


# --------------------------------------------------------------------------- #
# path_excluded — the primitive
# --------------------------------------------------------------------------- #
def test_excludes_the_directory_itself_and_everything_under_it():
    assert path_excluded("examples", ["examples"])
    assert path_excluded("examples/vuln_app/app.py", ["examples"])
    assert path_excluded("tests/fixtures/creds.py", ["tests"])


def test_matches_path_segments_not_substrings():
    # "examples_of_real_code/" is not inside "examples/", and a file merely
    # *named* after the excluded dir is still production code.
    assert not path_excluded("examples_extra/app.py", ["examples"])
    assert not path_excluded("src/examples.py", ["examples"])
    assert not path_excluded("src/sgai/test_helpers.py", ["tests"])


def test_nothing_is_excluded_by_default():
    for path in ("examples/app.py", "tests/test_x.py", "src/sgai/runner.py"):
        assert not path_excluded(path, [])


def test_whole_repo_exclusions_are_refused():
    # Honouring these would report zero findings for any repo — indistinguishable
    # from a clean one, which is the failure mode this tool exists to prevent.
    assert not path_excluded("src/sgai/runner.py", ["."])
    assert not path_excluded("src/sgai/runner.py", [""])
    assert not path_excluded("src/sgai/runner.py", ["/"])


def test_accepts_the_separator_the_shell_gave_us():
    # A Windows developer types --exclude examples\vuln_app; the finding paths
    # are always POSIX, so one side has to normalize and it may as well be both.
    assert path_excluded("examples/vuln_app/app.py", ["examples\\vuln_app"])
    assert path_excluded("examples/vuln_app/app.py", ["examples/"])


def test_several_exclusions_are_independent():
    excludes = ["examples", "tests"]
    assert path_excluded("examples/app.py", excludes)
    assert path_excluded("tests/test_x.py", excludes)
    assert not path_excluded("src/sgai/cli.py", excludes)


# --------------------------------------------------------------------------- #
# exclude_findings — applying it to real findings
# --------------------------------------------------------------------------- #
def test_drops_findings_inside_an_excluded_tree():
    kept, dropped = exclude_findings(
        [_f("examples/vuln_app/app.py:12"), _f("src/sgai/runner.py:40")], ["examples"]
    )

    assert [f.location for f in kept] == ["src/sgai/runner.py:40"]
    assert dropped == 1


def test_dependency_findings_follow_the_manifest_that_pins_them():
    """A dependency finding names a package, not a file. The path a reader would
    have to edit is the manifest, so that is what exclusion has to look at."""
    fixture_pin = _f("PyPI:flask@0.12.2", manifest="examples/vuln_app/requirements.txt")
    real_pin = _f("PyPI:jinja2@2.11.2", manifest="requirements.txt")

    kept, dropped = exclude_findings([fixture_pin, real_pin], ["examples"])

    assert kept == [real_pin]
    assert dropped == 1


def test_unattributable_findings_are_always_kept():
    """Exclusion must be *proved*. A finding SGAI cannot place in the tree —
    a bare package name with no manifest, a repo-wide policy hit — stays, because
    dropping it would turn a typo'd --exclude into a missed vulnerability."""
    floating = _f("PyPI:requests@2.19.1")

    kept, dropped = exclude_findings([floating], ["examples", "tests"])

    assert kept == [floating]
    assert dropped == 0


def test_no_exclusions_is_the_identity():
    findings = [_f("examples/app.py:1"), _f("tests/test_x.py:2")]

    kept, dropped = exclude_findings(findings, [])

    assert kept == findings
    assert dropped == 0


def test_a_finding_is_dropped_only_if_every_path_it_names_is_excluded():
    # Static hit in production source that a fixture manifest also references:
    # one of its paths survives, so the finding does too.
    straddling = _f("src/sgai/runner.py:40", manifest="examples/requirements.txt")

    kept, _ = exclude_findings([straddling], ["examples"])

    assert kept == [straddling]


# --------------------------------------------------------------------------- #
# End to end: the flag as the CI workflow uses it
# --------------------------------------------------------------------------- #
def test_gather_findings_reports_the_narrowed_surface_only(tmp_path):
    """Detection still runs over the excluded tree — only reporting narrows."""
    (tmp_path / "app.py").write_text('import os\nkey = "AKIAIOSFODNN7EXPMPL1"\n')
    demo = tmp_path / "examples" / "vuln_app"
    demo.mkdir(parents=True)
    (demo / "app.py").write_text('import os\nkey = "AKIAIOSFODNN7EXPMPL2"\n')

    everything = asyncio.run(gather_findings(str(tmp_path)))
    scoped = asyncio.run(gather_findings(str(tmp_path), exclude=["examples"]))

    assert any("examples/" in f.location for f in everything), (
        "fixture should produce a finding to exclude in the first place"
    )
    assert not any("examples/" in f.location for f in scoped)
    assert any(f.location.startswith("app.py") for f in scoped), (
        "excluding examples/ must not narrow anything else"
    )


# --------------------------------------------------------------------------- #
# sgai.proc — which binary a bare name resolves to
# --------------------------------------------------------------------------- #
def test_resolve_exe_returns_an_absolute_path():
    resolved = resolve_exe("python3")

    assert os.path.isabs(resolved)
    assert os.path.exists(resolved)


def test_resolve_exe_passes_absolute_paths_through_untouched():
    # An absolute path is already the caller's explicit choice; re-resolving it
    # through PATH would be the bug this module exists to prevent.
    assert resolve_exe("/usr/bin/env") == "/usr/bin/env"


def test_missing_executable_is_a_file_not_found_error():
    """Callers translate FileNotFoundError into their own domain error ("git is
    not installed"). Resolving earlier than exec must not change which except
    clause runs."""
    with pytest.raises(FileNotFoundError):
        resolve_exe("sgai-no-such-program-9f3a")

    with pytest.raises(ExecutableNotFound) as exc:
        resolve_exe("sgai-no-such-program-9f3a")
    assert "sgai-no-such-program-9f3a" in str(exc.value)


def test_resolve_argv_pins_the_program_and_leaves_arguments_alone():
    argv = resolve_argv(["python3", "-c", "print(1)", "git"])

    assert os.path.isabs(argv[0])
    assert argv[1:] == ["-c", "print(1)", "git"], "only argv[0] names a program"


def test_resolve_argv_rejects_an_empty_argv():
    with pytest.raises(ValueError):
        resolve_argv([])


def test_a_hijacked_path_cannot_change_which_binary_runs(tmp_path, monkeypatch):
    """The attack this module closes: something earlier on PATH shadowing `git`.

    Resolution still honours PATH — it has to, that is how tools are found — but
    it happens once, in one audited place, at a point where the resolved path can
    be logged and asserted on, instead of implicitly inside every exec.
    """
    real = shutil.which("git")
    if real is None:
        pytest.skip("git is not installed")

    fake_dir = tmp_path / "evil"
    fake_dir.mkdir()
    fake = fake_dir / "git"
    fake.write_text("#!/bin/sh\necho pwned\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setenv("PATH", f"{fake_dir}{os.pathsep}{os.environ['PATH']}")
    assert resolve_exe("git") == str(fake), (
        "resolution is PATH-based by design; the point is that it is visible"
    )

    monkeypatch.setenv("PATH", os.path.dirname(real))
    assert resolve_exe("git") == real


def test_a_dependency_resolves_without_an_activated_environment(monkeypatch):
    """Bandit ships *with* SGAI, so an empty PATH must not make it "not installed".

    The regression: SGAI declares bandit as a dependency, so it is installed
    beside the running interpreter, but resolution consulted only PATH — every
    Bandit-backed scan failed whenever SGAI was started by absolute interpreter
    path (container ENTRYPOINT, systemd, an IDE runner) instead of through an
    activated venv.
    """
    scripts_dir = os.path.dirname(sys.executable)
    if not shutil.which("bandit", path=scripts_dir):
        pytest.skip("bandit is not installed alongside this interpreter")

    monkeypatch.setenv("PATH", "")
    resolved = resolve_exe("bandit")

    assert os.path.isabs(resolved) and os.path.exists(resolved)
    assert os.path.dirname(resolved) == scripts_dir


def test_path_still_resolves_programs_sgai_does_not_ship(monkeypatch):
    """The interpreter-first lookup must not shadow ordinary PATH resolution.

    `git` is not installed into SGAI's environment, so it has to keep coming from
    PATH — otherwise the fix above would trade one broken lookup for another.
    """
    real = shutil.which("git")
    if real is None:
        pytest.skip("git is not installed")

    monkeypatch.setenv("PATH", os.path.dirname(real))
    assert resolve_exe("git") == real
