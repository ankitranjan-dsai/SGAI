"""Supplemental branch-coverage tests for the net-new policy and git_diff modules."""

import subprocess

import pytest

from sgai.git_diff import (
    GitDiffError,
    changed_files,
    changed_line_map,
    review_comments,
)
from sgai.models import Finding, Severity
from sgai.policy import (
    Policy,
    Violation,
    evaluate_policies,
    parse_policies,
)


def _f(source, sev, location, id="X"):
    return Finding(id=id, source=source, title="t", severity=sev, location=location)


# --------------------------------------------------------------------------- #
# policy.py branches
# --------------------------------------------------------------------------- #
def test_fail_on_severity_invalid_name_is_noop():
    findings = [_f("static", Severity.CRITICAL, "app.py:1")]
    result = evaluate_policies(findings, [Policy("fail-on-severity", {"severity": "bogus"})])
    assert result.passed is True  # unknown threshold → policy is skipped


def test_max_total_findings_policy():
    findings = [_f("static", Severity.LOW, "a.py:1"), _f("static", Severity.LOW, "a.py:2")]
    assert evaluate_policies(findings, [Policy("max-total-findings", {"max": 1})]).passed is False
    assert evaluate_policies(findings, [Policy("max-total-findings", {"max": 5})]).passed is True


def test_no_secrets_custom_min_severity():
    info_secret = [_f("secret", Severity.INFO, "tests/conf.py:1")]
    # Lowering the floor to info makes even a fixture secret a violation.
    result = evaluate_policies(info_secret, [Policy("no-secrets", {"min_severity": "info"})])
    assert result.passed is False


def test_parse_policies_list_form_skips_non_dict_and_unknown():
    policies = parse_policies({"policies": [
        "not-a-dict",
        {"rule": "unknown-policy"},
        {"id": "max-total-findings", "max": 3},
    ]})
    assert policies == [Policy("max-total-findings", {"max": 3})]


def test_parse_policies_bare_mapping_without_policies_key():
    # A top-level mapping is treated as the policy set directly.
    policies = parse_policies({"fail-on-severity": {"severity": "low"}})
    assert policies == [Policy("fail-on-severity", {"severity": "low"})]


def test_evaluate_skips_unknown_rule_object():
    result = evaluate_policies([], [Policy("does-not-exist", {})])
    assert result.evaluated == []
    assert result.passed is True


def test_result_and_violation_to_dict():
    v = Violation("p", "msg", ["a.py:1"])
    assert v.to_dict() == {"policy": "p", "message": "msg", "findings": ["a.py:1"]}
    result = evaluate_policies([_f("static", Severity.CRITICAL, "app.py:1")],
                               [Policy("no-critical-in-production", {})])
    d = result.to_dict()
    assert d["passed"] is False
    assert d["violations"][0]["policy"] == "no-critical-in-production"
    assert "no-critical-in-production" in d["evaluated"]


# --------------------------------------------------------------------------- #
# git_diff.py branches
# --------------------------------------------------------------------------- #
def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.co")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def test_git_diff_error_on_bad_ref(git_repo):
    (git_repo / "a.py").write_text("x = 1\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "c")
    with pytest.raises(GitDiffError):
        changed_files(str(git_repo), base="no-such-ref", head="HEAD", merge_base=False)


def test_git_not_installed(monkeypatch, tmp_path):
    import sgai.git_diff as gd

    def boom(*a, **k):
        raise FileNotFoundError("git")

    monkeypatch.setattr(gd.subprocess, "run", boom)
    with pytest.raises(GitDiffError, match="git is not installed"):
        changed_files(str(tmp_path))


def test_git_timeout(monkeypatch, tmp_path):
    import sgai.git_diff as gd

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(gd.subprocess, "run", slow)
    with pytest.raises(GitDiffError, match="timed out"):
        changed_files(str(tmp_path))


def test_line_map_with_deletions(git_repo):
    (git_repo / "a.py").write_text("a\nb\nc\nd\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "base")
    # Delete lines b and c, keep d, add a new line e — only the genuinely added
    # line counts, and the deletion branch must not miscount new-side numbers.
    (git_repo / "a.py").write_text("a\nd\ne\n")
    line_map = changed_line_map(str(git_repo), base="HEAD", head=None)
    assert line_map["a.py"] == {3}  # 'd' is unchanged context; only 'e' is new


def test_review_comments_empty_for_no_file_findings():
    assert review_comments([_f("dependency", Severity.HIGH, "PyPI:x@1")]) == []
