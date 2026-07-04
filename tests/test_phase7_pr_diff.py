"""Phase 7: git-diff extraction, delta filtering, PR scan endpoint."""

import subprocess

import pytest
from fastapi.testclient import TestClient

from sgai.api import app
from sgai.git_diff import (
    changed_files,
    changed_line_map,
    filter_to_delta,
    review_comments,
)
from sgai.models import Finding, Severity

client = TestClient(app)


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.co")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def _commit(repo, msg):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)


# --------------------------------------------------------------------------- #
# git diff extraction
# --------------------------------------------------------------------------- #
def test_changed_files_and_line_map(git_repo):
    (git_repo / "app.py").write_text("a = 1\nb = 2\n")
    _commit(git_repo, "base")
    (git_repo / "app.py").write_text("a = 1\nb = 2\nc = 3\nd = 4\n")
    (git_repo / "new.py").write_text("x = 1\n")
    _git(git_repo, "add", "-N", "new.py")  # intent-to-add so the new file shows in diff

    files = set(changed_files(str(git_repo), base="HEAD", head=None))
    assert files == {"app.py", "new.py"}

    line_map = changed_line_map(str(git_repo), base="HEAD", head=None)
    assert line_map["app.py"] == {3, 4}  # only the appended lines
    assert line_map["new.py"] == {1}


def test_line_map_between_commits(git_repo):
    (git_repo / "app.py").write_text("a = 1\n")
    _commit(git_repo, "base")
    (git_repo / "app.py").write_text("a = 1\neval(x)\n")
    _commit(git_repo, "head")
    line_map = changed_line_map(str(git_repo), base="HEAD~1", head="HEAD", merge_base=False)
    assert line_map["app.py"] == {2}


# --------------------------------------------------------------------------- #
# delta filtering
# --------------------------------------------------------------------------- #
def _finding(source, location, sev=Severity.HIGH):
    return Finding(id="B307", source=source, title="eval", severity=sev, location=location)


def test_filter_keeps_only_changed_lines():
    line_map = {"app.py": {5, 6}}
    on_change = _finding("static", "app.py:5")
    off_change = _finding("static", "app.py:2")
    other_file = _finding("static", "other.py:5")
    delta = filter_to_delta([on_change, off_change, other_file], line_map)
    assert delta == [on_change]


def test_filter_keeps_dependency_when_manifest_changed():
    line_map = {"requirements.txt": {3}}
    dep = _finding("dependency", "PyPI:jinja2@2.11.2")
    npm = _finding("dependency", "npm:lodash@4.0.0")
    delta = filter_to_delta([dep, npm], line_map)
    assert dep in delta
    assert npm not in delta  # no npm lockfile changed


def test_review_comments_shape():
    findings = [_finding("static", "api/app.py:5")]
    comments = review_comments(findings)
    assert comments[0]["path"] == "api/app.py"
    assert comments[0]["line"] == 5
    assert "SGAI" in comments[0]["body"]


def test_review_comments_skip_dependency_findings():
    assert review_comments([_finding("dependency", "PyPI:x@1")]) == []


# --------------------------------------------------------------------------- #
# End-to-end delta scan
# --------------------------------------------------------------------------- #
def test_delta_findings_only_new_code(git_repo):
    # Baseline already contains an eval — it must NOT be reported as new.
    (git_repo / "app.py").write_text("import os\nvalue = eval(existing)\n")
    _commit(git_repo, "base")
    # The PR adds a second eval on a new line.
    (git_repo / "app.py").write_text(
        "import os\nvalue = eval(existing)\nother = eval(fresh)\n"
    )

    import asyncio

    from sgai.git_diff import delta_findings

    findings, line_map = asyncio.run(delta_findings(str(git_repo), base="HEAD", head=None))
    locations = {f.location for f in findings if f.source == "static"}
    assert "app.py:3" in locations       # the newly added eval
    assert "app.py:2" not in locations   # the pre-existing eval is not new


# --------------------------------------------------------------------------- #
# POST /scan/pr
# --------------------------------------------------------------------------- #
def test_scan_pr_endpoint_reports_delta(git_repo):
    (git_repo / "app.py").write_text("x = 1\n")
    _commit(git_repo, "base")
    (git_repo / "app.py").write_text("x = 1\nimport subprocess\nsubprocess.call(c, shell=True)\n")

    resp = client.post("/scan/pr", json={"repo_dir": str(git_repo), "base": "HEAD"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["delta_count"] >= 1
    assert body["posted"] is False
    assert any(c["path"] == "app.py" for c in body["comments"])


def test_scan_pr_clean_change(git_repo):
    (git_repo / "app.py").write_text("x = 1\n")
    _commit(git_repo, "base")
    (git_repo / "app.py").write_text("x = 1\ny = 2\n")
    resp = client.post("/scan/pr", json={"repo_dir": str(git_repo), "base": "HEAD"})
    body = resp.json()
    assert body["delta_count"] == 0
    assert "no new security findings" in body["body"]


def test_scan_pr_requires_repo():
    resp = client.post("/scan/pr", json={})
    assert resp.status_code == 400


def test_scan_pr_post_needs_owner_and_number(git_repo):
    (git_repo / "app.py").write_text("x = 1\n")
    _commit(git_repo, "base")
    (git_repo / "app.py").write_text("x = 1\neval(z)\n")
    resp = client.post("/scan/pr", json={"repo_dir": str(git_repo), "base": "HEAD", "post": True})
    assert resp.status_code == 400
