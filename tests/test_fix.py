"""Tests for the auto-fix engine (offline)."""

from sgai.fix import Fix, apply_fixes, build_pr_body


def test_apply_fixes_rewrites_pins(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("jinja2==2.11.2\nrequests==2.19.1\n")

    fixes = [
        Fix(file="requirements.txt", package="jinja2", ecosystem="PyPI", old_version="2.11.2", new_version="3.1.6"),
        Fix(file="requirements.txt", package="requests", ecosystem="PyPI", old_version="2.19.1", new_version="2.32.0"),
    ]
    apply_fixes(str(tmp_path), fixes)

    text = req.read_text()
    assert "jinja2==3.1.6" in text
    assert "requests==2.32.0" in text
    assert "2.11.2" not in text


def test_build_pr_body_lists_upgrades():
    fixes = [
        Fix(file="requirements.txt", package="jinja2", ecosystem="PyPI", old_version="2.11.2", new_version="3.1.6"),
    ]
    body = build_pr_body(fixes)
    assert "automated dependency security fixes" in body
    assert "`jinja2`" in body
    assert "2.11.2" in body and "3.1.6" in body
