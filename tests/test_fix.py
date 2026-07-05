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


def test_lockfile_fixes_are_commands_not_rewrites(tmp_path):
    lock = tmp_path / "package-lock.json"
    original = '{"packages": {"node_modules/lodash": {"version": "4.17.11"}}}'
    lock.write_text(original)

    fixes = [
        Fix(file="package-lock.json", package="lodash", ecosystem="npm",
            old_version="4.17.11", new_version="4.17.21"),
        Fix(file="go.mod", package="github.com/x/y", ecosystem="Go",
            old_version="1.0.0", new_version="1.2.0"),
        Fix(file="uv.lock", package="idna", ecosystem="PyPI",
            old_version="2.7", new_version="3.7"),
    ]
    assert all(not fx.auto_fixable for fx in fixes)
    assert fixes[0].command == "npm install lodash@4.17.21"
    assert fixes[1].command == "go get github.com/x/y@v1.2.0 && go mod tidy"
    assert fixes[2].command == "uv lock --upgrade-package idna"

    # apply_fixes must never touch a lockfile.
    apply_fixes(str(tmp_path), fixes)
    assert lock.read_text() == original

    body = build_pr_body(fixes)
    assert "npm install lodash@4.17.21" in body
    assert "Lockfile upgrades" in body
