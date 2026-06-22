"""Tests for the filesystem sandbox — SecureGuard AI's core security boundary."""

import pytest

from secureguard.mcp_server.sandbox import SandboxError, safe_resolve


def test_allows_path_inside_root(tmp_path):
    target = tmp_path / "src" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("print('ok')")

    resolved = safe_resolve(tmp_path, "src/app.py")
    assert resolved == target.resolve()


def test_blocks_parent_traversal(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(SandboxError):
        safe_resolve(root, "../../etc/passwd")


def test_blocks_absolute_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(SandboxError):
        safe_resolve(root, "/etc/passwd")


def test_blocks_symlink_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    link = root / "link"
    link.symlink_to(secret)

    with pytest.raises(SandboxError):
        safe_resolve(root, "link")
