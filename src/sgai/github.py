"""Clone remote repositories so SGAI can audit any public repo by URL.

Only metadata and source are fetched (a shallow clone); SGAI never executes the
cloned code — it is statically analyzed and its dependencies are looked up. The
clone lives in a temp directory and is removed when the scan completes.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

# Matches "owner/repo" shorthand (treated as a GitHub repo when no local path matches).
_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+$")


class CloneError(Exception):
    """Raised when a repository cannot be cloned."""


def normalize_repo_url(target: str) -> str | None:
    """Return a git clone URL if ``target`` looks remote, else ``None``.

    Accepts full https/ssh URLs, ``github.com/owner/repo``, and ``owner/repo``
    shorthand (only when it doesn't match an existing local path).
    """
    t = target.strip()
    if t.startswith(("http://", "https://", "git@")):
        return t
    if t.startswith("github.com/"):
        return f"https://{t}"
    if _SHORTHAND.match(t) and not Path(t).exists():
        return f"https://github.com/{t}"
    return None


def is_remote(target: str) -> bool:
    """True if ``target`` should be treated as a remote repository URL."""
    return normalize_repo_url(target) is not None


@contextlib.contextmanager
def cloned_repo(target: str, timeout: float = 120.0) -> Iterator[Path]:
    """Shallow-clone ``target`` into a temp dir, yielding the local path.

    The directory is deleted on exit. Raises :class:`CloneError` on failure.
    """
    url = normalize_repo_url(target)
    if url is None:
        raise CloneError(f"{target!r} is not a recognized repository URL")

    with tempfile.TemporaryDirectory(prefix="sgai-clone-") as tmp:
        dest = Path(tmp) / "repo"
        try:
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:  # git not installed
            raise CloneError("git is not installed on this system") from exc
        except subprocess.TimeoutExpired as exc:
            raise CloneError(f"clone timed out after {timeout:.0f}s") from exc

        if proc.returncode != 0:
            raise CloneError(f"git clone failed: {proc.stderr.strip()[:300]}")
        yield dest


def _gh_env() -> dict[str, str]:
    """Environment for git/gh calls, pointing gh at ~/.gh when needed."""
    env = os.environ.copy()
    fallback = Path.home() / ".gh"
    if not env.get("GH_CONFIG_DIR") and fallback.is_dir():
        env["GH_CONFIG_DIR"] = str(fallback)
    return env


class PRError(Exception):
    """Raised when opening a pull request fails."""


def open_pull_request(repo_dir: str, branch: str, title: str, body: str) -> str:
    """Branch, commit staged changes, push, and open a PR; return its URL.

    Requires ``repo_dir`` to be a git repo with an ``origin`` you can push to and
    an authenticated ``gh`` CLI. Intended for repositories you own.
    """
    env = _gh_env()

    def run(args: list[str]) -> str:
        proc = subprocess.run(args, cwd=repo_dir, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise PRError(f"`{' '.join(args[:2])}` failed: {proc.stderr.strip()[:300]}")
        return proc.stdout.strip()

    run(["git", "checkout", "-b", branch])
    run(["git", "add", "-A"])
    run(["git", "commit", "-m", title])
    run(["git", "push", "-u", "origin", branch])
    return run(["gh", "pr", "create", "--title", title, "--body", body, "--head", branch])
