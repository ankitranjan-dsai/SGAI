"""The one audited place where SGAI names an external program to run.

Shelling out is inherent to what SGAI is: it drives ``git``, ``gh``, Bandit,
Semgrep, and a scanned project's own test runner. What is *not* inherent is
naming those programs by bare filename. ``subprocess.run(["git", ...])``
resolves ``git`` through ``PATH`` at exec time, so anything that can prepend a
directory to ``PATH`` — a poisoned CI image, a writable ``/usr/local/bin``, an
inherited environment — chooses the binary that runs instead of SGAI. For a
tool whose whole value is being trustworthy about other people's code, that is
the wrong hop to leave open. Resolving the name once, here, and handing
``subprocess`` an absolute path closes it; it is also exactly what Bandit's
B607 ("starting a process with a partial executable path") asks for.

The other half of the argv contract is enforced by convention at every call
site: SGAI always passes a **list**, never ``shell=True``. There is no shell to
re-parse the arguments, so a filename, branch name, or repository URL
containing spaces, quotes, or semicolons is one argument and can never become a
second command. Bandit still reports B603 on each of those calls, because it
cannot see that the argv is fixed and the executable resolved — those are
waived at the call site with a reason, not silenced globally.
"""

from __future__ import annotations

import os
import shutil
import sys


class ExecutableNotFound(FileNotFoundError):
    """A required external program is not installed or not on ``PATH``.

    Subclasses :class:`FileNotFoundError` on purpose: callers already translate
    that into their own domain error ("git is not installed on this system"),
    and resolving the name earlier than ``exec`` should not change which
    ``except`` clause handles it.
    """

    def __init__(self, name: str) -> None:
        super().__init__(f"{name!r} is not installed or not on PATH")
        self.name = name


def _interpreter_scripts_dir() -> str | None:
    """The directory console scripts land in for the running interpreter.

    For a virtualenv this is its ``bin/`` (``Scripts\\`` on Windows), which is
    also the directory holding ``sys.executable`` — so the dirname is the answer
    on every platform SGAI runs on. Returns ``None`` in the exotic case of an
    embedded interpreter that reports no ``sys.executable``.
    """
    if not sys.executable:
        return None
    return os.path.dirname(sys.executable) or None


def resolve_exe(name: str) -> str:
    """Return the absolute path to ``name``, or raise :class:`ExecutableNotFound`.

    An argument that is already absolute is returned unchanged, so a caller may
    pass an interpreter it was handed (``sys.executable``) through the same
    helper without a special case.

    A bare name is looked for **next to the running interpreter first**, and only
    then on ``PATH``. Bandit is a declared dependency of SGAI, so ``pip``/``uv``
    installs its console script into the very same environment as SGAI itself;
    consulting ``PATH`` alone found it only when that environment happened to be
    *activated*. Anything that runs SGAI by absolute interpreter path without
    exporting ``PATH`` — a container ``ENTRYPOINT``, a systemd unit, ``uvicorn``
    started by full path, an IDE's test runner — got "'bandit' is not installed"
    for a Bandit sitting beside the interpreter that raised it. CI never caught
    this because ``uv run`` prepends ``.venv/bin`` to ``PATH``.

    Looking there first is also the more conservative half of this module's own
    threat model: the environment SGAI was installed into is not attacker-chosen
    the way an inherited ``PATH`` is. Tools SGAI does *not* ship — ``git``,
    ``gh`` — are not in that directory and still resolve through ``PATH`` exactly
    as before.
    """
    if os.path.isabs(name):
        return name
    scripts_dir = _interpreter_scripts_dir()
    if scripts_dir is not None:
        bundled = shutil.which(name, path=scripts_dir)
        if bundled is not None:
            return bundled
    resolved = shutil.which(name)
    if resolved is None:
        raise ExecutableNotFound(name)
    return resolved


def resolve_argv(argv: list[str]) -> list[str]:
    """``argv`` with its executable resolved to an absolute path.

    For call sites that build the command elsewhere and only want the
    ``PATH``-resolution guarantee applied before handing it to ``subprocess``.
    """
    if not argv:
        raise ValueError("argv must name a program to run")
    return [resolve_exe(argv[0]), *argv[1:]]
