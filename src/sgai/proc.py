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


def resolve_exe(name: str) -> str:
    """Return the absolute path to ``name``, or raise :class:`ExecutableNotFound`.

    An argument that is already absolute is returned unchanged, so a caller may
    pass an interpreter it was handed (``sys.executable``) through the same
    helper without a special case.
    """
    if os.path.isabs(name):
        return name
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
