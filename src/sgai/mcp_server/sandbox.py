"""Filesystem sandboxing for the security MCP server.

A security tool that reads arbitrary files is itself a security risk. Every file
path coming from an agent is resolved and verified to live inside an allow-listed
root before the server will touch it. This blocks path-traversal (``../../etc``)
and symlink escapes, and is the core of SGAI's "Security features"
guarantee.
"""

from __future__ import annotations

from pathlib import Path


class SandboxError(Exception):
    """Raised when a requested path escapes the allowed root."""


def safe_resolve(root: str | Path, requested: str | Path) -> Path:
    """Resolve ``requested`` and confirm it stays within ``root``.

    Both paths are fully resolved (following symlinks) before the containment
    check, so neither ``..`` segments nor symlinks can be used to escape.

    Args:
        root: The allow-listed directory. The scan target's root.
        requested: A path provided by an agent, absolute or relative to ``root``.

    Returns:
        The resolved, sandbox-safe absolute path.

    Raises:
        SandboxError: If the resolved path is outside ``root``.
    """
    root_resolved = Path(root).resolve()
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = root_resolved / candidate
    candidate = candidate.resolve()

    if root_resolved != candidate and root_resolved not in candidate.parents:
        raise SandboxError(
            f"Path {requested!r} resolves outside the sandbox root {root_resolved}"
        )
    return candidate
