"""Persistent scan memory for SGAI — the project's *Sessions & Memory* layer.

Every scan SGAI runs is a moment in time. On its own a report answers "what is
wrong *now*?". Memory lets SGAI answer the more useful question a team actually
asks: "what changed since last time?" — which vulnerabilities are **new**, which
were **fixed**, and which are still **open** (and being ignored).

Two cooperating pieces live here:

1. :class:`ScanMemory` — a dependency-free, JSON-backed store of every scan of a
   target, plus a per-target list of *accepted risks* (findings a team has
   consciously decided to live with). This is SGAI's long-term memory; it
   persists across runs and across processes.
2. :class:`SgaiMemoryService` — a thin adapter that exposes the same store as a
   genuine ADK :class:`~google.adk.memory.BaseMemoryService`, so the agent layer
   can persist a session and recall it later via the ADK ``load_memory`` tool.

The deterministic :class:`ScanMemory` path needs no API key and is what the CLI
and the diff in the report are built on; the ADK service is the bridge into the
multi-agent runtime.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sgai.models import Finding

_SCHEMA_VERSION = 1


def default_memory_path() -> Path:
    """Where the memory store lives on disk.

    Honors ``$SGAI_HOME`` so a container or test can redirect it; defaults to
    ``~/.sgai/memory.json``.
    """
    home = os.environ.get("SGAI_HOME")
    base = Path(home) if home else Path.home() / ".sgai"
    return base / "memory.json"


def fingerprint(finding: Finding) -> str:
    """A stable identity for a finding, used to match it across scans.

    Combines the source, advisory/test id, and location so that *the same*
    vulnerability in *the same* place keeps one identity over time, while an
    upgrade (which changes the version in the location) reads as the old finding
    being resolved.
    """
    return f"{finding.source}:{finding.id}:{finding.location}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Snapshot:
    """One recorded scan of a target."""

    target: str
    at: str
    risk_score: int
    top_severity: str
    # fingerprint -> minimal finding metadata (enough to describe a fixed issue
    # whose full Finding object we no longer have).
    findings: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "at": self.at,
            "risk_score": self.risk_score,
            "top_severity": self.top_severity,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        return cls(
            target=d["target"],
            at=d["at"],
            risk_score=d.get("risk_score", 0),
            top_severity=d.get("top_severity", "Unknown"),
            findings=d.get("findings", {}),
        )


@dataclass
class ScanDiff:
    """The change between the previous snapshot and the current findings."""

    previous_at: str | None
    new: list[Finding]
    resolved: list[dict]  # finding metadata from the previous snapshot
    persisting: list[Finding]
    accepted: list[Finding]  # currently-present findings the team has accepted

    @property
    def is_first_scan(self) -> bool:
        return self.previous_at is None

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved)

    def summary(self) -> dict:
        """A compact, JSON-friendly summary (for the API and UI)."""
        return {
            "first_scan": self.is_first_scan,
            "previous_at": self.previous_at,
            "new": len(self.new),
            "resolved": len(self.resolved),
            "persisting": len(self.persisting),
            "accepted": len(self.accepted),
        }


def _snapshot_findings(findings: list[Finding]) -> dict[str, dict]:
    return {
        fingerprint(f): {
            "id": f.id,
            "source": f.source,
            "severity": f.severity.label,
            "location": f.location,
            "title": f.title,
        }
        for f in findings
    }


def _top_severity(findings: list[Finding]) -> str:
    if not findings:
        return "None"
    return max(findings, key=lambda f: f.severity).severity.label


class ScanMemory:
    """A persistent, per-target record of scans and accepted risks.

    The on-disk shape is::

        {
          "schema": 1,
          "targets": {
            "<target-key>": {
              "history": [ <snapshot>, ... ],
              "accepted": { "<fingerprint>": {"reason": str, "at": str} }
            }
          }
        }
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_memory_path()
        self._data = self._load()

    # ---- persistence -----------------------------------------------------
    def _load(self) -> dict:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                data = {}
        else:
            data = {}
        data.setdefault("schema", _SCHEMA_VERSION)
        data.setdefault("targets", {})
        return data

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def _target(self, target: str) -> dict:
        return self._data["targets"].setdefault(target, {"history": [], "accepted": {}})

    # ---- queries ---------------------------------------------------------
    def history(self, target: str) -> list[Snapshot]:
        return [Snapshot.from_dict(s) for s in self._target(target)["history"]]

    def last_snapshot(self, target: str) -> Snapshot | None:
        hist = self._target(target)["history"]
        return Snapshot.from_dict(hist[-1]) if hist else None

    def accepted(self, target: str) -> dict[str, dict]:
        return dict(self._target(target)["accepted"])

    def targets(self) -> list[str]:
        return sorted(self._data["targets"])

    # ---- diff + record ---------------------------------------------------
    def diff(self, target: str, findings: list[Finding]) -> ScanDiff:
        """Compare ``findings`` against the most recent snapshot of ``target``.

        This does not mutate the store; call :meth:`record` to persist the new
        snapshot afterwards.
        """
        previous = self.last_snapshot(target)
        accepted_fps = set(self._target(target)["accepted"])
        current = {fingerprint(f): f for f in findings}

        # A first scan is a baseline, not a change set: there is nothing to
        # diff against, so report no new/resolved/persisting — only acceptances.
        if previous is None:
            return ScanDiff(
                previous_at=None,
                new=[],
                resolved=[],
                persisting=[],
                accepted=[f for fp, f in current.items() if fp in accepted_fps],
            )

        prev_fps = set(previous.findings)

        new = [f for fp, f in current.items() if fp not in prev_fps and fp not in accepted_fps]
        persisting = [
            f for fp, f in current.items() if fp in prev_fps and fp not in accepted_fps
        ]
        accepted_now = [f for fp, f in current.items() if fp in accepted_fps]
        resolved = (
            [meta for fp, meta in previous.findings.items() if fp not in current]
            if previous
            else []
        )

        return ScanDiff(
            previous_at=previous.at if previous else None,
            new=new,
            resolved=resolved,
            persisting=persisting,
            accepted=accepted_now,
        )

    def record(self, target: str, findings: list[Finding]) -> Snapshot:
        """Append a snapshot of the current findings and persist it."""
        snapshot = Snapshot(
            target=target,
            at=_now(),
            risk_score=sum(f.risk_score for f in findings),
            top_severity=_top_severity(findings),
            findings=_snapshot_findings(findings),
        )
        self._target(target)["history"].append(snapshot.to_dict())
        self._save()
        return snapshot

    # ---- accepted risks --------------------------------------------------
    def accept(self, target: str, finding_fp: str, reason: str = "") -> None:
        """Mark a finding (by fingerprint) as an accepted risk for ``target``."""
        self._target(target)["accepted"][finding_fp] = {"reason": reason, "at": _now()}
        self._save()

    def unaccept(self, target: str, finding_fp: str) -> bool:
        """Remove an accepted-risk marker. Returns whether one existed."""
        existed = self._target(target)["accepted"].pop(finding_fp, None) is not None
        if existed:
            self._save()
        return existed

    def forget(self, target: str) -> bool:
        """Drop all history and accepted risks for a target."""
        existed = self._data["targets"].pop(target, None) is not None
        if existed:
            self._save()
        return existed


# ---------------------------------------------------------------------------
# ADK bridge: expose the same persistence as a real ADK memory service so the
# agent layer can store a session and recall it via the ``load_memory`` tool.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - import guard for ADK availability
    from google.adk.memory.base_memory_service import (
        BaseMemoryService,
        SearchMemoryResponse,
    )
    from google.adk.memory.memory_entry import MemoryEntry
    from google.genai import types

    _ADK_AVAILABLE = True
except Exception:  # pragma: no cover
    _ADK_AVAILABLE = False


if _ADK_AVAILABLE:

    class SgaiMemoryService(BaseMemoryService):
        """A JSON-backed ADK ``MemoryService`` for cross-session recall.

        ADK sessions are conversational; this service persists the text of a
        session's events so a *later* session (e.g. tomorrow's scan of the same
        repo) can recall what an earlier one concluded. It is intentionally
        simple — keyword matching, no embeddings — but it implements the real
        ADK contract, so the ``load_memory`` tool works against it unchanged.
        """

        def __init__(self, path: Path | None = None) -> None:
            self.path = path or (default_memory_path().parent / "adk_memory.json")
            self._entries = self._load()

        def _load(self) -> list[dict]:
            if self.path.exists():
                try:
                    return json.loads(self.path.read_text())
                except (json.JSONDecodeError, OSError):
                    return []
            return []

        def _save(self) -> None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._entries, indent=2))

        async def add_session_to_memory(self, session) -> None:
            for event in getattr(session, "events", []) or []:
                content = getattr(event, "content", None)
                parts = getattr(content, "parts", None) or []
                text = " ".join(p.text for p in parts if getattr(p, "text", None))
                if not text.strip():
                    continue
                self._entries.append(
                    {
                        "app_name": session.app_name,
                        "user_id": session.user_id,
                        "author": getattr(event, "author", "agent"),
                        "text": text,
                        "timestamp": _now(),
                    }
                )
            self._save()

        async def search_memory(
            self, *, app_name: str, user_id: str, query: str
        ) -> SearchMemoryResponse:
            tokens = [t for t in query.lower().split() if t]
            memories = []
            for e in self._entries:
                if e["app_name"] != app_name or e["user_id"] != user_id:
                    continue
                haystack = e["text"].lower()
                if not tokens or any(t in haystack for t in tokens):
                    memories.append(
                        MemoryEntry(
                            author=e["author"],
                            timestamp=e["timestamp"],
                            content=types.Content(
                                role="model", parts=[types.Part(text=e["text"])]
                            ),
                        )
                    )
            return SearchMemoryResponse(memories=memories)
