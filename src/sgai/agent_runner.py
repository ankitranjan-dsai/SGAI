"""Agent-driven scan runner for SGAI.

Runs the real multi-agent ADK pipeline (scanner → parallel dependency/static
analysis → risk → remediation → report) via an ADK ``Runner``. The agents call
the security MCP server for every tool action and produce a narrated security
report.

This is the LLM path; :mod:`sgai.runner` is the deterministic fallback.
"""

from __future__ import annotations

import hashlib
import json

from google.adk.runners import InMemoryRunner
from google.genai import types

from sgai.agents.narrator import build_narration_pipeline
from sgai.agents.orchestrator import build_pipeline
from sgai.memory import ScanDiff, ScanMemory, SgaiMemoryService
from sgai.models import Finding
from sgai.report import _changes_section
from sgai.runner import gather_findings, target_key

_APP = "sgai"
_USER = "user"


def _session_id(target: str) -> str:
    """A stable session id per target so the agent's sessions persist by repo."""
    return "scan-" + hashlib.sha1(target.encode()).hexdigest()[:12]


def _memory_context(diff: ScanDiff) -> str:
    """A short natural-language recap of prior scans for the narration prompt."""
    if diff.is_first_scan:
        return "This is the first recorded scan of this target; no prior history."
    return (
        f"Memory of prior scans: the last scan was at {diff.previous_at}. "
        f"Since then {len(diff.new)} finding(s) are new, {len(diff.resolved)} were "
        f"fixed, and {len(diff.persisting)} remain open. Acknowledge this trend in "
        "the executive summary."
    )


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "source": f.source,
        "severity": f.severity.label,
        "location": f.location,
        "title": f.title,
        "remediation": f.remediation,
        "references": f.references,
    }


async def run_agent_report(
    repo: str,
    label: str | None = None,
    deep: bool = False,
    memory: ScanMemory | None = None,
) -> tuple[list[Finding], str, ScanDiff | None]:
    """Gather findings deterministically, then narrate them with the agent layer.

    The deterministic core finds vulnerabilities with zero LLM calls; the
    two-agent narration pipeline (triage → report writer) then produces the
    human-facing report. This keeps LLM usage within the free-tier rate limit.

    When ``memory`` is supplied, SGAI recalls the previous scan of this target,
    tells the agents what changed so the narrative reflects the trend, appends a
    deterministic "Changes since last scan" section, persists the session into
    its ADK memory service, and records a new snapshot.

    Args:
        repo: Path to the repository to audit.
        label: Display name for the report (e.g. a GitHub URL); defaults to repo.
        deep: Also run Semgrep multi-language static analysis.
        memory: Optional scan-memory store enabling cross-scan recall.

    Returns:
        A tuple of (findings, agent-written Markdown report, diff-or-None).
    """
    target = label or repo
    findings = await gather_findings(repo, deep=deep)

    diff = None
    context = ""
    if memory is not None:
        key = target_key(label, repo)
        diff = memory.diff(key, findings)
        context = _memory_context(diff)

    report = await narrate_findings(findings, target, memory_context=context)

    if diff is not None:
        report = report.rstrip() + "\n\n" + "\n".join(_changes_section(diff))
        memory.record(target_key(label, repo), findings)

    return findings, report, diff


async def narrate_findings(
    findings: list[Finding], target: str, memory_context: str = ""
) -> str:
    """Run the two-agent narration pipeline over already-gathered findings.

    Shared by the CLI (`sgai scan --explain`) and the web API, so any source of
    findings can get an agent-written report without re-scanning. The session is
    keyed per target and persisted into SGAI's ADK memory service so a later
    scan of the same target can recall it.

    Args:
        findings: The findings to narrate.
        target: Label for what was scanned (path, "submitted code", etc.).
        memory_context: Optional recap of prior scans, injected into the prompt.

    Returns:
        The agent-written Markdown report.
    """
    payload = json.dumps([_finding_to_dict(f) for f in findings], indent=2)

    pipeline = build_narration_pipeline()
    runner = InMemoryRunner(agent=pipeline, app_name=_APP)
    session_id = _session_id(target)
    await runner.session_service.create_session(
        app_name=_APP, user_id=_USER, session_id=session_id
    )

    preamble = f"{memory_context}\n\n" if memory_context else ""
    prompt = f"{preamble}Target: {target}\nFindings (JSON):\n{payload}"
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    report = ""
    async for event in runner.run_async(
        user_id=_USER, session_id=session_id, new_message=message
    ):
        if event.is_final_response() and event.content and event.content.parts:
            report = event.content.parts[0].text or report

    # Persist this session into the ADK memory service so future scans can
    # recall it via the `load_memory` tool. Best-effort: never fail a report.
    try:
        session = await runner.session_service.get_session(
            app_name=_APP, user_id=_USER, session_id=session_id
        )
        if session is not None:
            await SgaiMemoryService().add_session_to_memory(session)
    except Exception:  # noqa: BLE001 — memory persistence is best-effort
        pass

    return report


async def run_agent_scan(repo: str) -> str:
    """Run the multi-agent pipeline against ``repo`` and return the final report.

    Args:
        repo: Absolute path to the repository to audit. Used as the sandbox root
            for every MCP tool call.

    Returns:
        The final report text produced by the pipeline's report agent.
    """
    pipeline = build_pipeline()
    runner = InMemoryRunner(agent=pipeline, app_name=_APP)
    await runner.session_service.create_session(
        app_name=_APP, user_id=_USER, session_id="scan"
    )

    prompt = (
        "Audit the repository for security vulnerabilities.\n"
        f"Absolute repository path (use this exact string as the `root` for every tool): {repo}\n"
        "Work through the pipeline and produce a final, prioritized security report."
    )
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    final = ""
    async for event in runner.run_async(
        user_id=_USER, session_id="scan", new_message=message
    ):
        if event.is_final_response() and event.content and event.content.parts:
            final = event.content.parts[0].text or final
    return final
