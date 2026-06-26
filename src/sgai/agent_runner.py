"""Agent-driven scan runner for SGAI.

Runs the real multi-agent ADK pipeline (scanner → parallel dependency/static
analysis → risk → remediation → report) via an ADK ``Runner``. The agents call
the security MCP server for every tool action and produce a narrated security
report.

This is the LLM path; :mod:`sgai.runner` is the deterministic fallback.
"""

from __future__ import annotations

import json

from google.adk.runners import InMemoryRunner
from google.genai import types

from sgai.agents.narrator import build_narration_pipeline
from sgai.agents.orchestrator import build_pipeline
from sgai.models import Finding
from sgai.runner import run_scan

_APP = "sgai"
_USER = "user"


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
    repo: str, label: str | None = None, deep: bool = False
) -> tuple[list[Finding], str]:
    """Gather findings deterministically, then narrate them with the agent layer.

    The deterministic core finds vulnerabilities with zero LLM calls; the
    two-agent narration pipeline (triage → report writer) then produces the
    human-facing report. This keeps LLM usage within the free-tier rate limit.

    Args:
        repo: Path to the repository to audit.
        label: Display name for the report (e.g. a GitHub URL); defaults to repo.

    Returns:
        A tuple of (findings, agent-written Markdown report).
    """
    findings, _ = await run_scan(repo, label=label, deep=deep)
    report = await narrate_findings(findings, label or repo)
    return findings, report


async def narrate_findings(findings: list[Finding], target: str) -> str:
    """Run the two-agent narration pipeline over already-gathered findings.

    Shared by the CLI (`sgai scan --explain`) and the web API, so any source of
    findings can get an agent-written report without re-scanning.

    Args:
        findings: The findings to narrate.
        target: Label for what was scanned (path, "submitted code", etc.).

    Returns:
        The agent-written Markdown report.
    """
    payload = json.dumps([_finding_to_dict(f) for f in findings], indent=2)

    pipeline = build_narration_pipeline()
    runner = InMemoryRunner(agent=pipeline, app_name=_APP)
    await runner.session_service.create_session(
        app_name=_APP, user_id=_USER, session_id="report"
    )

    prompt = f"Target: {target}\nFindings (JSON):\n{payload}"
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    report = ""
    async for event in runner.run_async(
        user_id=_USER, session_id="report", new_message=message
    ):
        if event.is_final_response() and event.content and event.content.parts:
            report = event.content.parts[0].text or report
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
