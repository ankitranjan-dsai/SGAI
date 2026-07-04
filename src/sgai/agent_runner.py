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
from sgai.threats import detect_exploit_chains, render_threat_section

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
        from sgai.risk import suppress_dismissed

        key = target_key(label, repo)
        findings = suppress_dismissed(findings, memory.dismissals(key))
        diff = memory.diff(key, findings)
        context = _memory_context(diff)

    report = await narrate_findings(findings, target, memory_context=context, repo_dir=repo)

    if diff is not None:
        report = report.rstrip() + "\n\n" + "\n".join(_changes_section(diff))
        memory.record(target_key(label, repo), findings)

    return findings, report, diff


async def narrate_findings(
    findings: list[Finding], target: str, memory_context: str = "", repo_dir: str | None = None
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
        repo_dir: Repo root, used to load ``custom_chains.json`` for threat
            modeling when available.

    Returns:
        The agent-written Markdown report.
    """
    payload = json.dumps([_finding_to_dict(f) for f in findings], indent=2)

    # Correlate findings into exploit chains deterministically and hand the summary
    # to the triage agent so its threat-model narration is grounded, not invented.
    # The raw Mermaid graph and the recommended fix order go into the prompt too,
    # so the agent can reference specific graph nodes and the break-the-chain
    # ordering instead of inventing an attack path.
    chains = detect_exploit_chains(findings, repo_dir=repo_dir)
    chain_context = ""
    if chains:
        blocks = []
        for c in chains:
            entry = " [internet-facing entry point]" if c.internet_facing else ""
            fix_order = " ; ".join(
                f"{s['rank']}) {s['location']} ({s['id']})"
                for s in c.recommended_fix_order
            )
            blocks.append(
                f"- {c.name} ({c.severity.label}){entry}: "
                + " → ".join(f.location for f in c.findings)
                + f" ⇒ {c.impact}\n"
                f"  Recommended fix order: {fix_order}\n"
                "  Mermaid graph:\n"
                "  ```mermaid\n"
                + "\n".join("  " + line for line in c.mermaid().splitlines())
                + "\n  ```"
            )
        chain_context = (
            "Pre-computed exploit chains (narrate these; reference the Mermaid "
            "node labels and the recommended fix order):\n"
            + "\n".join(blocks)
            + "\n\n"
        )

    pipeline = build_narration_pipeline()
    runner = InMemoryRunner(agent=pipeline, app_name=_APP)
    session_id = _session_id(target)
    await runner.session_service.create_session(
        app_name=_APP, user_id=_USER, session_id=session_id
    )

    preamble = f"{memory_context}\n\n" if memory_context else ""
    prompt = f"{preamble}{chain_context}Target: {target}\nFindings (JSON):\n{payload}"
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    report = ""
    async for event in runner.run_async(
        user_id=_USER, session_id=session_id, new_message=message
    ):
        if event.is_final_response() and event.content and event.content.parts:
            report = event.content.parts[0].text or report

    # Guarantee the Mermaid exploit-chain graphs are present even if the LLM
    # narrated the chains only in prose — the deterministic section renders the
    # graphs the report UI expects.
    if chains and "```mermaid" not in report:
        report = report.rstrip() + "\n\n" + "\n".join(render_threat_section(chains))

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


def llm_available() -> bool:
    """True when a Gemini API key is configured, so LLM calls won't hang offline."""
    import os

    return bool(os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY"))


async def refine_patch_chat(
    code: str, message: str, history: list[dict], patch_summary: str
) -> str:
    """One turn of the interactive remediation chat; returns the assistant reply.

    Raises if no model is configured or the model errors — the caller is expected
    to fall back to a deterministic responder so the chat always answers.
    """
    from sgai.agents.specialists import build_remediation_chat_agent

    if not llm_available():
        raise RuntimeError("no model configured")

    runner = InMemoryRunner(agent=build_remediation_chat_agent(), app_name=_APP)
    session_id = "chat-" + hashlib.sha1((code + str(len(history))).encode()).hexdigest()[:12]
    await runner.session_service.create_session(
        app_name=_APP, user_id=_USER, session_id=session_id
    )

    transcript = "\n".join(f"{m.get('role', 'user')}: {m.get('content', '')}" for m in history)
    prompt = (
        f"Code under review:\n```python\n{code}\n```\n\n"
        f"SGAI's proposed patches:\n{patch_summary}\n\n"
        + (f"Conversation so far:\n{transcript}\n\n" if transcript else "")
        + f"Developer: {message}"
    )
    content = types.Content(role="user", parts=[types.Part(text=prompt)])

    reply = ""
    async for event in runner.run_async(
        user_id=_USER, session_id=session_id, new_message=content
    ):
        if event.is_final_response() and event.content and event.content.parts:
            reply = event.content.parts[0].text or reply
    return reply


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
