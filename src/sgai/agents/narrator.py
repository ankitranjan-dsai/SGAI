"""Lean multi-agent narration layer for SGAI.

The deterministic core (:mod:`sgai.runner`) gathers every finding via the
security MCP tools with zero LLM calls. These agents then *reason* over those
findings — triage first, then write the report — adding the human-facing
narrative and remediation guidance.

Two sequential LLM calls keep the pipeline comfortably inside Gemini's
free-tier rate limit while still being a genuine multi-agent ADK system.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, SequentialAgent

from sgai.config import MODEL


def build_triage_agent() -> LlmAgent:
    """Assess overall risk posture, surface urgent issues, and model exploit chains."""
    return LlmAgent(
        name="triage_agent",
        model=MODEL,
        description="Security triage analyst and threat modeler.",
        output_key="triage",
        instruction=(
            "You are a security triage analyst and threat modeler. The conversation "
            "contains a JSON list of security findings (each with id, source, severity, "
            "location, remediation, and — for dependencies — a `reachable` flag) and may "
            "include a list of pre-computed exploit chains.\n\n"
            "Do three things:\n"
            "1. Assess the overall risk posture in 2-3 sentences. Treat `reachable: true` "
            "dependency vulnerabilities as more urgent than unreached ones.\n"
            "2. List the top 3 most urgent issues to fix first and why.\n"
            "3. THREAT MODELING — reason about how findings COMBINE into exploit chains. "
            "Explicitly look for multi-step attacks, e.g. a path-traversal flaw that lets "
            "an attacker read a file containing a hardcoded API key, or a code-execution "
            "sink reached through a vulnerable dependency. For each chain, describe the "
            "attacker's steps from entry point to impact. If exploit chains are provided "
            "in the input, validate and expand on them; otherwise derive them yourself. "
            "Be concise and specific."
        ),
    )


def build_report_writer_agent() -> LlmAgent:
    """Write the final Markdown security report from findings + triage."""
    return LlmAgent(
        name="report_writer_agent",
        model=MODEL,
        description="Security report writer.",
        instruction=(
            "You are a security report writer. Using the findings JSON and the triage "
            "assessment in the conversation, write a clear Markdown security report with: "
            "an executive summary, a severity-ordered list of findings, and a concrete "
            "remediation step for each. Write for an engineer who must act today. "
            "Output only the Markdown report."
        ),
    )


def build_narration_pipeline() -> SequentialAgent:
    """Compose the triage and report-writing agents into a sequential pipeline."""
    return SequentialAgent(
        name="sgai_narration",
        sub_agents=[build_triage_agent(), build_report_writer_agent()],
    )
