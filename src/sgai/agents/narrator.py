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
    """Assess overall risk posture and surface the most urgent issues."""
    return LlmAgent(
        name="triage_agent",
        model=MODEL,
        description="Security triage analyst.",
        output_key="triage",
        instruction=(
            "You are a security triage analyst. The conversation contains a JSON list "
            "of security findings (each with id, source, severity, location, and "
            "remediation). Assess the overall risk posture in 2-3 sentences, then list "
            "the top 3 most urgent issues to fix first and why. Be concise and specific."
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
