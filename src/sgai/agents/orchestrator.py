"""The root orchestrator that drives the SGAI audit pipeline.

The audit is a pipeline: scan → (dependency audit ∥ static analysis) → risk
scoring → remediation → report. The dependency audit and static analysis are
independent and run as a parallel fan-out; everything else is sequential.

The user-facing orchestrator (:func:`build_root_agent`) owns the pipeline as
its sub-agent and delegates to it via ADK agent transfer; the tool-using stages
inside the pipeline reach the security MCP server through their filtered
toolsets — see docs/architecture.md.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent

from sgai.agents.specialists import (
    build_dependency_audit_agent,
    build_remediation_agent,
    build_report_agent,
    build_risk_scoring_agent,
    build_scanner_agent,
    build_static_analysis_agent,
)
from sgai.config import MODEL


def build_pipeline() -> SequentialAgent:
    """Compose the specialist agents into the full audit pipeline."""
    scanner = build_scanner_agent()

    # Dependency auditing and static analysis are independent — fan them out.
    analysis = ParallelAgent(
        name="analysis_stage",
        sub_agents=[build_dependency_audit_agent(), build_static_analysis_agent()],
    )

    risk = build_risk_scoring_agent()
    remediation = build_remediation_agent()
    report = build_report_agent()

    return SequentialAgent(
        name="sgai_pipeline",
        sub_agents=[scanner, analysis, risk, remediation, report],
    )


def build_root_agent() -> LlmAgent:
    """Build the user-facing orchestrator agent.

    The orchestrator holds the audit pipeline as its sub-agent: given a target
    repository it transfers control to ``sgai_pipeline`` (ADK auto-flow adds
    the transfer tool), the pipeline stages call the security MCP server
    through their least-privilege toolsets, and the pipeline's report agent
    produces the final answer.
    """
    return LlmAgent(
        name="sgai_orchestrator",
        model=MODEL,
        description="Coordinates a multi-agent security audit of a target repository.",
        instruction=(
            "You are SGAI, a multi-agent security-audit coordinator. When the user "
            "names a target repository (its absolute path is stated in the "
            "conversation), immediately transfer control to `sgai_pipeline`, which "
            "runs the full audit: scan → dependency audit and static analysis in "
            "parallel → risk scoring → remediation → report. Do not audit anything "
            "yourself and never invent findings — the pipeline's report is the "
            "answer. If the user asks anything other than to audit a repository, "
            "briefly explain what SGAI does and what you need (a repository path)."
        ),
        sub_agents=[build_pipeline()],
    )
