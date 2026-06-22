"""The root orchestrator that drives the SGAI audit pipeline.

The audit is a pipeline: scan → (dependency audit ∥ static analysis) → risk
scoring → remediation → report. The dependency audit and static analysis are
independent and run as a parallel fan-out; everything else is sequential.

NOTE (Day 1): the structure below reflects the intended ADK composition. The
MCPToolset binding to the security server is wired here once the agents are
fully built out — see docs/architecture.md.
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

    TODO: attach the security MCP server via MCPToolset and delegate to the
    pipeline. For now this returns the orchestrator shell.
    """
    return LlmAgent(
        name="sgai_orchestrator",
        model="gemini-2.0-flash",
        description="Coordinates a multi-agent security audit of a target repository.",
        instruction=(
            "You are SGAI. Given a target repository, run the security "
            "audit pipeline and return the final report. Keep the user informed of "
            "which stage is running."
        ),
    )
