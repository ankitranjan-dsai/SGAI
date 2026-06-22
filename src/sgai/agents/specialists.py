"""The six specialist agents that make up the SGAI audit pipeline.

Each builder returns a configured ADK ``LlmAgent``. The scanner, dependency, and
static-analysis agents are bound to the security MCP server via a *filtered*
``MCPToolset`` so each sees only the tools it needs (least privilege). The risk,
remediation, and report agents reason over the prior agents' output and need no
tools of their own.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent

from sgai.agents.security_tools import (
    DEPENDENCY_TOOLS,
    SCANNER_TOOLS,
    STATIC_ANALYSIS_TOOLS,
    build_security_toolset,
)
from sgai.config import MODEL


def build_scanner_agent() -> LlmAgent:
    """Enumerate the target repo and identify source files and dependency manifests."""
    return LlmAgent(
        name="scanner_agent",
        model=MODEL,
        description="Enumerates source files and dependency manifests in the target repo.",
        instruction=(
            "You map the attack surface of a codebase. Use the source-listing tools "
            "to enumerate Python files and locate dependency manifests "
            "(requirements.txt, pyproject.toml). Report a structured inventory: "
            "source files to analyze and manifests to audit. Do not analyze content."
        ),
        tools=[build_security_toolset(SCANNER_TOOLS)],
    )


def build_dependency_audit_agent() -> LlmAgent:
    """Audit pinned dependencies against the OSV.dev vulnerability database."""
    return LlmAgent(
        name="dependency_audit_agent",
        model=MODEL,
        description="Audits dependencies against OSV.dev and reports known CVEs.",
        instruction=(
            "You audit third-party dependencies. Given a requirements manifest, use "
            "the dependency-scan tools to check each pin against OSV.dev. Report every "
            "vulnerable package with its version and the matched vulnerability IDs."
        ),
        tools=[build_security_toolset(DEPENDENCY_TOOLS)],
    )


def build_static_analysis_agent() -> LlmAgent:
    """Run static analysis (Bandit) over the source and collect findings."""
    return LlmAgent(
        name="static_analysis_agent",
        model=MODEL,
        description="Runs Bandit static analysis and collects code-level findings.",
        instruction=(
            "You find vulnerabilities in source code. Use the static-analysis tool to "
            "run Bandit over the source files identified by the scanner. Report each "
            "finding with its severity, confidence, location, and a one-line explanation."
        ),
        tools=[build_security_toolset(STATIC_ANALYSIS_TOOLS)],
    )


def build_risk_scoring_agent() -> LlmAgent:
    """De-duplicate and prioritize findings by exploitability and severity."""
    return LlmAgent(
        name="risk_scoring_agent",
        model=MODEL,
        description="De-duplicates and ranks all findings by risk.",
        instruction=(
            "You triage. Merge the dependency and static-analysis findings, remove "
            "duplicates, and rank them by severity and exploitability into "
            "Critical / High / Medium / Low. Output an ordered, de-duplicated list."
        ),
    )


def build_remediation_agent() -> LlmAgent:
    """Propose concrete fixes for the prioritized findings."""
    return LlmAgent(
        name="remediation_agent",
        model=MODEL,
        description="Proposes concrete remediation for each finding.",
        instruction=(
            "You fix problems. For each prioritized finding, propose a concrete "
            "remediation: a safe version to upgrade a dependency to, or a code change "
            "to remove an unsafe pattern. Be specific and minimal."
        ),
    )


def build_report_agent() -> LlmAgent:
    """Synthesize everything into a prioritized Markdown security report."""
    return LlmAgent(
        name="report_agent",
        model=MODEL,
        description="Writes the final prioritized security report.",
        instruction=(
            "You communicate findings. Produce a clear Markdown security report: an "
            "executive summary, a severity-ordered table of findings, and the proposed "
            "remediation for each. Write for an engineer who needs to act today."
        ),
    )
