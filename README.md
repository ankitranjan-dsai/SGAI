# SGAI — SecureGuardAI

> A multi-agent security review system that audits a codebase for vulnerabilities, maps findings to known CVEs, scores them by risk, and proposes remediation — autonomously.

**Kaggle AI Agents Capstone — Track: Freestyle**

SGAI points a team of specialist agents at any Python repository. They scan the source, audit dependencies against the live [OSV.dev](https://osv.dev) vulnerability database, run static analysis, score and de-duplicate the findings by severity, and generate a prioritized, remediation-ready security report — in minutes instead of weeks.

---

## Why agents?

A security audit is naturally parallel and specialized. No single prompt can simultaneously enumerate source files, query a CVE database, run a static analyzer, reason about exploitability, and write patches. SGAI gives each of those jobs to a dedicated agent and coordinates them with an orchestrator — which is exactly what makes the multi-agent architecture *necessary* rather than decorative.

## Architecture

```
                          ┌──────────────────────┐
        target repo  ──▶  │   OrchestratorAgent  │
                          └──────────┬───────────┘
                                     │ coordinates
        ┌────────────┬───────────────┼───────────────┬──────────────┐
        ▼            ▼               ▼               ▼              ▼
  ScannerAgent  DependencyAudit  StaticAnalysis  RiskScoring   Remediation
   (enumerate    (OSV.dev CVE     (Bandit SAST)   (dedupe +     (propose
    sources)      lookup)                          CVSS rank)    patches)
        │            │               │               │              │
        └────────────┴───────────────┴───────┬───────┴──────────────┘
                                              ▼
                                       ReportAgent
                              (prioritized Markdown report
                                  + optional GitHub PR)
```

All security tooling (CVE lookups, static analysis, sandboxed file reads) is exposed through a **custom MCP server** that the agents call as tools. This keeps the security capabilities cleanly decoupled, independently testable, and reusable by any MCP-compatible client.

## Required course concepts demonstrated

| Concept | How SGAI demonstrates it |
|---|---|
| **Multi-agent system (ADK)** | Orchestrator + 6 specialist agents built on Google's Agent Development Kit |
| **MCP Server** | Custom server (`src/sgai/mcp_server`) exposing OSV.dev CVE lookup, Bandit static analysis, and sandboxed file tools |
| **Security features** | Sandboxed file access scoped to the target repo, least-privilege GitHub token, auditable/traceable findings, input validation |

## Status

See [docs/architecture.md](docs/architecture.md) for the build roadmap.

- [x] Project structure, packaging, MCP server
- [x] OSV.dev dependency-scan tool (working)
- [x] Bandit static-analysis tool (working)
- [x] ADK agents wired to the MCP server (least-privilege toolsets)
- [x] Risk scoring + Markdown report generation
- [x] `sgai scan` runs end-to-end (deterministic core, no API key required)
- [ ] Agent-driven pipeline run (needs `GOOGLE_API_KEY`)
- [ ] Optional: GitHub PR creation
- [ ] Deployment (Cloud Run) + demo

## Setup

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
# clone, then from the repo root:
uv sync                      # create venv + install dependencies
cp .env.example .env         # add your GOOGLE_API_KEY

# run the security MCP server standalone
uv run python -m sgai.mcp_server.server

# run a scan (CLI — coming soon)
uv run sgai scan ./examples/vulnerable_app
```

## License

MIT © 2026 Ankit Ranjan
