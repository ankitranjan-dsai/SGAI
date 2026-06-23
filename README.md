# SGAI — SecureGuardAI

> A multi-agent security review system that audits a codebase for vulnerabilities, maps findings to known CVEs, scores them by risk, and proposes remediation — autonomously.

**Kaggle AI Agents Capstone — Track: Freestyle**

SGAI points a team of specialist agents at any Python repository. They scan the source, audit dependencies against the live [OSV.dev](https://osv.dev) vulnerability database, run static analysis, score and de-duplicate the findings by severity, and generate a prioritized, remediation-ready security report — in minutes instead of weeks.

---

## Quick start — one command

**macOS / Linux**

```bash
./run.sh
```

**Windows (PowerShell)**

```powershell
./run.ps1
```

That's it — the script installs everything it needs (via [`uv`](https://docs.astral.sh/uv/)), starts SGAI, and opens **http://localhost:8080** in your browser.

### 📱 Use it from your phone

SGAI's web app is mobile-first. Two ways to scan from a phone:

1. **Same Wi-Fi:** after running the command above, open `http://<your-computer-ip>:8080` in your phone's browser.
2. **Deployed:** host it on Cloud Run (see [docs/deploy.md](docs/deploy.md)) and open the public URL anywhere.

Paste a `requirements.txt` and/or some code, tap **Scan**, and get a ranked report — no install on the phone.

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
| **Security features** | Sandboxed file access (path-traversal + symlink safe), least-privilege per-agent toolsets, stateless request handling, input validation |
| **Deployability** *(bonus)* | Stateless FastAPI service (`src/sgai/api.py`) + Dockerfile, Cloud Run ready — see [docs/deploy.md](docs/deploy.md) |

## Status

See [docs/architecture.md](docs/architecture.md) for the build roadmap.

- [x] Project structure, packaging, MCP server
- [x] OSV.dev dependency-scan tool (working)
- [x] Bandit static-analysis tool (working)
- [x] ADK agents wired to the MCP server (least-privilege toolsets)
- [x] Risk scoring + Markdown report generation
- [x] `sgai scan` runs end-to-end (deterministic core, no API key required)
- [x] Agent-driven report via `sgai scan --explain` (triage → report agents, Gemini)
- [ ] Optional: GitHub PR creation
- [ ] Deployment (Cloud Run) + demo

## Setup

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
# clone, then from the repo root:
uv sync                      # create venv + install dependencies

# run a scan — deterministic core, NO API key required:
uv run sgai scan ./examples/vulnerable_app

# add a Gemini key for the multi-agent narrated report:
cp .env.example .env         # then put your GOOGLE_API_KEY in .env
uv run sgai scan ./examples/vulnerable_app --explain

# or run the security MCP server standalone:
uv run python -m sgai.mcp_server.server
```

Get a free Gemini key at https://aistudio.google.com/apikey. The free tier allows
5 requests/minute, which the lean two-agent narration layer stays within.

## License

MIT © 2026 Ankit Ranjan
