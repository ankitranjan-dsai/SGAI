# SGAI — Architecture

## Overview

SGAI audits a Python repository for security vulnerabilities using a
team of specialist agents coordinated by an orchestrator. The agents reach the
outside world only through a custom MCP server, which mediates and sandboxes
every CVE lookup, static-analysis run, and file read.

## Components

### 1. Security MCP server (`src/sgai/mcp_server`)

A standalone MCP server exposing the security toolbox:

| Tool | Purpose | Backed by |
|---|---|---|
| `scan_dependency` | Check one package for CVEs | OSV.dev `/v1/query` |
| `scan_requirements_file` | Audit a whole requirements.txt | OSV.dev `/v1/querybatch` |
| `run_static_analysis` | Find unsafe code patterns | Bandit |
| `list_source_files` | Enumerate sources (sandboxed) | filesystem |
| `read_source_file` | Read one source file (sandboxed) | filesystem |

**Security boundary.** Every filesystem tool routes through `sandbox.safe_resolve`,
which fully resolves the path (defeating `..` and symlinks) and rejects anything
outside the allow-listed scan root.

### 2. Agent team (`src/sgai/agents`)

```
OrchestratorAgent
└── SequentialAgent: sgai_pipeline
    ├── scanner_agent
    ├── ParallelAgent: analysis_stage
    │   ├── dependency_audit_agent   (OSV.dev)
    │   └── static_analysis_agent    (Bandit)
    ├── risk_scoring_agent
    ├── remediation_agent
    └── report_agent
```

The dependency audit and static analysis are independent, so they fan out in
parallel; the remaining stages are sequential because each consumes the previous
stage's output.

### 3. CLI (`src/sgai/cli.py`)

`sgai scan <repo>` is the entry point that kicks off the orchestrator.

## Required course concepts

1. **Multi-agent system (ADK)** — orchestrator + 6 specialists, sequential and
   parallel composition.
2. **MCP Server** — the custom security toolbox above.
3. **Security features** — path sandboxing, least-privilege GitHub token,
   input validation, auditable findings.

## Build roadmap

- [x] **M0 — Foundation:** packaging, config, MCP server with working OSV.dev +
  Bandit + sandboxed file tools, example vulnerable app, sandbox unit test.
- [x] **M1 — Wire agents to MCP:** specialists bound to the security server via a
  filtered `MCPToolset` (least-privilege tool access, verified over stdio).
- [x] **M2 — Risk + report:** deterministic normalization, de-duplication, risk
  ranking (`risk.py`) and Markdown report generation (`report.py`); see
  `examples/sample_report.md`.
- [ ] **M3 — CLI end-to-end:** `sgai scan` runs the full pipeline.
- [ ] **M4 — Optional GitHub PR:** open a remediation PR with a scoped token.
- [ ] **M5 — Deploy + demo:** Cloud Run + the <5-minute demo video.
