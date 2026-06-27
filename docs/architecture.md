# SGAI — Architecture

## Overview

SGAI is a **Python-first** security reviewer: it runs Bandit static analysis on
Python source, audits dependency manifests across **multiple ecosystems**
(PyPI, npm, Go, crates.io) against OSV.dev, and — with `--deep` — adds optional
**Semgrep** multi-language static analysis (JavaScript, Go, Java, …). A team of
specialist agents, coordinated by an orchestrator, drives the audit and reaches
the outside world only through a custom MCP server, which mediates and sandboxes
every CVE lookup, static-analysis run, and file read.

## Components

### 1. Security MCP server (`src/sgai/mcp_server`)

A standalone MCP server exposing the security toolbox:

| Tool | Purpose | Backed by |
|---|---|---|
| `scan_dependency` | Check one package for CVEs | OSV.dev `/v1/query` |
| `scan_requirements_file` | Audit a whole requirements.txt | OSV.dev `/v1/querybatch` |
| `scan_manifest` | Audit any supported manifest (PyPI/npm/Go/crates.io) | OSV.dev + `manifests.py` |
| `run_static_analysis` | Find unsafe Python code patterns | Bandit |
| `run_semgrep` | Multi-language static analysis (optional, `--deep`) | Semgrep via `uvx` |
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
stage's output. This is the **fully autonomous** pipeline (`agent_runner.run_agent_scan`)
where agents drive every tool call; it needs a higher Gemini rate limit.

**Default narration layer (`agents/narrator.py`).** Because the free Gemini tier
allows only 5 requests/minute, the default agent path is leaner: the deterministic
core gathers every finding via the MCP tools with **zero LLM calls**, then a
two-agent `SequentialAgent` (triage → report writer) reasons over the findings to
produce the narrated report. Same multi-agent ADK system, reliably within free-tier
limits. Run it with `sgai scan <repo> --explain`.

### 3. CLI (`src/sgai/cli.py`)

`sgai scan <repo>` runs the deterministic audit; add `--explain` to write the
report with the multi-agent narration layer. `sgai history <repo>` and
`sgai accept <repo> <id>` drive the memory layer below.

### 4. Sessions & Memory (`src/sgai/memory.py`)

`ScanMemory` is a JSON-backed, per-target store of every scan plus a list of
accepted risks. Each scan computes a `ScanDiff` against the previous snapshot —
**new / fixed / still-open** findings — which flows into the report, the CLI
banner, and the API/UI. Findings are matched across scans by a stable
`fingerprint` (source + id + location), so an upgrade reads as "fixed" and a
freshly-introduced CVE reads as "new". `SgaiMemoryService` adapts the same store
to ADK's `BaseMemoryService` contract, so the agent layer can persist a session
and recall it later through the built-in `load_memory` tool. Storage lives under
`~/.sgai/` (override with `$SGAI_HOME`); remote targets are keyed by URL so the
deployed service tracks repos across calls.

## Required course concepts

1. **Multi-agent system (ADK)** — orchestrator + 6 specialists, sequential and
   parallel composition.
2. **MCP Server** — the custom security toolbox above.
3. **Security features** — path sandboxing, least-privilege GitHub token,
   input validation, auditable findings.
4. **Sessions & Memory** (course Day 3) — persistent per-target scan memory with
   cross-scan diffing and an ADK `MemoryService` adapter (`memory.py`).

## Build roadmap

- [x] **M0 — Foundation:** packaging, config, MCP server with working OSV.dev +
  Bandit + sandboxed file tools, example vulnerable app, sandbox unit test.
- [x] **M1 — Wire agents to MCP:** specialists bound to the security server via a
  filtered `MCPToolset` (least-privilege tool access, verified over stdio).
- [x] **M2 — Risk + report:** deterministic normalization, de-duplication, risk
  ranking (`risk.py`) and Markdown report generation (`report.py`); see
  `examples/sample_report.md`.
- [x] **M3 — CLI end-to-end:** `sgai scan <repo>` discovers manifests + source,
  runs the tools, scores, and writes a Markdown report (`runner.py`, `cli.py`).
- [ ] **M4 — Optional GitHub PR:** open a remediation PR with a scoped token.
- [x] **M4.5 — Live agent run:** multi-agent narration (`agents/narrator.py`,
  `agent_runner.py`) writes the report via Gemini; `sgai scan --explain`.
- [x] **M6 — Sessions & Memory:** `memory.py` — persistent per-target scan
  history, new/fixed/still-open diffing in every report, accepted risks
  (`sgai history` / `sgai accept`), and an ADK `MemoryService` adapter.
- [~] **M5 — Deploy + demo:** stateless FastAPI service (`api.py`) + Dockerfile +
  Cloud Run docs (`docs/deploy.md`) done; demo video remains.
