# SGAI — SecureGuardAI

> A multi-agent security reviewer that audits a codebase for vulnerable dependencies and unsafe code patterns, scores them by risk, explains them, and proposes fixes — and remembers what changed since last time.

**Kaggle AI Agents: Intensive Vibe Coding Capstone — Track: Freestyle**

[![CI](https://github.com/ankitranjan-dsai/SGAI/actions/workflows/ci.yml/badge.svg)](https://github.com/ankitranjan-dsai/SGAI/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ankitranjan-dsai/SGAI)](https://github.com/ankitranjan-dsai/SGAI/releases)
[![Container](https://img.shields.io/badge/ghcr.io-sgai-blue?logo=docker&logoColor=white)](https://github.com/ankitranjan-dsai/SGAI/pkgs/container/sgai)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

| | |
|---|---|
| **Live demo** | _coming soon_ — local demo available now: run `./run.sh` |
| **Demo video** | _coming soon_ |
| **Kaggle writeup** | _coming soon_ |

---

## Problem

AI coding assistants now write huge amounts of code, fast. Almost none of it is
checked for *security* before it ships: a pinned dependency with a known CVE, a
`subprocess(…, shell=True)`, a `yaml.load` on untrusted input. Security review is
slow, specialized, and easy to skip — so vulnerabilities pile up silently, and
nobody can answer "is this getting better or worse since last week?"

## Solution

SGAI points a team of specialist agents at any repository — a local path or a
GitHub URL. They audit dependency manifests across **PyPI, npm, Go, and
crates.io** (requirements, `pyproject.toml`, `poetry.lock`, `uv.lock`,
`Pipfile.lock`, `package-lock.json`, `go.mod`, `Cargo.lock`) against the live
[OSV.dev](https://osv.dev) database, run **Bandit**
static analysis on Python (and optional **Semgrep** multi-language analysis with
`--deep`), de-duplicate and risk-rank the findings, write a remediation-ready
report, and can preview dependency fixes — and optionally open a remediation PR
for a repo you own. Because it stores every scan, it also tells you exactly
**what's new, what's fixed, and what's still open** since the last run.

Five capabilities take it past a scanner:

- **Self-healing patches** (`sgai heal`) — maps Bandit/Semgrep findings to
  AST-safe refactorings (`yaml.load`→`yaml.safe_load`, `eval`→`ast.literal_eval`,
  `shell=True`→`shlex.split`, weak hashes→`sha256`, hardcoded secrets→env vars),
  applies them, runs the project's own tests through a sandboxed `validate_patch`
  tool, and **rolls back any patch that breaks the suite**.
- **Dependency reachability** — a static import graph decides whether a
  vulnerable package is actually imported. Reachable CVEs are **upgraded** in
  severity; unused ones are **downgraded**, so triage targets what's exploitable.
- **Threat modeling & exploit chains** — correlates individual findings into
  end-to-end attack paths (e.g. path-traversal + hardcoded key → credential
  disclosure), rendered as **Mermaid graphs** in the report.
- **Container & secret scanning** — Dockerfile/compose/Terraform misconfigurations
  (unpinned base images, root/privileged containers, open CIDRs) plus
  entropy-based secret detection with an **LLM pass to weed out dummy credentials**.
- **Interactive playground** — a web UI to watch code get patched in a
  side-by-side diff and **chat with the remediation agent over SSE** to refine fixes.

It runs three ways from one codebase: a **CLI**, a **mobile-friendly web app**,
and a reusable **MCP server** any agent can call.

> **Scope, stated honestly:** Python-first static analysis (Bandit) +
> multi-ecosystem dependency-manifest CVE scanning + optional Semgrep
> multi-language static analysis under `--deep`.

### Advanced suite (v3)

Building on the pillars above — **zero-LLM detection** (all detection is fast,
deterministic local analysis; the LLM only narrates, triages, and powers the
chat copilot) and **deterministic scan diffs** (`source:id:location`
fingerprints in a JSON `ScanMemory`) — SGAI adds:

- **Self-healing v2** — `validate_patch` auto-detects and runs `pytest`,
  `npm test`, `go test`, and `cargo test` under a strict 30 s timeout;
  patch **confidence scoring** orders rewrites; a **binary-search rollback**
  isolates the minimal breaking subset in `O(b·log n)` test runs.
  `POST /commit-patch` writes a validated diff inside the sandbox.
- **Reachability v2** — production-vs-test file classification, **transitive
  import closure**, and a multi-language import graph (Python, JS/TS, Go, Rust).
  Test-only imports are downgraded; production imports upgraded. Each finding
  carries a tri-state `reachability` (`production` / `test_only` / `unreached`).
- **CVSS-accurate dependency severity** — each advisory's full OSV record is
  fetched and its CVSS vector (v4 > v3 > v2) scored into the standard bands
  (≥9.0 Critical, ≥7.0 High, ≥4.0 Medium, else Low), falling back to the
  database's own label, then HIGH only when no signal exists — so a CVSS 9.8
  RCE and a CVSS 3.1 ReDoS no longer rank identically.
- **Typosquatting detector** — flags dependency names one edit, an adjacent
  transposition, a homoglyph, or an affix away from a popular package
  (`requsts`, `lodahs`, `crypt0graphy`, `requests2`) — supply-chain risk caught
  before any CVE exists. Pure string analysis, zero network.
- **Context-aware secrets** — the LLM verifier sees rich context (file, variable,
  surrounding lines/comments) with **every secret value masked**; test/fixture
  secrets auto-downgrade to Info; each finding gets a **rotation-urgency** score.
- **Threat modeling v2** — user `custom_chains.json` templates, a
  **recommended fix order** to break each chain (numbered `🔧1 → 🔧2` directly
  on the Mermaid graph), **internet-facing** entry-point weighting, and raw
  Mermaid handed to the triage agent.
- **Security copilot UI** — clickable finding cards seed a contextual chat, a
  **Commit patch** button re-validates fixes, chat sessions persist per target,
  and a multi-file playground shows cross-file patches.
- **Policy-as-Code** — `.sgai/policy.yml` gates (`no-critical-in-production`,
  `max-unpatched-cves`, …); `sgai check` exits non-zero on violation for CI.
- **PR differential scanning** — `git diff` delta analysis reports only findings
  **newly introduced** by a change; `POST /scan/pr` posts inline GitHub reviews.
- **SBOM & VEX** — `GET /sbom` (CycloneDX/SPDX) and `GET /vex` (OpenVEX, mapping
  reachability to `affected` / `not_affected` / `under_investigation`).
- **False-positive dismissals** — `POST /dismiss` + `/undismiss`; dismissed
  findings (by fingerprint or pattern) are auto-suppressed on future scans.
- **Trend dashboard** — `GET /trends` and a Chart.js **Trends** tab plotting
  findings and risk score over time from `ScanMemory`.

## Why agents?

A security audit is naturally parallel and specialized. No single prompt can
simultaneously enumerate source files, query a CVE database, run a static
analyzer, reason about exploitability, and write patches. SGAI gives each of
those jobs to a dedicated agent and coordinates them with an orchestrator — which
is what makes the multi-agent architecture *necessary* rather than decorative.

## Architecture

```
                          ┌──────────────────────┐
        target repo  ──▶  │   OrchestratorAgent  │
                          └──────────┬───────────┘
                                     │ coordinates
        ┌────────────┬───────────────┼───────────────┬──────────────┐
        ▼            ▼               ▼               ▼              ▼
  ScannerAgent  DependencyAudit  StaticAnalysis  RiskScoring   Remediation
   (enumerate    (OSV.dev CVE     (Bandit/Semgrep) (dedupe +    (propose
    sources)      lookup)                          rank)         fixes)
        │            │               │               │              │
        └────────────┴───────────────┴───────┬───────┴──────────────┘
                                              ▼
                                       ReportAgent
                              (prioritized Markdown report
                                  + optional GitHub PR)
```

All security tooling (CVE lookups, static analysis, sandboxed file reads) is
exposed through a **custom MCP server** the agents call as tools — cleanly
decoupled, independently testable, and reusable by any MCP-compatible client.
See [docs/architecture.md](docs/architecture.md).

## Required course concepts demonstrated — all 6, plus Sessions & Memory

| Concept | How SGAI demonstrates it |
|---|---|
| **Multi-agent system (ADK)** | Orchestrator + 6 specialist agents, plus a triage→report narration pipeline, built on Google's Agent Development Kit |
| **MCP Server** | Custom server (`src/sgai/mcp_server`) exposing OSV.dev CVE lookup, Bandit + Semgrep static analysis, and sandboxed file tools |
| **Security features** | Sandboxed file access (path-traversal + symlink safe), least-privilege per-agent toolsets, stateless requests, input validation — see [docs/security.md](docs/security.md) |
| **Deployability** | Stateless FastAPI service (`src/sgai/api.py`) + Dockerfile, Cloud Run ready — see [docs/deploy.md](docs/deploy.md) |
| **Agent skills / Agents CLI** | Packaged as the `sgai` CLI and a reusable skill ([SKILL.md](SKILL.md)); installable with `uv tool install` |
| **Antigravity** | Security MCP server plugs into Antigravity (and any MCP agent) — see [docs/integrations.md](docs/integrations.md) |
| **Sessions & Memory** *(course Day 3)* | Persistent per-target scan memory (`src/sgai/memory.py`) reports **new / fixed / still open** since the last scan and remembers accepted risks; also exposed as a real ADK `MemoryService` so agents can recall prior scans via `load_memory` |

## Quick start

**Just double-click — no terminal needed:**

| OS | Double-click | Or from a terminal |
|---|---|---|
| **macOS** | `run.command` | `./run.sh` |
| **Windows** | `run.bat` | `./run.ps1` (PowerShell) |
| **Linux** | — | `./run.sh` |

Any of these installs everything it needs (via [`uv`](https://docs.astral.sh/uv/)),
starts SGAI, and opens **http://localhost:8080** once the server is ready.

> First macOS double-click: if you see "unidentified developer", right-click
> `run.command` → **Open** → **Open** (only needed once). On Windows, `run.bat`
> handles the PowerShell execution policy for you.

## Web demo

SGAI's web app is mobile-first:

1. **Same Wi-Fi:** open `http://<your-computer-ip>:8080` on your phone.
2. **Deployed:** host it on Cloud Run (below) and open the public URL anywhere.

Paste a `requirements.txt` and/or some code (or click **Use sample vulnerable
input**), tap **Scan**, and get a ranked report with a risk summary, findings +
fixes, and the "changes since last scan" diff — no install on the phone. The UI
has three tabs:

1. **Scan Results** — the ranked report, with exploit-chain **Mermaid** diagrams.
2. **Code Playground** — paste code and watch SGAI patch it in a **side-by-side diff**.
3. **Interactive Agent Chat** — chat with the remediation agent over **SSE** to
   refine a fix, then apply it back into the playground.

## Demo commands

A self-contained, intentionally-vulnerable repo lives at
[`examples/kaggle_demo_repo`](examples/kaggle_demo_repo) — PyPI + npm + Go
dependency CVEs, unsafe Python for Bandit, and an insecure `server.js` for
Semgrep. **No API key required.**

```bash
uv run sgai scan ./examples/kaggle_demo_repo            # rich report — typically ~20+ findings (deps + Bandit)
uv run sgai scan ./examples/kaggle_demo_repo --deep     # Semgrep adds more findings when available
uv run sgai scan ./examples/kaggle_demo_repo --sarif out.sarif
uv run sgai history ./examples/kaggle_demo_repo         # the scan timeline
```

## CLI usage

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync                                       # create venv + install deps (incl. dev tools)

uv run sgai scan ./examples/vulnerable_app    # deterministic scan, NO API key
uv run sgai scan https://github.com/owner/repo   # audit any public repo by URL
uv run sgai scan ./examples/multi_lang --deep    # + Semgrep multi-language SAST
uv run sgai scan ./path --sarif out.sarif        # SARIF 2.1.0 for code scanning

uv run sgai fix ./examples/vulnerable_app     # preview dependency upgrades (dry run)
uv run sgai fix . --open-pr                    # open a remediation PR (repo you own)

uv run sgai heal ./path --dry-run             # preview AST-safe code patches (diff)
uv run sgai heal ./path                        # apply patches, validated by the repo's tests

uv run sgai check ./path                       # CI gate: exits non-zero on policy violation

uv run sgai scan ./path --explain             # multi-agent narrated report (Gemini)
uv run sgai scan ./path --agentic             # fully autonomous: orchestrator + 6-agent
                                              #   pipeline doing its own MCP tool calls
                                              #   (needs Gemini quota headroom)
uv run sgai history ./path                     # scan timeline (new/fixed over time)
uv run sgai accept ./path <finding-id> --reason "tracked in JIRA-123"

uv run python -m sgai.mcp_server.server       # run the security MCP server standalone
```

### HTTP API (deployable service)

Beyond `GET /health`, `GET /`, and `POST /scan[/stream]`, the service exposes:
`POST /commit-patch`, `POST /heal` + `POST /heal/multi`, `POST /chat` (SSE) +
`WS /chat/ws` (bidirectional) + `GET/POST/DELETE /chat/session`,
`POST /scan/check`, `POST /scan/pr`, `POST /fix/plan`,
`GET /sbom`, `GET /vex`, `POST /dismiss` + `POST /undismiss`, and `GET /trends`.

A free Gemini key (https://aistudio.google.com/apikey) is **only** needed for
`--explain`; the free tier's 5 req/min is enough for the lean two-agent narration.

## MCP tools

Running `python -m sgai.mcp_server.server` gives any MCP client these tools:

| Tool | Purpose |
|---|---|
| `scan_manifest` | Audit a dependency manifest (PyPI/npm/Go/crates.io) against OSV.dev |
| `scan_dependency` | Check a single package for CVEs |
| `scan_requirements_file` | Audit a whole `requirements.txt` |
| `run_static_analysis` | Bandit static analysis (Python) |
| `run_semgrep` | Multi-language static analysis (optional) |
| `scan_dockerfile` | Dockerfile / compose / Terraform misconfiguration checks |
| `scan_secrets` | High-entropy + known-format secret detection (LLM dummy filtering) |
| `validate_patch` | Run the target project's own tests inside the sandbox (self-healing) |
| `list_source_files` / `read_source_file` | Sandboxed source access |

Wiring it into Antigravity, Claude Code, or the Gemini CLI: see
[docs/mcp.md](docs/mcp.md) and [docs/integrations.md](docs/integrations.md).

## Memory — "what changed since last scan?"

A one-off report tells you what's wrong *now*. SGAI also **remembers every scan
of a target** and answers what teams ask at standup: *what changed?*

```bash
uv run sgai scan ./myproject           # 1st run: saves a baseline
# …fix some deps, introduce others…
uv run sgai scan ./myproject           # 2nd run: "3 new · 1 fixed · 8 still open"
uv run sgai history ./myproject        # the full scan timeline
uv run sgai accept ./myproject CVE-... --reason "patch scheduled Q3"
```

Every report gains a **Changes since last scan** section; accepted risks stop
being flagged as new. Memory lives in `~/.sgai/` (override with `$SGAI_HOME`);
GitHub-URL targets are tracked by URL, so the web app and deployed service
remember repos across scans too.

## Security design

SGAI is built to be safe to point at untrusted code: sandboxed file access
(path-traversal + symlink safe), least-privilege per-agent MCP toolsets,
stateless request handling (pasted code is scanned in a throwaway temp dir and
never stored), no secrets in code (env vars + `.env.example`), and an optional,
local-only PR step. Full details in [docs/security.md](docs/security.md).

## Deployment

SGAI ships as a stateless HTTP service and a container image.

```bash
# Local:
uv run uvicorn sgai.api:app --host 0.0.0.0 --port 8080

# Docker — published image (no build needed):
docker run -p 8080:8080 ghcr.io/ankitranjan-dsai/sgai:latest

# Docker — build locally:
docker build -t sgai . && docker run -p 8080:8080 sgai

# Google Cloud Run:
gcloud run deploy sgai --source . --region us-central1 --allow-unauthenticated
```

Full guide (incl. wiring the optional Gemini key as a secret):
[docs/deploy.md](docs/deploy.md).

## Known limitations

- **Static analysis is Python-only (Bandit).** Other languages are covered by
  dependency-manifest CVE scanning and, under `--deep`, optional Semgrep.
- **Semgrep is fetched at runtime** via `uvx`; if unavailable it is skipped
  gracefully (the rest of the scan still runs).
- **Severity enrichment costs one extra OSV fetch per unique advisory.** An
  advisory whose record carries no CVSS vector or database label (rare; some
  PYSEC entries) falls back to **High**.
- **Memory matches findings by `source:id:location`, with line-shift
  tolerance.** A static finding whose line moved (code edited above it) is
  recognized as the same issue; a same-id finding that moves *files* still
  reads as one fixed and one new.
- **Fully-autonomous tool-calling pipeline needs higher Gemini quota.** The
  default `--explain` path uses just two LLM calls to stay within the free tier;
  the deterministic core needs no key at all.

## CI/CD integration

SGAI gates its own repository with the workflows in
[`.github/workflows/`](.github/workflows) — copy them into any repo for the
same setup:

- **`ci.yml`** — tests, lint, and a dogfooded `sgai check .` self-audit.
- **`sgai-security.yml`** — on every PR: full scan uploaded as SARIF to the
  GitHub Security tab, then `sgai check .` as the merge gate, so a
  `.sgai/policy.yml` violation blocks the merge.
- **`sgai-dependency-audit.yml`** — weekly cron that re-audits every pinned
  dependency against OSV.dev and opens an upgrade PR (`sgai fix --open-pr`)
  when a new CVE lands.

This repo's own policy lives at [`.sgai/policy.yml`](.sgai/policy.yml); an
annotated copy ships in [`examples/policy.yml`](examples/policy.yml), and a
custom exploit-chain template in
[`examples/custom_chains.json`](examples/custom_chains.json).

## License

MIT © 2026 Ankit Ranjan
