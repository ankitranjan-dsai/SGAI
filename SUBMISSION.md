# SGAI — SecureGuardAI

*Kaggle "AI Agents: Intensive Vibe Coding Capstone" — Freestyle track*

## One-line pitch

A multi-agent security reviewer, built on Google ADK and a custom MCP server,
that audits AI-generated code for vulnerable dependencies and unsafe patterns,
remembers every scan, and can open a fix.

## Problem

AI coding assistants now write a large share of the world's new code, and they
write it fast — faster than most teams can security-review it. A "vibe coded"
app routinely ships with an outdated dependency carrying a known CVE, a path
traversal bug, or a hardcoded secret, because nobody paused to check. Standing
up a proper review pipeline — SAST, dependency auditing, secret scanning,
policy enforcement — has historically meant wiring together five separate
tools, which is exactly the step solo developers and small teams skip. Fast
generation without a fast, equally automated check is a supply-chain problem
waiting to happen.

## Solution

SGAI points at a local path or any public GitHub URL and:

1. **Finds** vulnerable dependencies (PyPI, npm, Go, crates.io via OSV.dev)
   and unsafe code (Bandit for Python; Semgrep for JS/Go/Java/... under
   `--deep`), plus leaked secrets and container/IaC misconfigurations.
2. **Prioritizes** every finding with a real CVSS-derived severity and a
   reachability classification (is the vulnerable package actually imported
   by production code, only by tests, or never touched?).
3. **Explains** the risk in plain English, including composing individual
   findings into multi-step exploit chains with a Mermaid diagram.
4. **Fixes** what it can: resolves patched dependency versions and opens a
   pull request, or generates a test-validated code patch and applies it
   directly (`sgai heal`), rolling back if the patch breaks the suite.
5. **Remembers** every scan, so the second run reports "3 new, 2 fixed, 5
   still open" instead of re-dumping the same list, and lets a team
   permanently dismiss a false positive.
6. **Gates** CI with a `.sgai/policy.yml` policy-as-code rule set, and reviews
   pull requests differentially — flagging only what a diff introduces.

All of it is reachable three ways from one codebase: a CLI (`sgai scan`,
`sgai heal`, `sgai check`, `sgai fix`, `sgai history`, `sgai accept`), a
mobile-friendly four-tab web app, and a standalone MCP server any other agent
can attach to.

## Why agents are needed

A security audit is naturally parallel and specialized: enumerate source
files, query a CVE database, run a static analyzer, reason about
exploitability, decide what to fix, and write the fix — six different jobs
requiring six different kinds of reasoning. No single prompt does all of that
reliably. SGAI gives each job to a dedicated agent (scanner, dependency-audit,
static-analysis, risk-scoring, remediation, report) coordinated by an
orchestrator, which is what makes the multi-agent architecture *necessary*
rather than decorative — this is the actual reason the system is agentic and
not "a scanner with an LLM wrapper."

**A deliberate engineering trade-off, stated honestly:** the fully-autonomous
version of this pipeline — every specialist agent reasoning tool-call by
tool-call — works (`sgai scan --agentic`) but a free-tier Gemini key caps at 5
requests/minute, and six agents making their own tool calls exceeds that in
seconds. So the default path splits the work: a **deterministic core** (the
MCP tools below, called directly, zero LLM calls) does all detection,
scoring, and de-duplication; a **lean two-agent narration layer**
(`triage_agent` → `report_writer_agent`) then reasons over the pre-gathered
findings to write the human-readable report and threat model — two LLM calls
total, regardless of repo size. This is also the better architecture on its
merits: the parts that must be reliable (what's vulnerable, how bad is it)
never depend on an LLM being available or rate-limited; the parts that
benefit from language reasoning (explaining impact, composing exploit chains)
are exactly where the LLM is used. The fully-autonomous pipeline is kept in
the codebase, not deleted, as a legitimate demonstration of ADK's autonomous
tool-calling pattern under higher quota.

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

Every specialist agent is bound to a **least-privilege tool allowlist** on the
MCP server — e.g. the static-analysis agent literally cannot call the tool
that reads arbitrary files outside its scan root, because that tool isn't in
its filter. Built with Google ADK: `LlmAgent`, `SequentialAgent`, and
`ParallelAgent` for the fan-out analysis stage. Source: `src/sgai/agents/`.

## MCP tools

All security tooling is exposed through a custom `FastMCP` server
(`src/sgai/mcp_server/server.py`) — this is what lets any MCP-compatible
client (Antigravity, Claude Code, the Gemini CLI, or SGAI's own agents) reuse
the same toolbox instead of it being locked inside one script:

| Tool | Purpose |
|---|---|
| `scan_manifest` | Audit a dependency manifest (PyPI/npm/Go/crates.io) against OSV.dev |
| `scan_dependency` | Check a single package for CVEs |
| `scan_requirements_file` | Audit a whole `requirements.txt` in one batched call |
| `run_static_analysis` | Bandit static analysis (Python) |
| `run_semgrep` | Multi-language static analysis (optional, `--deep`) |
| `scan_dockerfile` | Dockerfile / compose / Terraform misconfiguration checks |
| `scan_secrets` | High-entropy + known-format secret detection with masked-value LLM verification |
| `validate_patch` | Run the target project's own tests inside the sandbox (self-healing) |
| `list_source_files` / `read_source_file` | Sandboxed source access |

Why MCP specifically, not direct function calls: it decouples the security
toolbox from the agent framework. The same server, unmodified, already serves
three different consumers — SGAI's own ADK agents over stdio, a standalone
process any external MCP client can attach to (`docs/integrations.md`), and a
shared network service over streamable-HTTP/SSE for multi-client use. That
reuse is the concrete evidence it's a real protocol boundary, not an internal
function call renamed.

## Security and guardrails

SGAI is built to be safe to point at untrusted, AI-generated code:

- **Sandboxed file access.** Every filesystem tool routes through
  `sandbox.safe_resolve`, which fully resolves the path — defeating `../`
  traversal and symlink escapes — and rejects anything outside the
  allow-listed scan root, whether the request comes from a user, an agent, or
  a bug. Verified by `tests/test_sandbox.py`.
- **Least-privilege per-agent tool filters.** Each specialist agent gets only
  the MCP tools its job requires (`SCANNER_TOOLS`, `DEPENDENCY_TOOLS`,
  `STATIC_ANALYSIS_TOOLS`, `HEALER_TOOLS`, `CONTAINER_TOOLS` in
  `agents/security_tools.py`) — a compromised or misdirected agent still
  cannot call a tool outside its allowlist.
- **Stateless request handling.** Pasted code from the web UI is scanned in a
  throwaway temp directory and never persisted.
- **No code execution of scanned repos.** SGAI reads and analyzes source; it
  does not import or run the target's code (the one exception —
  `validate_patch` for self-healing — runs the target's *own* test suite
  inside the sandboxed root, to confirm a generated patch doesn't break it).
- **No secrets in code.** Config is env vars only (`.env.example` ships with
  placeholders); `.env` is gitignored.
- **Opt-in, scoped remediation.** The GitHub PR step (`sgai fix --open-pr`)
  is dry-run by default and requires an explicit flag plus a token the user
  supplies.

Full detail: [docs/security.md](docs/security.md).

## Memory and sessions

A one-off report tells you what's wrong *now*; SGAI also remembers every scan
of a target and answers what a team actually asks at standup — *what
changed?* `ScanMemory` (`src/sgai/memory.py`) is a JSON-backed, per-target
store of every scan plus a list of accepted risks. Each new scan computes a
diff against the previous snapshot by a stable `fingerprint` (source + id +
location), so an upgraded dependency reads as **fixed** and a
freshly-introduced CVE reads as **new** — everything else is **still open**.
A finding can be permanently dismissed (`sgai accept` / `POST /dismiss`) and
stops being flagged as new on future scans. The same store is adapted to
ADK's `BaseMemoryService` contract (`SgaiMemoryService`), so the agent layer
can persist a session and recall it later through the built-in `load_memory`
tool — this is real ADK session/memory usage, not just a database table.
Storage lives under `~/.sgai/` (override with `$SGAI_HOME`); GitHub-URL
targets are keyed by URL, so the deployed service tracks repos across calls
too.

```bash
uv run sgai scan ./myproject      # 1st run: saves a baseline
# …fix some deps, introduce others…
uv run sgai scan ./myproject      # 2nd run: "3 new · 1 fixed · 8 still open"
uv run sgai history ./myproject   # the full scan timeline
```

## Demo flow

1. **The problem, in one breath.** AI writes most code now; almost none of it
   gets security-reviewed before it ships.
2. **Live scan, no key needed.** `uv run sgai scan ./examples/kaggle_demo_repo --deep`
   — point at the severity table and one finding's remediation line.
3. **It's agentic, not a linter.** Glance at
   `src/sgai/agents/orchestrator.py` (orchestrator + `ParallelAgent` fan-out),
   then run `uv run sgai scan ./examples/kaggle_demo_repo --explain` and read
   one line of the narrated report aloud.
4. **Memory.** Re-run the same scan and point at the
   `Changes since last scan: 0 new · 0 fixed · N still open` banner, then
   `uv run sgai history ./examples/kaggle_demo_repo`.
5. **It fixes things.** `uv run sgai heal ./examples/kaggle_demo_repo --dry-run`
   — an AST-safe patch diff, not a suggestion in prose.
6. **It's deployable.** `docker run -p 8080:8080 ghcr.io/ankitranjan-dsai/sgai:latest`
   (public, no login) or `./run.sh` and open `localhost:8080`.

Full timed script (rehearsed, ≤5:00): [docs/video_script.md](docs/video_script.md).
Condensed version and a step-by-step walkthrough also live in the
[README's Demo Script](README.md#demo-script-23-min) and
[docs/demo.md](docs/demo.md).

## Setup and run commands

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/) (`uv` fetches a
matching Python automatically if you don't have 3.11+ on PATH). No API key is
needed for any command below except `--explain`/`--agentic`.

```bash
git clone https://github.com/ankitranjan-dsai/SGAI.git && cd SGAI
uv sync                                                 # venv + deps
uv run pytest -q                                        # 275+ tests, all green

uv run sgai scan ./examples/kaggle_demo_repo            # deterministic scan
uv run sgai scan ./examples/kaggle_demo_repo --deep     # + Semgrep
uv run sgai history ./examples/kaggle_demo_repo         # scan timeline
uv run sgai check ./examples/kaggle_demo_repo           # CI policy gate

uv run python -m sgai.mcp_server.server                 # MCP server standalone

./run.sh                                                # web app on :8080
docker run -p 8080:8080 ghcr.io/ankitranjan-dsai/sgai:latest  # published image
```

Full command reference: [README.md](README.md#quick-judge-run-under-5-minutes-no-api-key-needed).

## What works today

- Multi-agent pipeline (orchestrator + 6 specialists) built on Google ADK,
  plus a two-agent narration layer that stays within the free Gemini tier.
- Custom MCP server with 9 tools, reused by SGAI's own agents, external MCP
  clients, and a network-servable transport.
- Dependency CVE scanning (PyPI/npm/Go/crates.io via OSV.dev), Bandit SAST,
  optional Semgrep multi-language SAST, secret scanning, and
  Dockerfile/IaC checks.
- Reachability classification, exploit-chain threat modeling with Mermaid
  diagrams, and CVSS-derived severity.
- Self-healing code patches (`sgai heal`) with test-validated rollback.
- Persistent per-target scan memory with new/fixed/still-open diffing, an
  ADK `MemoryService` adapter, and permanent false-positive dismissal.
- Policy-as-code CI gate (`sgai check`, `.sgai/policy.yml`) and differential
  PR scanning.
- SBOM (CycloneDX/SPDX) and VEX (OpenVEX) export.
- CLI, mobile-friendly four-tab web app (Scan Results, Code Playground,
  Interactive Agent Chat, Trends), and a stateless FastAPI HTTP service.
- Dockerfile + a public, pre-built container image on GHCR
  (`ghcr.io/ankitranjan-dsai/sgai`, pullable with no authentication) +
  Cloud Run instructions.
- Four GitHub Actions workflows: test/lint CI, a security-audit workflow that
  uploads SARIF and gates merges, a scheduled dependency-audit workflow that
  opens its own fix PRs, and a release workflow that publishes the container.
- 275+ automated tests, all green.

## Known limitations

- **Static analysis is Python-only (Bandit).** Other languages get
  dependency-manifest CVE coverage always, and optional Semgrep coverage
  under `--deep`.
- **Semgrep is fetched at runtime** via `uvx`; if unavailable it's skipped
  gracefully and the rest of the scan still runs.
- **Severity enrichment costs one extra OSV fetch per unique advisory**; an
  advisory with no CVSS vector or database label (rare) falls back to High.
- **Memory matching is fingerprint-based with line-shift tolerance** — a
  finding whose line moved is still recognized as the same issue, but a
  same-id finding that moves *files* reads as one fixed and one new.
- **The fully-autonomous tool-calling pipeline (`--agentic`) needs a paid or
  higher-quota Gemini key.** The default `--explain` path uses two LLM calls
  total and stays within the free tier; the deterministic core needs no key.

## Future improvements

- Native support for more manifest ecosystems (Maven, NuGet, RubyGems) so
  Java/.NET/Ruby repos get dependency-CVE coverage, not just `--deep` Semgrep.
- A hosted, no-install version of the web app so a repo owner can paste a URL
  without cloning SGAI locally first.
- Expanding the exploit-chain templates with more attacker archetypes
  (SSRF-to-cloud-metadata, deserialization-to-RCE) beyond what the LLM derives
  ad hoc today.

## Links

- **GitHub:** https://github.com/ankitranjan-dsai/SGAI
- **Demo video:** https://www.youtube.com/watch?v=deRzztaJo9E
- **Kaggle writeup:** https://kaggle.com/competitions/vibecoding-agents-capstone-project/writeups/new-writeup-1782074784033
- **Live/local demo:**
  - Fastest: `./run.sh` (or double-click `run.command` / `run.bat`) →
    `http://localhost:8080` — no Docker or API key required.
  - Published container, no build needed:
    `docker run -p 8080:8080 ghcr.io/ankitranjan-dsai/sgai:latest`
  - Cloud Run: `gcloud run deploy sgai --source . --region us-central1 --allow-unauthenticated`
    (full guide: [docs/deploy.md](docs/deploy.md))
  - Under-5-minute judge run with exact commands:
    [README.md — Quick Judge Run](README.md#quick-judge-run-under-5-minutes-no-api-key-needed)
