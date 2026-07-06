# SGAI — a multi-agent security reviewer for AI-written code

*Kaggle "AI Agents: Intensive Vibe Coding Capstone" — Freestyle track*
*Repo: https://github.com/ankitranjan-dsai/SGAI · Demo video: https://www.youtube.com/watch?v=deRzztaJo9E*

> ~1,300 words (excluding code blocks) — well under the 2,500 cap.

## The problem

AI coding assistants now write a huge share of the world's new code, and they
write it fast. What they don't do is stop and ask "is this dependency
vulnerable?" or "did I just introduce a path traversal bug?" Security review
hasn't kept pace with generation speed — most solo developers and small teams
ship AI-generated code with no security gate at all, because standing up a
proper review pipeline (SAST, dependency auditing, secret scanning, policy
enforcement) has historically meant integrating five different tools.

**SGAI is that missing gate, built as a multi-agent system rather than a
single script**, because "find it, understand why it matters, decide what to
do, and fix it" is naturally four different jobs with four different kinds of
reasoning — which is exactly what an agent architecture is for.

## What it does

Point SGAI at a local path or any public GitHub URL and it:

1. **Finds** vulnerable dependencies (PyPI, npm, Go, crates.io via OSV.dev)
   and unsafe code patterns (Bandit for Python; Semgrep for JS/Go/Java/... in
   `--deep` mode), plus leaked secrets and container/IaC misconfigurations.
2. **Prioritizes** every finding with a real CVSS-derived severity (not a
   flat "High" bucket) and a reachability classification — is the vulnerable
   package actually imported by production code, only by tests, or never
   touched at all?
3. **Explains** the risk in plain English via a lean two-agent narration
   pipeline, including composing individual findings into multi-step exploit
   chains with a Mermaid diagram of the attack path.
4. **Fixes** what it can: resolves patched dependency versions and opens a
   pull request, or generates a test-validated code patch and applies it
   directly (`sgai heal`) — with binary-search rollback if a patch breaks the
   suite.
5. **Remembers** every scan, so the second run on the same target reports
   "3 new, 2 fixed, 5 still open" instead of re-dumping the same list, and
   lets you permanently dismiss a false positive.
6. **Gates** CI with a `.sgai/policy.yml` policy-as-code rule set, and reviews
   pull requests differentially — flagging only what a diff *introduces*,
   with inline GitHub review comments.

All of this is available three ways from one codebase: a CLI (`sgai scan`,
`sgai heal`, `sgai check`, `sgai fix`, `sgai history`, `sgai accept`), a
mobile-friendly web app with a four-tab UI (Scan Results, Code Playground,
Interactive Agent Chat, Trends), and a standalone MCP server that any other
agent (Antigravity, Claude Code, Gemini CLI) can attach to for its own
security tools.

## Architecture

```
              ┌─────────────────────────┐
              │   Orchestrator (ADK)    │
              └──────────┬──────────────┘
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
 dependency-audit   static-analysis     remediation
    agent               agent              agent
        │                 │                  │
        └────────┬────────┴─────────┬────────┘
                  ▼                  ▼
        ┌───────────────────────────────────┐
        │   SGAI MCP server (FastMCP)        │
        │  scan_manifest · run_static_       │
        │  analysis · run_semgrep ·          │
        │  scan_secrets · scan_dockerfile ·  │
        │  read/list_source_file             │
        └───────────────────────────────────┘
```

Each specialist agent is bound to a **least-privilege tool allowlist** on the
MCP server — the static-analysis agent literally cannot call the tool that
reads arbitrary files outside its scan root, because the tool isn't in its
filter. File access itself goes through a sandboxing layer (`safe_resolve`)
that resolves paths and rejects anything — `../` traversal, symlink escapes —
that would land outside the audited directory, whether the request comes from
a user, an agent, or a bug.

### A deliberate engineering trade-off worth calling out

The fully-autonomous version of this pipeline — every specialist agent
reasoning tool-call-by-tool-call — works, but a free-tier Gemini key caps at
5 requests/minute, and six agents making their own tool calls blows through
that in seconds. Rather than paper over it, SGAI's default path splits the
work: a **deterministic core** (the MCP tools above, called directly, zero
LLM calls) does all detection, scoring, and de-duplication; a **lean two-agent
narration layer** (`triage_agent` → `report_writer_agent`) then reasons over
the pre-gathered findings to write the human-readable report and threat
model — two LLM calls total, regardless of repo size. This is *also* a better
architecture on its merits: the parts of the system that must be reliable
(what's vulnerable, how bad is it) never depend on an LLM being available or
rate-limited; the parts that benefit from language reasoning (explaining
impact, composing exploit chains) are exactly where the LLM is used. The
fully-autonomous pipeline is kept in the codebase and documented as the
higher-quota alternative, not deleted, because it's a legitimate
demonstration of ADK's autonomous tool-calling pattern.

## Course concepts demonstrated

Only three were required; SGAI covers six, plus Sessions & Memory:

| Concept | Where |
|---|---|
| Multi-agent (ADK) | `src/sgai/agents/` — orchestrator, six specialists, two-agent narration pipeline |
| MCP Server | `src/sgai/mcp_server/server.py` — a real `FastMCP` server, reusable by any MCP client |
| Security features | Filesystem sandbox, least-privilege per-agent tool filters, stateless scans, no code execution of scanned repos |
| Deployability | `Dockerfile`, published image at `ghcr.io/ankitranjan-dsai/sgai`, `docker run` or Cloud Run, FastAPI service |
| Agent skills / CLI | `sgai` console script (`SKILL.md` packages it as an invocable agent skill) |
| Antigravity / external agents | MCP client config in `docs/integrations.md` — any MCP-capable agent gets SGAI's tools |
| Sessions & Memory | `src/sgai/memory.py` — cross-scan diffing, dismissal persistence, an ADK `BaseMemoryService` adapter |

## The advanced suite

Past the required concepts, six more subsystems separate "finds bugs" from
"runs a security program":

- **Reachability analysis** — a multi-language import graph classifies every
  vulnerable dependency as `production`, `test_only`, or `unreached`, so
  severity reflects actual exposure, not just "this version has a CVE."
- **Exploit-chain threat modeling** — findings are composed into attack
  chains (e.g., a path-traversal read into a file containing a hardcoded key)
  with a numbered fix order and a Mermaid graph, so remediation priority
  follows attacker value, not alphabetical severity.
- **Typosquat detection** — edit-distance/homoglyph/affix checks against
  popular package names, a zero-network, pre-CVE supply-chain check.
- **Context-aware secret scanning** — masked-value LLM verification to cut
  false positives, with test-fixture secrets automatically downgraded and
  rotation urgency scored separately from discovery.
- **Policy-as-Code** — `.sgai/policy.yml` plus `sgai check`/`POST /scan/check`
  gives CI a hard pass/fail gate; it's wired into SGAI's own
  `sgai-security.yml` workflow, so the tool audits itself on every push.
- **PR differential scanning + SBOM/VEX export** — `POST /scan/pr` flags only
  what a diff introduces and can post inline GitHub review comments;
  `GET /sbom` / `GET /vex` produce CycloneDX/SPDX and OpenVEX documents with
  reachability mapped to VEX's `affected` / `not_affected` states.

## Quality and reproducibility

- **275+ automated tests**, all green, covering every module above.
- **Four CI workflows**: test/lint on every push, a security-audit workflow
  (SARIF upload), a scheduled dependency-audit workflow that opens its own
  fix PRs, and a release workflow that builds and publishes the container.
- **v0.1.0 is a tagged GitHub release** with a `CHANGELOG.md`, and the
  container image is public on GHCR — `docker pull
  ghcr.io/ankitranjan-dsai/sgai:latest` works with no authentication.
- A judge can reproduce the entire thing in two commands:

```bash
uv sync && uv run pytest -q                        # 275+ passed, all green
uv run sgai scan ./examples/kaggle_demo_repo --deep --explain
```

Ten public repositories spanning Python, npm, Go, PHP, and Ruby are catalogued
in `docs/demo_repos.md` for anyone who wants to exercise every ecosystem the
tool supports, each with a verified finding count from a live scan.

## What I'd build next

- Native support for more manifest ecosystems (Maven, NuGet, RubyGems) so
  Java/.NET/Ruby repos get dependency-CVE coverage, not just `--deep`
  Semgrep.
- A hosted, no-install version of the web app so a repo owner can paste a URL
  without cloning SGAI locally first.
- Expanding the exploit-chain templates with more attacker archetypes
  (SSRF-to-cloud-metadata, deserialization-to-RCE) beyond what the LLM derives
  ad hoc today.

## Why this fits the moment

The premise of this hackathon is that AI agents can now build real, working
software fast. SGAI is a bet on the other half of that story: the faster
agents write code, the more that code needs an equally fast, equally
autonomous system checking it — and that system is itself a better product
when it's built the same way, as cooperating agents with narrow
responsibilities rather than one monolithic script. It's the security
counterpart to the same shift this competition is about.
