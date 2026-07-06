# Kaggle Submission Guide

Working checklist for submitting SGAI to the **AI Agents: Intensive Vibe Coding
Capstone**. Track: **Freestyle**. Deadline: **2026-07-07, 07:59 GMT+1**
(confirm on the competition page).

## Required artifacts

| Artifact | Limit | Status |
|---|---|---|
| Kaggle Writeup | ≤ 2,500 words | ✅ published — [Kaggle writeup](https://kaggle.com/competitions/vibecoding-agents-capstone-project/writeups/new-writeup-1782074784033) |
| Public demo video (YouTube) | ≤ 5 min | ✅ published — [Watch on YouTube](https://www.youtube.com/watch?v=deRzztaJo9E) |
| Public code link | — | ✅ https://github.com/ankitranjan-dsai/SGAI |
| README (setup, architecture, reproduce) | — | ✅ `README.md` |

Code and docs are stable (v0.1.0 tagged, container published to GHCR, CI
green). All four required artifacts are published — the submission is complete.

## Course concepts → where to find them

Only 3 are required; SGAI demonstrates 6 + Sessions & Memory.

| Concept | Evidence |
|---|---|
| Multi-agent (ADK) | `src/sgai/agents/` (orchestrator, 6 specialists, narration pipeline) |
| MCP Server | `src/sgai/mcp_server/server.py` — see [mcp.md](mcp.md) |
| Security features | sandbox + least-privilege + stateless — see [security.md](security.md) |
| Deployability | `src/sgai/api.py`, `Dockerfile`, [deploy.md](deploy.md) |
| Agent skills / CLI | `sgai` CLI + [`SKILL.md`](../SKILL.md); `uv tool install .` |
| Antigravity | MCP config in [integrations.md](integrations.md) |
| Sessions & Memory | `src/sgai/memory.py` (Day 3) — new/fixed/still-open + ADK `MemoryService` |

## Judging rubric (100 pts) — how SGAI maps

- **Pitch / problem / solution / value (30):** real, universal problem (AI
  writes code, nobody security-reviews it); clear before/after; live demo.
- **Technical implementation / architecture / code (50):** 7 concepts, custom
  MCP server, multi-agent ADK pipeline, deterministic core + LLM narration,
  275+ passing tests, SARIF/SBOM/VEX export, self-healing, policy-as-code CI
  gate, and four GitHub Actions workflows (test/lint CI, a security-audit
  workflow that uploads SARIF, a scheduled dependency-audit that opens fix
  PRs, and a release workflow that publishes the container to GHCR).
- **Documentation (20):** structured README + `docs/` (architecture, security,
  mcp, deploy, demo, demo_repos, integrations, kaggle_writeup, video_script)
  + an intentionally-vulnerable demo repo.

## Reproduce in 2 minutes (what a judge runs)

```bash
uv sync
uv run pytest -q                                  # 275+ passed, all green
uv run sgai scan ./examples/kaggle_demo_repo      # rich report (~20+ findings)
uv run sgai scan ./examples/kaggle_demo_repo --deep   # + Semgrep adds more
./run.sh                                           # web app on :8080
docker pull ghcr.io/ankitranjan-dsai/sgai:latest  # published container, public, no auth
```

Full walkthrough: [demo.md](demo.md). Ten public repos to exercise every
ecosystem: [demo_repos.md](demo_repos.md).

## Video

Full timed shot list with exact commands: [video_script.md](video_script.md).

## Pre-submit checklist

- [x] Tests green (`uv run pytest -q` — 275+ passed, verified 2026-07-05)
- [x] All demo commands produce non-empty output
- [x] No secrets committed (`.env` ignored; only `.env.example` tracked)
- [x] README links resolve
- [x] Repo is public
- [x] CI green on `main` and the `v0.1.0` tag
- [x] Container image public on GHCR (verified via anonymous pull token)
- [x] Video recorded and uploaded (public/unlisted)
- [x] Video URL pasted into `kaggle_writeup.md` and the Kaggle form
- [x] Writeup ≤ 2,500 words (~1,300), links to repo, published on Kaggle
