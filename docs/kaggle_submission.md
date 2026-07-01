# Kaggle Submission Guide

Working checklist for submitting SGAI to the **AI Agents: Intensive Vibe Coding
Capstone**. Track: **Freestyle**. Deadline: **2026-07-07, 07:59 GMT+1**
(confirm on the competition page).

## Required artifacts

| Artifact | Limit | Status |
|---|---|---|
| Kaggle Writeup | ≤ 2,500 words | ⬜ draft after code freeze |
| Public demo video (YouTube) | ≤ 5 min | ⬜ record after code freeze |
| Public code link | — | ✅ https://github.com/ankitranjan-dsai/SGAI |
| README (setup, architecture, reproduce) | — | ✅ `README.md` |

> The writeup and video script are intentionally **not finalized yet** — they
> come after the code and docs are stable.

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
  30 passing tests, SARIF, and two GitHub Actions workflows (a test/lint CI and
  a security-audit workflow that uploads SARIF).
- **Documentation (20):** structured README + `docs/` (architecture, security,
  mcp, deploy, demo, integrations) + an intentionally-vulnerable demo repo.

## Reproduce in 2 minutes (what a judge runs)

```bash
uv sync
uv run pytest -q                                  # 30 passed
uv run sgai scan ./examples/kaggle_demo_repo      # rich report (~20+ findings)
uv run sgai scan ./examples/kaggle_demo_repo --deep   # + Semgrep adds more
./run.sh                                           # web app on :8080
```

Full walkthrough: [demo.md](demo.md).

## What to show in the video (outline only — not the final script)

1. The problem in one sentence + the hero line.
2. Web app: **Use sample vulnerable input** → Scan → risk summary, findings,
   fixes.
3. CLI on `examples/kaggle_demo_repo` (deps + Bandit), then `--deep` (Semgrep).
4. **Sessions & Memory:** scan twice → "new / fixed / still open"; `sgai history`.
5. Architecture: multi-agent ADK + MCP server (one diagram).
6. Deployability: Dockerfile / Cloud Run; SARIF + CI.

## Pre-submit checklist

- [ ] Tests green (`uv run pytest -q`)
- [ ] All demo commands produce non-empty output
- [ ] No secrets committed (`.env` ignored; only `.env.example` tracked)
- [ ] README links resolve
- [ ] Repo is public
- [ ] Video uploaded (public/unlisted) and linked in the writeup
- [ ] Writeup ≤ 2,500 words, links to repo + video
