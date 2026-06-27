# Demo Walkthrough

A reproducible, ~3-minute path that exercises every part of SGAI. No API key is
required for steps 1–5. Run from the repo root.

## 0. Setup

```bash
uv sync
uv run pytest -q        # expect: 30 passed
```

## 1. Deterministic scan (dependencies + Bandit)

```bash
uv run sgai scan ./examples/kaggle_demo_repo
```

Expect ~23 findings: PyPI + npm + Go CVEs (OSV.dev) and Python unsafe patterns
(Bandit), risk-ranked, written to `sgai_report.md`.

## 2. Deep scan (adds Semgrep multi-language SAST)

```bash
uv run sgai scan ./examples/kaggle_demo_repo --deep
```

Expect ~32 findings — the extra ones are Semgrep flags, including the insecure
`server.js`.

## 3. SARIF export (GitHub code scanning / IDEs)

```bash
uv run sgai scan ./examples/kaggle_demo_repo --sarif out.sarif
```

`out.sarif` is valid SARIF 2.1.0 and can be uploaded to GitHub code scanning.

## 4. Sessions & Memory — "what changed?"

```bash
uv run sgai scan ./examples/kaggle_demo_repo     # baseline (or a 2nd run vs step 1)
uv run sgai history ./examples/kaggle_demo_repo   # the scan timeline
```

The second run's report includes a **Changes since last scan** section
(new / fixed / still open). Try `sgai accept <target> <finding-id>` to suppress a
known risk, then re-scan — it stops being flagged as new.

## 5. Scan any public repo by URL

```bash
uv run sgai scan https://github.com/owner/repo
```

Shallow-clones into a temp dir, audits it, and discards it.

## 6. Web app

```bash
./run.sh          # or: uv run uvicorn sgai.api:app --host 0.0.0.0 --port 8080
```

Open http://localhost:8080, click **Use sample vulnerable input**, tap **Scan**,
and watch the live progress log, risk summary, findings + fixes, and the
"changes since last scan" diff. It's mobile-first — open the same URL from a
phone on the same Wi-Fi.

## 7. Multi-agent narrated report (optional, needs a Gemini key)

```bash
cp .env.example .env       # add GOOGLE_API_KEY
uv run sgai scan ./examples/kaggle_demo_repo --explain
```

The triage → report-writer agents narrate the findings and reference the prior
scan from memory. Falls back to the deterministic report if no key / rate-limited.

## 8. MCP server (used by Antigravity / any MCP agent)

```bash
uv run python -m sgai.mcp_server.server
```

See [mcp.md](mcp.md) for client configuration.
