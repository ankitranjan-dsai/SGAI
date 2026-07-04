# Demo video script (≤ 5:00)

A timed shot list for the Kaggle submission video. Each row is `[time] SAY
(spoken line) / DO (on-screen action, exact command)`. Practice it once
end-to-end before recording — the timings assume you don't re-read commands
live.

## Before you hit record (5-minute prep, not part of the video)

```bash
cd /Users/ankit/Documents/sgai
uvx semgrep --version           # warms the Semgrep download so --deep has no dead air
rm -f ~/.sgai/memory.json       # clean slate so the "first scan" has no prior history
git fetch --tags                # nothing to push, just sanity
```

- Have **two windows** ready side by side: a terminal (large font, dark theme)
  and a browser at `http://localhost:8080` — don't alt-tab on camera.
- Fork [`snyk-labs/nodejs-goof`](https://github.com/snyk-labs/nodejs-goof) to
  your own account beforehand if you're including the auto-fix-PR segment
  (Section 6, optional) — that's the one step that needs write access.
- Start the server before recording: `./run.sh` (leave it running in a
  background terminal tab, not on screen).
- Screen recorder: QuickTime (macOS, free) → File → New Screen Recording, or
  OBS if you want picture-in-picture webcam. Record at 1080p.

---

## Script

**[0:00–0:15] Hook**
> SAY: "AI writes most of our code now — but nothing reviews it for security
> before it ships. That's the gap SGAI closes."
DO: Title card or the README hero line on screen (no terminal yet).

**[0:15–0:35] The one-liner**
> SAY: "SGAI is a multi-agent security reviewer. Point it at any codebase —
> local or a GitHub URL — and it finds vulnerable dependencies, unsafe code
> patterns, and secrets, ranks them by real exploitability, explains them in
> plain English, and can even fix them."
DO: `cat README.md | head -20` or just show the repo's GitHub page for 2 seconds.

**[0:35–1:25] Live demo — web app**
> SAY: "Here's the web app — same engine, mobile-friendly." (click **Use
> sample vulnerable input** → **Scan**) "It's cloning nothing here — this is a
> local snippet — but watch: dependency CVEs from OSV.dev, Bandit findings,
> each one severity-scored from the real CVSS vector, not a guess."
DO: Browser, `Scan Results` tab. Click **Use sample vulnerable input**, click
**Scan**, let the live progress log stream, then scroll the findings list —
pause on one card to show the severity chip and the fix suggestion.

**[1:25–2:05] Live demo — CLI on a real repo**
> SAY: "From the CLI it's one command against any public repo — no cloning
> it yourself."
DO:
```bash
uv run sgai scan https://github.com/adeyosemanputra/pygoat
```
> SAY (while it runs): "That's a real, unmodified vulnerable-by-design Python
> app — 85 findings, risk-ranked, with remediation for each one."
Let it finish, scroll the terminal report briefly.

**[2:05–2:35] Deep scan + SARIF + reachability**
> SAY: "`--deep` adds Semgrep for multi-language analysis, and every finding
> carries a reachability tag — is the vulnerable package actually imported in
> production code, or just sitting in a lockfile nobody calls?"
DO:
```bash
uv run sgai scan ./examples/kaggle_demo_repo --deep --sarif out.sarif
```
Point at a `reachable: true` tag in the output and the generated `out.sarif`
file in a `ls`.

**[2:35–3:05] Memory — what changed since last scan**
> SAY: "It remembers. Scan again and it tells you what's new, what's fixed,
> and what you've already accepted as a known risk."
DO:
```bash
uv run sgai scan ./examples/kaggle_demo_repo   # second run
uv run sgai history ./examples/kaggle_demo_repo
```
Or: switch to the browser's **Trends** tab and show the chart built from
the same history.

**[3:05–3:50] The advanced suite — pick ONE for time**
Choose whichever demos best on your machine; don't try to fit both.

- **Self-healing:**
  > SAY: "SGAI doesn't stop at finding problems — `heal` generates a patch,
  > runs the project's own tests against it, and only keeps the fix if the
  > tests still pass."
  DO: `uv run sgai heal ./examples/kaggle_demo_repo --dry-run`

- **Policy-as-Code CI gate:**
  > SAY: "And it enforces standards in CI — this exact command runs on SGAI's
  > own repository, every push, and fails the build on a policy violation."
  DO: `uv run sgai check .` then flash `.github/workflows/sgai-security.yml`
  and a green check on the GitHub Actions tab.

**[3:50–4:25] Deployability**
> SAY: "It's a real deployable service, not just a script — published as a
> container, pull it from anywhere, no build step."
DO:
```bash
docker pull ghcr.io/ankitranjan-dsai/sgai:latest
docker run -p 8080:8080 ghcr.io/ankitranjan-dsai/sgai:latest
```
(If Docker isn't installed on the recording machine, show the GHCR package
page in a browser tab instead — `github.com/ankitranjan-dsai/SGAI/pkgs/container/sgai`.)

**[4:25–4:50] Architecture recap**
> SAY: "Under the hood it's a multi-agent system on Google's ADK — specialist
> agents for dependency auditing, static analysis, triage, and remediation —
> talking to a custom MCP server with least-privilege tools, so no agent can
> touch more of the filesystem than its job needs."
DO: Show the architecture diagram from `docs/architecture.md`, or the
`src/sgai/agents/` folder tree for 3 seconds.

**[4:50–5:00] Close**
> SAY: "SGAI — multi-agent, MCP-native, deployable, and it's entirely open
> source. Link's in the description."
DO: End card with the repo URL: `github.com/ankitranjan-dsai/SGAI`.

---

## Recording tips

- Speak the SAY lines in your own words once you've rehearsed the shape —
  reading verbatim on camera sounds stiff.
- If a live command runs slow (a cold clone, a rate-limited API), cut and
  splice in edit rather than let dead air run — a 5-minute cap leaves no
  slack for waiting.
- Caption or zoom into terminal text; small monospace text doesn't survive
  YouTube compression at a glance.
- Upload as **Public or Unlisted** (Kaggle requires the link to be viewable,
  not necessarily indexed) and paste the URL into the Writeup before
  submitting.
