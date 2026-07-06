# Demo repositories

Ten public repositories (plus the bundled fixture) chosen to collectively
exercise every scanning capability in SGAI: multi-ecosystem dependency CVEs,
Bandit and Semgrep static analysis, reachability classification, secret/
container scanning, and the memory/diff loop. Sizes matter for a live
recording — prefer the small ones on camera and cut to a pre-recorded clip for
the large ones.

| # | Repo | Ecosystem / size | What it demonstrates | Verified |
|---|---|---|---|---|
| 1 | `./examples/kaggle_demo_repo` (bundled) | PyPI+npm+Go, tiny | End-to-end offline: multi-ecosystem deps, Bandit, Semgrep, SARIF, memory, secrets, container scan — no network/clone needed | 23 findings shallow, 32 with `--deep` |
| 2 | [`adeyosemanputra/pygoat`](https://github.com/adeyosemanputra/pygoat) | Python, 18MB | Flagship "scan any repo by URL" + Python deps/Bandit at real-world scale | **100 findings** (4 critical, 22 high, 27 medium, 47 low — re-verified live 2026-07-04; rises over time as SGAI adds detection capabilities, not a regression) |
| 3 | [`snyk-labs/nodejs-goof`](https://github.com/snyk-labs/nodejs-goof) | npm, 8.5MB | npm dependency CVEs + reachability classification (large lockfile — this is the repo that exposed and validated the OSV batch-chunking fix) | **136 findings** |
| 4 | [`0c34/govwa`](https://github.com/0c34/govwa) | Go, 1.3MB | Go dependency CVEs, fast clone for a live segment | **1 finding** |
| 5 | [`OWASP/NodeGoat`](https://github.com/OWASP/NodeGoat) | npm, 9MB | Second target for the memory/diff/history segment (scan, edit, re-scan → "new / fixed / still open") | exists |
| 6 | [`digininja/DVWA`](https://github.com/digininja/DVWA) | PHP, 2.8MB | `--deep` Semgrep on a language with no dependency-CVE support — shows graceful scope, not a gap | exists |
| 7 | [`OWASP/railsgoat`](https://github.com/OWASP/railsgoat) | Ruby, 8MB | Second `--deep`-only language; also has Dockerfiles for container-scan coverage | exists |
| 8 | [`appsecco/dvna`](https://github.com/appsecco/dvna) | npm, 3.3MB | Small alt for a fast npm segment if #3/#5 are too slow to clone live | exists |
| 9 | Your own fork of `nodejs-goof` | npm | `sgai fix <fork> --open-pr` — real PR opened with patched pins (needs `GITHUB_TOKEN`); the only repo that needs write access | fork before recording |
| 10 | `ankitranjan-dsai/SGAI` (this repo) | Python, self-scan | Policy-as-Code gate (`sgai check`) and self-healing on real production code — SGAI auditing itself, wired into its own CI | ✅ running in `.github/workflows/sgai-security.yml` |

## Coverage notes

- **Dependency-CVE ecosystems**: PyPI, npm, Go, crates.io only (OSV.dev
  coverage). Java/Ruby/PHP/Rails repos (#6, #7) exercise `--deep` Semgrep, not
  dependency scanning — say this out loud in the video so it reads as scope,
  not a bug.
- **Warm the Semgrep cache** before recording: `uvx semgrep --version` once,
  since `uvx` downloads it on first use and that pause is dead air on camera.
- **Avoid live-cloning** `juice-shop` (301MB) or `WebGoat` (108MB) — use a
  pre-recorded clip or skip them; they exist and work but blow the 5-minute
  budget on `git clone` alone.
