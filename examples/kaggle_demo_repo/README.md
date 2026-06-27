# ⚠️ Intentionally Vulnerable Demo Repo

**This folder is deliberately insecure.** It exists only as a target for SGAI so
judges (and you) can see a rich, non-empty scan in seconds. **Nothing here should
ever be installed, run, or copied into real software.**

It is designed to light up every part of SGAI at once:

| File | What it exercises |
|---|---|
| `requirements.txt` | 6 known-vulnerable **PyPI** pins → OSV.dev CVE findings |
| `package-lock.json` | 3 known-vulnerable **npm** pins → OSV.dev CVE findings |
| `go.mod` | 2 known-vulnerable **Go** modules → OSV.dev CVE findings |
| `app.py` | 9 unsafe Python patterns → **Bandit** static-analysis findings |
| `server.js` | code/command injection → **Semgrep** findings (with `--deep`) |

## Try it

```bash
# Dependency CVEs (PyPI + npm + Go) and Bandit static analysis — no API key:
uv run sgai scan ./examples/kaggle_demo_repo

# Add Semgrep multi-language static analysis (also flags server.js):
uv run sgai scan ./examples/kaggle_demo_repo --deep

# Emit SARIF 2.1.0 for GitHub code scanning / IDEs:
uv run sgai scan ./examples/kaggle_demo_repo --sarif out.sarif

# Run it twice to see the Sessions & Memory diff ("new / fixed / still open"):
uv run sgai scan ./examples/kaggle_demo_repo
uv run sgai history ./examples/kaggle_demo_repo
```
