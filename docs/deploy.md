# Deploying SGAI

SGAI ships as a stateless HTTP service (`sgai.api:app`) and a container image, so
it runs locally, in Docker, or on Google Cloud Run.

## Run the service locally

```bash
uv run uvicorn sgai.api:app --host 0.0.0.0 --port 8080
```

Then:

```bash
curl localhost:8080/health

curl -s localhost:8080/scan \
  -H 'content-type: application/json' \
  -d '{"requirements": "jinja2==2.11.2\n", "code": "import os\neval(input())\n"}'
```

## CI endpoints: policy gate and PR differential scan

**`POST /scan/check`** evaluates a scan against the Policy-as-Code gate and
returns `passed: false` with the violations when the policy fails — a CI job
blocks the merge on that flag. A `github_url` is cloned and checked against its
own `.sgai/policy.yml`; submitted code can carry an inline `policy` YAML
(see [`examples/policy.yml`](../examples/policy.yml)):

```bash
curl -s localhost:8080/scan/check \
  -H 'content-type: application/json' \
  -d '{
    "requirements": "PyYAML==5.3.1\n",
    "code": "import yaml\nyaml.load(open(\"c.yml\"))\n",
    "policy": "policies:\n  fail-on-severity:\n    severity: high\n"
  }'
# → {"passed": false, "violations": [...], "evaluated": [...], "finding_count": N}
```

(For a CLI equivalent in CI, `sgai check .` exits non-zero on violation — see
the repo's own `.github/workflows/sgai-security.yml`.)

**`POST /scan/pr`** scans only what a pull request changed: it diffs `base`
against `head` (or the working tree), audits the head tree, and keeps only
findings introduced on the changed lines. With `post: true` plus
`owner_repo`/`pr_number` it posts the result as an inline GitHub review via
`gh`:

```bash
curl -s localhost:8080/scan/pr \
  -H 'content-type: application/json' \
  -d '{"repo_dir": "/workspace/checkout", "base": "origin/main"}'
# → {"delta_count": N, "findings": [...], "comments": [...], "body": "..."}
```

## Build and run with Docker

```bash
docker build -t sgai .
docker run -p 8080:8080 sgai
```

## Deploy to Google Cloud Run

The image listens on `$PORT` (Cloud Run sets this automatically).

```bash
# Build and push, then deploy:
gcloud run deploy sgai \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

To enable the agent-driven pipeline in the deployed service, set the model key as
a secret/env var:

```bash
gcloud run services update sgai \
  --update-env-vars GOOGLE_GENAI_USE_VERTEXAI=FALSE \
  --update-secrets GOOGLE_API_KEY=sgai-gemini-key:latest
```

## Notes

- The service is **stateless**: submitted code and requirements are written to a
  throwaway temp directory, audited through the sandboxed security tools, and
  discarded. Nothing is persisted between requests.
- `bandit` runs inside the container's virtual environment, so static analysis
  works with no extra setup.
