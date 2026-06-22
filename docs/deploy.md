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
