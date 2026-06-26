# SGAI container image. Builds the audit service and serves it over HTTP.
# Designed for Cloud Run (listens on $PORT, default 8080).
FROM python:3.11-slim

# git is needed to clone repos submitted by URL.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# uv for fast, reproducible installs from the committed lockfile.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (better layer caching), then the source.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

EXPOSE 8080

# Shell form so ${PORT} (set by Cloud Run) is expanded at runtime.
CMD uv run uvicorn sgai.api:app --host 0.0.0.0 --port ${PORT:-8080}
