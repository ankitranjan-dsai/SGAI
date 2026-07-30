# SGAI container image. Builds the audit service and serves it over HTTP.
# Designed for Cloud Run (listens on $PORT, default 8080).
FROM python:3.11-slim

# git is needed to clone repos submitted by URL.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# uv for fast, reproducible installs from the committed lockfile. Pinned: a
# floating `:latest` on the tool that resolves the dependency graph means the
# build's own toolchain can change between two builds of the same commit, which
# is the supply-chain property `uv.lock` exists to guarantee.
COPY --from=ghcr.io/astral-sh/uv:0.12.0 /uv /uvx /bin/

# An unprivileged runtime account. This service clones and statically analyses
# repositories submitted by URL — untrusted input by definition — so the process
# must not be root: a container escape from a root process is root on the host.
# The account is created before the install so it owns /app and the virtualenv
# it has to execute, and uv's cache lands in a writable home.
RUN useradd --create-home --uid 10001 app
ENV UV_CACHE_DIR=/home/app/.cache/uv
WORKDIR /app
RUN chown app:app /app
USER app

# Install dependencies first (better layer caching), then the source.
COPY --chown=app:app pyproject.toml uv.lock README.md ./
COPY --chown=app:app src ./src
RUN uv sync --frozen --no-dev

EXPOSE 8080

# Shell form so ${PORT} (set by Cloud Run) is expanded at runtime.
CMD uv run uvicorn sgai.api:app --host 0.0.0.0 --port ${PORT:-8080}
