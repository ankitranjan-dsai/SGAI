#!/usr/bin/env bash
# SGAI one-command launcher for macOS / Linux.
# Installs uv if needed, syncs dependencies, and starts the web app.
set -e

cd "$(dirname "$0")"

if ! command -v uv >/dev/null 2>&1; then
  echo "› Installing uv (one-time)…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

echo "› Installing dependencies…"
uv sync --quiet

PORT="${PORT:-8080}"
URL="http://localhost:${PORT}"
echo "› SGAI is starting at ${URL}"
echo "  On your phone (same Wi-Fi): http://<this-computer-ip>:${PORT}"

# Open a browser shortly after the server comes up.
( sleep 2
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  fi ) >/dev/null 2>&1 &

exec uv run uvicorn sgai.api:app --host 0.0.0.0 --port "$PORT"
