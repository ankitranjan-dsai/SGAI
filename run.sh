#!/usr/bin/env bash
# SGAI — one-command launcher for macOS / Linux.
# Installs uv if needed, syncs dependencies, starts the web app, and opens it
# in your browser once the server is actually ready.
set -euo pipefail

cd "$(dirname "$0")"

# 1. Make sure uv (the Python package manager) is available.
if ! command -v uv >/dev/null 2>&1; then
  echo "› Installing uv (one-time)…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

# 2. Install dependencies from the committed lockfile.
echo "› Installing dependencies…"
uv sync --quiet

PORT="${PORT:-8080}"
URL="http://localhost:${PORT}"
echo "› SGAI is starting at ${URL}"
echo "  On your phone (same Wi-Fi): http://<this-computer-ip>:${PORT}"

# 3. Open the browser only once the server answers /health — avoids landing on
#    a connection-refused page. Runs in the background so the server can start.
(
  for _ in $(seq 1 60); do
    if curl -fsS "${URL}/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  fi
) >/dev/null 2>&1 &

# 4. Serve the web app (foreground; Ctrl-C to stop).
exec uv run uvicorn sgai.api:app --host 0.0.0.0 --port "$PORT"
