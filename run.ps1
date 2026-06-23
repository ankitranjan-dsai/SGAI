# SGAI one-command launcher for Windows (PowerShell).
# Installs uv if needed, syncs dependencies, and starts the web app.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "> Installing uv (one-time)..."
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}

Write-Host "> Installing dependencies..."
uv sync --quiet

$port = if ($env:PORT) { $env:PORT } else { "8080" }
$url = "http://localhost:$port"
Write-Host "> SGAI is starting at $url"
Write-Host "  On your phone (same Wi-Fi): http://<this-computer-ip>:$port"

Start-Process $url
uv run uvicorn sgai.api:app --host 0.0.0.0 --port $port
