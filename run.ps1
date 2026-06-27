# SGAI — one-command launcher for Windows (PowerShell).
# Installs uv if needed, syncs dependencies, starts the web app, and opens it
# in your browser once the server is actually ready.
#
# Run it from PowerShell:   ./run.ps1
# (If scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\run.ps1)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# 1. Make sure uv (the Python package manager) is available.
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "> Installing uv (one-time)..."
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}

# 2. Install dependencies from the committed lockfile.
Write-Host "> Installing dependencies..."
uv sync --quiet

$port = if ($env:PORT) { $env:PORT } else { "8080" }
$url = "http://localhost:$port"
Write-Host "> SGAI is starting at $url"
Write-Host "  On your phone (same Wi-Fi): http://<this-computer-ip>:$port"

# 3. Open the browser only once the server answers /health (background job).
Start-Job -ArgumentList $url -ScriptBlock {
  param($u)
  for ($i = 0; $i -lt 60; $i++) {
    try { Invoke-WebRequest "$u/health" -UseBasicParsing -TimeoutSec 1 | Out-Null; break }
    catch { Start-Sleep -Milliseconds 500 }
  }
  Start-Process $u
} | Out-Null

# 4. Serve the web app (foreground; Ctrl-C to stop).
uv run uvicorn sgai.api:app --host 0.0.0.0 --port $port
