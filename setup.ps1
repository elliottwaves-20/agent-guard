# setup.ps1 — Install cisco-ai-skill-scanner via uv (Windows)
# Run from PowerShell: .\setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Checking prerequisites..." -ForegroundColor Cyan

# Check uv
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found. Install from https://docs.astral.sh/uv/" -ForegroundColor Red
    Write-Host "  winget install astral-sh.uv" -ForegroundColor Yellow
    exit 1
}

# Check Python >= 3.10
$pyver = python --version 2>&1
Write-Host "  Python: $pyver"

# Install cisco-ai-skill-scanner isolated via uv
Write-Host "`nInstalling cisco-ai-skill-scanner..." -ForegroundColor Cyan

# --link-mode=copy required when uv cache and target are on different filesystems (e.g. OneDrive)
uv tool install cisco-ai-skill-scanner --link-mode=copy

Write-Host "`nVerifying installation..." -ForegroundColor Cyan
skill-scanner --version

Write-Host "`n[OK] Setup complete." -ForegroundColor Green
Write-Host "     Next: copy .env.example to .env and set SKILL_SCANNER_LLM_API_KEY"
