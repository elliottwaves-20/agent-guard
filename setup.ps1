# setup.ps1 -- Install cisco-ai-skill-scanner via uv (Windows)
# Run from PowerShell: .\setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Checking prerequisites..." -ForegroundColor Cyan

# Check uv (uv ships its own Python for tools -- no system Python required)
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found. Install from https://docs.astral.sh/uv/" -ForegroundColor Red
    Write-Host "  winget install astral-sh.uv" -ForegroundColor Yellow
    exit 1
}
Write-Host "  uv: $(uv --version)"

Write-Host "`nInstalling cisco-ai-skill-scanner..." -ForegroundColor Cyan

# --link-mode=copy: required when uv cache and target sit on different
# filesystems or inside a synced folder (OneDrive); harmless otherwise.
$installed = uv tool list 2>$null | Select-String -Quiet "cisco-ai-skill-scanner"
if ($installed) {
    Write-Host "  already installed -- upgrading instead"
    uv tool upgrade cisco-ai-skill-scanner
} else {
    uv tool install cisco-ai-skill-scanner --link-mode=copy
}

Write-Host "`nVerifying installation..." -ForegroundColor Cyan
if (Get-Command skill-scanner -ErrorAction SilentlyContinue) {
    skill-scanner --version
} else {
    Write-Host "skill-scanner is installed but not on PATH." -ForegroundColor Yellow
    Write-Host "  Run: uv tool update-shell   -- then open a new terminal." -ForegroundColor Yellow
}

Write-Host "`n[OK] Setup complete." -ForegroundColor Green
Write-Host "     Next: copy .env.example to .env and set SKILL_SCANNER_LLM_API_KEY"
