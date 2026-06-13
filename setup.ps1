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

Write-Host "`nInstalling Cisco scanners (skills + MCP servers)..." -ForegroundColor Cyan

# --link-mode=copy: required when uv cache and target sit on different
# filesystems or inside a synced folder (OneDrive); harmless otherwise.
foreach ($pkg in @("cisco-ai-skill-scanner", "cisco-ai-mcp-scanner")) {
    $installed = uv tool list 2>$null | Select-String -Quiet $pkg
    if ($installed) {
        Write-Host "  ${pkg}: already installed -- upgrading"
        uv tool upgrade $pkg
    } else {
        uv tool install $pkg --link-mode=copy
    }
}

Write-Host "`nVerifying installation..." -ForegroundColor Cyan
foreach ($bin in @("skill-scanner", "mcp-scanner")) {
    if (Get-Command $bin -ErrorAction SilentlyContinue) {
        Write-Host "  $(& $bin --version 2>&1 | Select-Object -First 1)"
    } else {
        Write-Host "  $bin installed but not on PATH -- run: uv tool update-shell (then reopen terminal)" -ForegroundColor Yellow
    }
}

Write-Host "`n[OK] Setup complete." -ForegroundColor Green
Write-Host "     Next: copy .env.example to .env and set SKILL_SCANNER_LLM_API_KEY"
