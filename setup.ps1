# setup.ps1 -- install the agent-guard scanners via uv (Windows)
#   - SkillSpector          : skill scans + the static MCP source scan
#   - cisco-ai-mcp-scanner  : the optional runtime MCP check (scan_mcp.py
#                             --sandbox / remote) -- the one thing a static
#                             scan cannot do (see tools registered at runtime)
# Run from PowerShell: .\setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# SkillSpector is Alpha: no releases/tags and not on PyPI. We pin an exact
# commit so "scan = install" applies to the scanner itself. Bump deliberately.
$SkillSpectorRepo = "https://github.com/NVIDIA/SkillSpector"
$SkillSpectorSha  = "cff7ecc4f2881d9e23ea4bb801a6353e1dbe39e6"

Write-Host "Checking prerequisites..." -ForegroundColor Cyan

# Check uv (uv ships its own Python for tools -- no system Python required)
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found. Install from https://docs.astral.sh/uv/" -ForegroundColor Red
    Write-Host "  winget install astral-sh.uv" -ForegroundColor Yellow
    exit 1
}
Write-Host "  uv: $(uv --version)"

$sha12 = $SkillSpectorSha.Substring(0, 12)
Write-Host "`nInstalling SkillSpector (skills + static MCP scan), pinned @ $sha12..." -ForegroundColor Cyan
# --python 3.12: SkillSpector requires 3.12/3.13; we pin 3.12 (uv fetches it)
# for prebuilt yara-python wheels. --link-mode=copy keeps it safe when the uv
# cache/target sit in a synced folder (OneDrive); harmless otherwise.
#
# Windows ARM64: yara-python publishes no win_arm64 wheels, so a native ARM64
# Python would need a C compiler + libyara. Windows 11 on ARM emulates x64
# transparently, so we request an x86-64 CPython for the SkillSpector tool env
# there -- prebuilt win_amd64 wheels then install cleanly.
$ssPython = "3.12"
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "ARM64") {
    $ssPython = "cpython-3.12-windows-x86_64-none"
    Write-Host "  Windows ARM64 detected: using x86-64 Python (emulated) for prebuilt yara-python wheels"
}
$ssSpec = "git+$SkillSpectorRepo@$SkillSpectorSha"
$ssInstalled = uv tool list 2>$null | Select-String -Quiet "^skillspector"
if ($ssInstalled) {
    Write-Host "  skillspector: already installed -- re-pinning to $sha12"
    uv tool install --force $ssSpec --python $ssPython --link-mode=copy
} else {
    uv tool install $ssSpec --python $ssPython --link-mode=copy
}

Write-Host "`nInstalling cisco-ai-mcp-scanner (optional runtime MCP check)..." -ForegroundColor Cyan
$mcpInstalled = uv tool list 2>$null | Select-String -Quiet "^cisco-ai-mcp-scanner"
if ($mcpInstalled) {
    Write-Host "  cisco-ai-mcp-scanner: already installed -- upgrading"
    uv tool upgrade cisco-ai-mcp-scanner
} else {
    uv tool install cisco-ai-mcp-scanner --link-mode=copy
}

# cisco-ai-skill-scanner is no longer used -- SkillSpector replaced it for skill
# and static MCP scans. Leave any existing install untouched, but flag it.
$oldInstalled = uv tool list 2>$null | Select-String -Quiet "^cisco-ai-skill-scanner"
if ($oldInstalled) {
    Write-Host "`n  Note: cisco-ai-skill-scanner is installed but no longer used by agent-guard." -ForegroundColor Yellow
    Write-Host "        Remove it with: uv tool uninstall cisco-ai-skill-scanner" -ForegroundColor Yellow
}

Write-Host "`nVerifying installation..." -ForegroundColor Cyan
if (Get-Command skillspector -ErrorAction SilentlyContinue) {
    Write-Host "  $(skillspector --version 2>&1 | Select-Object -First 1)"
} else {
    Write-Host "  skillspector installed but not on PATH -- run: uv tool update-shell (then reopen terminal)" -ForegroundColor Yellow
}
if (Get-Command mcp-scanner -ErrorAction SilentlyContinue) {
    Write-Host "  mcp-scanner: ready"   # no --version flag; presence on PATH is the check
} else {
    Write-Host "  mcp-scanner installed but not on PATH -- run: uv tool update-shell (then reopen terminal)" -ForegroundColor Yellow
}

Write-Host "`n[OK] Setup complete." -ForegroundColor Green
Write-Host "     Next: copy .env.example to .env"
Write-Host "           Set OpenAI/NVIDIA for SkillSpector full coverage; set MCP_SCANNER_LLM_* for Cisco runtime scans"
Write-Host "           Optional: set VIRUSTOTAL_API_KEY for binary/archive malware reputation checks"
Write-Host "           CLI-tool scans (scan_cli.py npm/pypi/go) use Datadog GuardDog via the"
Write-Host "           official Docker image ghcr.io/datadog/guarddog (pulled lazily on first"
Write-Host "           scan; Docker is GuardDog's only supported install on Windows)"
