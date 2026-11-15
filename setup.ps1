# setup.ps1 -- install the agent-guard scanners via uv (Windows)
#   - SkillSpector          : skill scans + the static MCP source scan
#   - cisco-ai-mcp-scanner  : the optional runtime MCP check (scan_mcp.py
#                             --sandbox / remote) -- the one thing a static
#                             scan cannot do (see tools registered at runtime)
# Run from PowerShell: .\setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# SkillSpector is not on PyPI. We pin an exact commit on NVIDIA's main branch
# (not a release tag: the 2.13.x tags lack fixes agent-guard relies on), so
# "scan = install" applies to the scanner itself. Bump deliberately; see
# scripts/_pins.py (a test keeps both in sync).
$SkillSpectorRepo = "https://github.com/NVIDIA/SkillSpector"   # main until 2.13.0
$SkillSpectorSha  = "e48d771a26f7398b36256ceb8d8f94adce3d5c44"   # v2.12.0 + main 2026-11-06

# Cisco mcp-scanner: pinned to a commit on the official main branch. The newest
# PyPI release still pins a litellm with published advisories; main accepts a
# newer one, so we require litellm past those advisories and never the
# compromised 1.107.0. Reasons and bump rules: scripts/_pins.py.
$CiscoRepo   = "https://github.com/cisco-ai-defense/mcp-scanner"
$CiscoSha    = "9ff8fc84b792aae315a838cf4e37b40ef46a0293"   # main 2026-11-06, package version 4.8.7
$CiscoLitellm = "litellm>=1.106.5,!=1.107.0"

# A pinned commit fixes the scanner code, not its dependencies: uv resolves them
# fresh. --exclude-newer limits registry packages to files uploaded before this
# fixed instant (set at least 7 days back with each pin bump), so a release
# from the days before a setup run cannot slip in (see scripts/_pins.py).
$ExcludeNewer = "2026-11-08T09:00:00Z"

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
# --force on every run: a fresh install and a re-pin of an existing (possibly
# unpinned) install take the same path. On failure uv leaves any previous
# install in place, which is not the pinned state, so setup stops.
$ssSpec = "git+$SkillSpectorRepo@$SkillSpectorSha"
uv tool install --force $ssSpec --python $ssPython --link-mode=copy --exclude-newer $ExcludeNewer
if ($LASTEXITCODE -ne 0) { Write-Host "SkillSpector install failed; any previous install is unchanged and NOT the pinned version." -ForegroundColor Red; exit 1 }

$ciscoSha12 = $CiscoSha.Substring(0, 12)
Write-Host "`nInstalling cisco-ai-mcp-scanner (optional runtime MCP check), pinned @ $ciscoSha12..." -ForegroundColor Cyan
$ciscoSpec = "git+$CiscoRepo@$CiscoSha"
uv tool install --force $ciscoSpec --with $CiscoLitellm --link-mode=copy --exclude-newer $ExcludeNewer
if ($LASTEXITCODE -ne 0) { Write-Host "cisco-ai-mcp-scanner install failed; any previous install is unchanged and NOT the pinned version." -ForegroundColor Red; exit 1 }

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
Write-Host "     Next: configure user/process environment variables (README). .env is optional."
Write-Host "           SkillSpector LLM: defaults to your coding-agent CLI (claude/opencode login, no API key);"
Write-Host "           hosted providers (anthropic/openai/nv_build/...) work with a key. MCP_SCANNER_LLM_* for Cisco runtime scans."
Write-Host "           Optional: set VIRUSTOTAL_API_KEY for binary/archive malware reputation checks"
Write-Host "           CLI-tool scans (scan_cli.py npm/pypi/go) use Datadog GuardDog via the"
Write-Host "           official Docker image ghcr.io/datadog/guarddog (pinned by digest in scripts/_pins.py,"
Write-Host "           pulled on first scan; Docker is GuardDog's only supported install on Windows)"
