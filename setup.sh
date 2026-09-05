#!/usr/bin/env bash
# setup.sh -- install the agent-guard scanners via uv (macOS / Linux / Git Bash)
#   - SkillSpector          : skill scans + the static MCP source scan
#   - cisco-ai-mcp-scanner  : the optional runtime MCP check (scan_mcp.py
#                             --sandbox / remote) -- the one thing a static
#                             scan cannot do (see tools registered at runtime)
# Run: chmod +x setup.sh && ./setup.sh

set -euo pipefail

# SkillSpector ships tagged GitHub releases but is not on PyPI. We pin the exact
# commit behind a release tag (tags can move, commits cannot) so "scan = install"
# applies to the scanner itself. Bump deliberately; keep the tag comment in sync.
SKILLSPECTOR_REPO="https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA="b7241089d7ec15d8b30df980dacbb428214732b9"   # v2.11.0

echo "Checking prerequisites..."

# Check uv (uv ships its own Python for tools -- no system Python required)
if ! command -v uv &>/dev/null; then
  echo "uv not found. Install from https://docs.astral.sh/uv/"
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi
echo "  uv: $(uv --version)"

# --link-mode=copy: required when uv cache and target sit on different
# filesystems or inside a synced folder (OneDrive on Git Bash).
LINK_ARGS=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) LINK_ARGS="--link-mode=copy" ;;
esac

# --python 3.12: SkillSpector requires 3.12/3.13; we pin 3.12 (uv fetches it)
# because yara-python ships prebuilt wheels there -- no C compiler needed.
#
# Windows ARM64 (Git Bash): yara-python publishes no win_arm64 wheels. Windows
# 11 on ARM emulates x64 transparently, so request an x86-64 CPython for the
# SkillSpector tool env there -- prebuilt win_amd64 wheels install cleanly.
SS_PYTHON="3.12"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    if [ "${PROCESSOR_ARCHITECTURE:-}" = "ARM64" ]; then
      SS_PYTHON="cpython-3.12-windows-x86_64-none"
      echo "  Windows ARM64 detected: using x86-64 Python (emulated) for prebuilt yara-python wheels"
    fi
    ;;
esac

echo ""
echo "Installing SkillSpector (skills + static MCP scan), pinned @ ${SKILLSPECTOR_SHA:0:12}..."
SS_SPEC="git+${SKILLSPECTOR_REPO}@${SKILLSPECTOR_SHA}"
if uv tool list 2>/dev/null | grep -q "^skillspector"; then
  echo "  skillspector: already installed -- re-pinning to ${SKILLSPECTOR_SHA:0:12}"
  # shellcheck disable=SC2086  # LINK_ARGS is intentionally word-split (single flag or empty)
  uv tool install --force "$SS_SPEC" --python "$SS_PYTHON" $LINK_ARGS
else
  # shellcheck disable=SC2086
  uv tool install "$SS_SPEC" --python "$SS_PYTHON" $LINK_ARGS
fi

echo ""
echo "Installing cisco-ai-mcp-scanner (optional runtime MCP check)..."
if uv tool list 2>/dev/null | grep -q "^cisco-ai-mcp-scanner"; then
  echo "  cisco-ai-mcp-scanner: already installed -- upgrading"
  uv tool upgrade cisco-ai-mcp-scanner
else
  # shellcheck disable=SC2086
  uv tool install cisco-ai-mcp-scanner $LINK_ARGS
fi

# cisco-ai-skill-scanner is no longer used -- SkillSpector replaced it for skill
# and static MCP scans. Leave any existing install untouched, but flag it.
if uv tool list 2>/dev/null | grep -q "^cisco-ai-skill-scanner"; then
  echo ""
  echo "  Note: cisco-ai-skill-scanner is installed but no longer used by agent-guard."
  echo "        Remove it with: uv tool uninstall cisco-ai-skill-scanner"
fi

echo ""
echo "Verifying..."
if command -v skillspector &>/dev/null; then
  echo "  $(skillspector --version 2>&1 | head -1)"
else
  echo "  skillspector installed but not on PATH -- run: uv tool update-shell (then reopen shell)"
fi
if command -v mcp-scanner &>/dev/null; then
  echo "  mcp-scanner: ready"   # no --version flag; presence on PATH is the check
else
  echo "  mcp-scanner installed but not on PATH -- run: uv tool update-shell (then reopen shell)"
fi

echo ""
echo "[OK] Setup complete."
echo "     Next: cp .env.example .env"
echo "           SkillSpector LLM: defaults to your coding-agent CLI (claude/codex/gemini login, no API key);"
echo "           hosted providers (anthropic/openai/nv_build/...) work with a key. MCP_SCANNER_LLM_* for Cisco runtime scans."
echo "           Optional: set VIRUSTOTAL_API_KEY for binary/archive malware reputation checks"
echo "           CLI-tool scans (scan_cli.py npm/pypi/go) use Datadog GuardDog:"
echo "           native 'guarddog' on PATH if present, else the official Docker"
echo "           image ghcr.io/datadog/guarddog (pulled lazily on first scan)"
