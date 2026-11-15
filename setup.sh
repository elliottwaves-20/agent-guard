#!/usr/bin/env bash
# setup.sh -- install the agent-guard scanners via uv (macOS / Linux / Git Bash)
#   - SkillSpector          : skill scans + the static MCP source scan
#   - cisco-ai-mcp-scanner  : the optional runtime MCP check (scan_mcp.py
#                             --sandbox / remote) -- the one thing a static
#                             scan cannot do (see tools registered at runtime)
# Run: chmod +x setup.sh && ./setup.sh

set -euo pipefail

# SkillSpector is not on PyPI. We pin an exact commit on NVIDIA's main branch
# (not a release tag: the 2.13.x tags lack fixes agent-guard relies on), so
# "scan = install" applies to the scanner itself. Bump deliberately; see
# scripts/_pins.py (a test keeps both in sync).
SKILLSPECTOR_REPO="https://github.com/NVIDIA/SkillSpector"   # main until 2.13.0
SKILLSPECTOR_SHA="e48d771a26f7398b36256ceb8d8f94adce3d5c44"   # v2.12.0 + main 2026-11-06

# Cisco mcp-scanner: pinned to a commit on the official main branch. The newest
# PyPI release still pins a litellm with published advisories; main accepts a
# newer one, so we require litellm past those advisories and never the
# compromised 1.107.0. Reasons and bump rules: scripts/_pins.py.
CISCO_REPO="https://github.com/cisco-ai-defense/mcp-scanner"
CISCO_SHA="9ff8fc84b792aae315a838cf4e37b40ef46a0293"   # main 2026-11-06, package version 4.8.7
CISCO_LITELLM="litellm>=1.106.5,!=1.107.0"

# A pinned commit fixes the scanner code, not its dependencies: uv resolves them
# fresh. --exclude-newer limits registry packages to files uploaded before this
# fixed instant (set at least 7 days back with each pin bump), so a release
# from the days before a setup run cannot slip in (see scripts/_pins.py).
EXCLUDE_NEWER="2026-11-08T09:00:00Z"

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
# --force on every run: a fresh install and a re-pin of an existing (possibly
# unpinned) install take the same path. On failure uv leaves any previous
# install in place, which is not the pinned state, so setup stops.
install_failed() {
  echo "$1 install failed; any previous install is unchanged and NOT the pinned version." >&2
  exit 1
}
SS_SPEC="git+${SKILLSPECTOR_REPO}@${SKILLSPECTOR_SHA}"
# shellcheck disable=SC2086  # LINK_ARGS is intentionally word-split (single flag or empty)
uv tool install --force "$SS_SPEC" --python "$SS_PYTHON" $LINK_ARGS --exclude-newer "$EXCLUDE_NEWER" || install_failed SkillSpector

echo ""
echo "Installing cisco-ai-mcp-scanner (optional runtime MCP check), pinned @ ${CISCO_SHA:0:12}..."
CISCO_SPEC="git+${CISCO_REPO}@${CISCO_SHA}"
# shellcheck disable=SC2086
uv tool install --force "$CISCO_SPEC" --with "$CISCO_LITELLM" $LINK_ARGS --exclude-newer "$EXCLUDE_NEWER" || install_failed cisco-ai-mcp-scanner

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
echo "     Next: configure user/process environment variables (README). .env is optional."
echo "           SkillSpector LLM: defaults to your coding-agent CLI (claude/opencode login, no API key);"
echo "           hosted providers (anthropic/openai/nv_build/...) work with a key. MCP_SCANNER_LLM_* for Cisco runtime scans."
echo "           Optional: set VIRUSTOTAL_API_KEY for binary/archive malware reputation checks"
echo "           CLI-tool scans (scan_cli.py npm/pypi/go) use Datadog GuardDog:"
echo "           native 'guarddog' on PATH if present, else the official Docker"
echo "           image ghcr.io/datadog/guarddog (pinned by digest, pulled on first scan)"
