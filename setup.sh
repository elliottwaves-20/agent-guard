#!/usr/bin/env bash
# setup.sh -- Install cisco-ai-skill-scanner via uv (macOS / Linux / Git Bash)
# Run: chmod +x setup.sh && ./setup.sh

set -euo pipefail

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

echo ""
echo "Installing cisco-ai-skill-scanner..."
if uv tool list 2>/dev/null | grep -q "^cisco-ai-skill-scanner"; then
  echo "  already installed -- upgrading instead"
  uv tool upgrade cisco-ai-skill-scanner
else
  # shellcheck disable=SC2086  # LINK_ARGS is intentionally word-split (single flag or empty)
  uv tool install cisco-ai-skill-scanner $LINK_ARGS
fi

echo ""
echo "Verifying..."
if command -v skill-scanner &>/dev/null; then
  skill-scanner --version
else
  echo "skill-scanner is installed but not on PATH."
  echo "  Run: uv tool update-shell   -- then open a new shell."
fi

echo ""
echo "[OK] Setup complete."
echo "     Next: cp .env.example .env  -- then set SKILL_SCANNER_LLM_API_KEY"
