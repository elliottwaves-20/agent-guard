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
echo "Installing Cisco scanners (skills + MCP servers)..."
for pkg in cisco-ai-skill-scanner cisco-ai-mcp-scanner; do
  if uv tool list 2>/dev/null | grep -q "^${pkg}"; then
    echo "  ${pkg}: already installed -- upgrading"
    uv tool upgrade "$pkg"
  else
    # shellcheck disable=SC2086  # LINK_ARGS is intentionally word-split (single flag or empty)
    uv tool install "$pkg" $LINK_ARGS
  fi
done

echo ""
echo "Verifying..."
for bin in skill-scanner mcp-scanner; do
  if command -v "$bin" &>/dev/null; then
    echo "  $($bin --version 2>&1 | head -1)"
  else
    echo "  $bin installed but not on PATH -- run: uv tool update-shell (then reopen shell)"
  fi
done

echo ""
echo "[OK] Setup complete."
echo "     Next: cp .env.example .env  -- then set SKILL_SCANNER_LLM_API_KEY"
