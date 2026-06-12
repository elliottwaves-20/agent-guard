#!/usr/bin/env bash
# setup.sh — Install cisco-ai-skill-scanner via uv (macOS / Linux / Git Bash)
# Run: chmod +x setup.sh && ./setup.sh

set -euo pipefail

echo "Checking prerequisites..."

# Check uv
if ! command -v uv &>/dev/null; then
  echo "uv not found. Install from https://docs.astral.sh/uv/"
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

echo "  uv: $(uv --version)"
echo "  Python: $(python3 --version 2>/dev/null || python --version)"

echo ""
echo "Installing cisco-ai-skill-scanner..."
uv tool install cisco-ai-skill-scanner

echo ""
echo "Verifying..."
skill-scanner --version

echo ""
echo "[OK] Setup complete."
echo "     Next: cp .env.example .env  — then set SKILL_SCANNER_LLM_API_KEY"
