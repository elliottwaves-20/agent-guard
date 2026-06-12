# skill-scanner

A Claude Code skill that scans AI agent skills and MCP servers for security threats using [cisco-ai-skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) before installation.

Includes a universal installer that deploys to all detected agent tools on the current machine.

## What it does

- **Scans GitHub repos as ZIP** (no `git clone` — avoids git hook execution)
- **LLM-powered analysis** via Anthropic API (`--use-llm --enable-meta`)
- **Behavioral + static analysis** (no API key required for baseline scan)
- **Verdict**: clear SAFE / CHECK / DO NOT INSTALL output
- **Universal installer**: deploys skills and MCPs to all detected tools simultaneously

## Supported tools (auto-detected)

| Tool | Skills | MCPs |
|------|--------|------|
| Claude Code | `~/.claude/skills/` | `~/.claude/settings.json` |
| Claude Desktop | — | `%APPDATA%/Claude/claude_desktop_config.json` |
| Codex | `~/.codex/skills/` | `~/.codex/config.toml` |
| Antigravity / Gemini CLI | — | `~/.gemini/config/mcp_config.json` |

Detection is automatic — only tools with existing configs are targeted.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) — for isolated installation
- An [Anthropic API key](https://console.anthropic.com/) — for LLM-powered analysis (optional but recommended)

## Setup

**Windows (PowerShell):**
```powershell
.\setup.ps1
```

**macOS / Linux:**
```bash
chmod +x setup.sh && ./setup.sh
```

Then copy `.env.example` to `.env` and fill in your API key:
```bash
cp .env.example .env
# Edit .env and set SKILL_SCANNER_LLM_API_KEY
```

Install the skill globally for Claude Code:
```bash
# Windows (Git Bash)
ln -s "$(pwd)" "$HOME/.claude/skills/skill-scanner"

# macOS / Linux
ln -s "$(pwd)" "$HOME/.claude/skills/skill-scanner"
```

## Usage

### Scan a GitHub repo before installing

```bash
# Load API key
source .env  # or: set -a && source .env && set +a

# Download as ZIP (safe — no git hooks execute)
REPO="user/repo-name"
curl -sL "https://github.com/${REPO}/archive/refs/heads/main.zip" -o /tmp/scan.zip
unzip -q /tmp/scan.zip -d /tmp/scan-dir/

# Scan
skill-scanner scan /tmp/scan-dir --use-behavioral --use-llm \
  --llm-provider anthropic --enable-meta --format table

# Cleanup
rm -rf /tmp/scan-dir /tmp/scan.zip
```

### Install after a SAFE verdict

**Skill (markdown only):**
```bash
git clone --depth=1 https://github.com/user/repo ~/path/to/workspace/repo-name
python scripts/install_skill.py skill ~/path/to/workspace/repo-name
```

**MCP server (PyPI, isolated via uvx):**
```bash
python scripts/install_skill.py mcp \
  --name "my-server" \
  --command "uvx" \
  --args "package-name" \
  --env "API_KEY=your-key"
```

**Dry run first:**
```bash
python scripts/install_skill.py mcp --name foo --command uvx --args bar --dry-run
```

### Scan all installed skills

```bash
source .env
skill-scanner scan-all ~/.claude/skills --use-behavioral --format table 2>/dev/null
```

## MCP isolation rules

Never install MCP dependencies globally. Always use isolated runners:

| Source | Command |
|--------|---------|
| PyPI package | `uvx package-name` |
| PyPI (module start) | `uv run --with dep1 --with dep2 python -m module` |
| GitHub (not on PyPI) | `uv tool install --from "git+URL" name` |
| npm | `npx --silent -y package-name` |

On OneDrive paths, add `--link-mode=copy`:
```bash
uv tool install package-name --link-mode=copy
```

## Severity guide

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Clear threat | Do not install |
| HIGH | Probable threat | Read source code, then decide |
| MEDIUM | Structural patterns | Usually false positive — verify |
| LOW / INFO | Policy hints | Safe to ignore |

## License

MIT
