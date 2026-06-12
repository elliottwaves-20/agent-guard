# skill-scanner

**Scan any Claude Code skill, plugin, or MCP server for malicious code — before it ever runs on your machine.**

Skills and MCP servers are third-party code executed with your user account's permissions. A malicious one can read your SSH keys, grab `.env` files and browser sessions, exfiltrate data — or hijack your AI agent through a poisoned SKILL.md (prompt injection). This skill makes **scan first, install after** the default workflow, powered by [cisco-ai-skill-scanner](https://github.com/cisco-ai-defense/skill-scanner).

## What you get

- **Commit-pinned ZIP scanning** — repos are fetched as a ZIP snapshot of one exact commit; `git clone` never touches your machine before a verdict, and the commit that was scanned is the commit that gets installed. No scan/install gap an attacker could slip a push into.
- **Three analysis layers** — static signatures, behavioral dataflow analysis, and optional LLM-powered semantic analysis with automatic false-positive filtering (Anthropic API).
- **Fail-closed workflow** — scanner errors are never silently treated as "no findings".
- **Prompt-injection aware** — content of scanned repos is treated as data, never as instructions to the reviewing agent.
- **Clear verdicts** — ✅ SAFE / ⚠️ REVIEW / 🚫 DO NOT INSTALL, with file and line for every finding.
- **Universal installer included** — after a SAFE verdict, one command installs the skill or MCP server to every agent tool detected on the machine.

## Supported tools (auto-detected)

| Tool | Skills | MCP servers |
|------|--------|-------------|
| Claude Code | `~/.claude/skills/` | `claude mcp add -s user` → `~/.claude.json` |
| Claude Desktop | — | `%APPDATA%/Claude/claude_desktop_config.json` |
| Codex | `~/.codex/skills/` | `~/.codex/config.toml` |
| Antigravity / Gemini CLI | — | `~/.gemini/config/mcp_config.json` |

Detection is automatic — only tools whose configs exist are touched. JSON configs are backed up (`.bak`) before every write.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) — installs the scanner in an isolated environment (uv ships its own Python)
- Python 3.10+ — only for running `scripts/install_skill.py`
- An [Anthropic API key](https://console.anthropic.com/) — optional, enables LLM-powered analysis

## Quick start

```bash
git clone https://github.com/elliottwaves-20/skill-scanner
cd skill-scanner

./setup.sh          # Windows PowerShell: .\setup.ps1

cp .env.example .env   # optional: set SKILL_SCANNER_LLM_API_KEY for LLM analysis

# Register as a global Claude Code skill (auto-detects your tools):
python scripts/install_skill.py skill .
```

## Usage

### Scan a GitHub repo before installing

```bash
# Load API key (optional, enables --use-llm)
set -a && source .env && set +a

REPO="user/repo-name"
WORKDIR=$(mktemp -d)

# Pin the current commit of the default branch (works for main, master, anything)
SHA=$(curl -fsSL "https://api.github.com/repos/${REPO}/commits/HEAD" \
      | grep -m1 '"sha"' | cut -d'"' -f4)

# Download exactly that commit as ZIP — no git hooks, no git attack surface
curl -fsSL "https://github.com/${REPO}/archive/${SHA}.zip" -o "$WORKDIR/scan.zip"
unzip -q "$WORKDIR/scan.zip" -d "$WORKDIR/src"

# Scan the extracted skill directory (the ZIP unpacks into <repo>-<sha>/)
skill-scanner scan "$WORKDIR/src"/* --use-behavioral --use-llm \
  --llm-provider anthropic --enable-meta --format table

# Cleanup (keep $SHA for installation)
rm -rf "$WORKDIR"
```

Scanner errors or empty output mean **no verdict** — never treat a failed scan as safe.

### Install after a SAFE verdict

Install the same commit that was scanned:

```bash
git clone https://github.com/user/repo-name ~/path/to/workspace/repo-name
git -C ~/path/to/workspace/repo-name -c advice.detachedHead=false checkout "$SHA"

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

**Dry run first** to preview every change:

```bash
python scripts/install_skill.py mcp --name foo --command uvx --args bar --dry-run
python scripts/install_skill.py skill <path> --dry-run
```

### Audit all installed skills

```bash
skill-scanner scan-all ~/.claude/skills --use-behavioral --format table
```

## Security model

1. **Scanned content is data, never instructions** — a malicious SKILL.md cannot talk the reviewing agent into a SAFE verdict.
2. **Fail closed** — scanner crash/error ⇒ no verdict, not "no findings".
3. **Scan = install** — the pinned commit SHA bridges scan and installation; if the repo moves in between, re-scan.
4. **ZIP before verdict, clone after** — plain ZIP downloads execute nothing, while `git clone` has historically had RCE edge cases (e.g. CVE-2024-32002 via recursive submodules). Cloning is reserved for repos that already passed.

## MCP isolation rules

Never install MCP dependencies globally. Always use isolated runners:

| Source | Command |
|--------|---------|
| PyPI package | `uvx package-name` |
| PyPI (module start) | `uv run --with dep1 --with dep2 python -m module` |
| GitHub (not on PyPI) | `uv tool install --from "git+URL" name` |
| npm | `npx --silent -y package-name` |

On synced folders (OneDrive, Dropbox), add `--link-mode=copy`:

```bash
uv tool install package-name --link-mode=copy
```

## Severity guide

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Clear threat | Do not install |
| HIGH | Probable threat | Read source code, then decide |
| MEDIUM | Structural patterns | Check context — often false positive |
| LOW / INFO | Policy hints | Usually safe to ignore |

## License

[MIT](LICENSE)
