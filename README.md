# agent-guard

[![skills.sh](https://skills.sh/b/elliottwaves-20/agent-guard)](https://skills.sh/elliottwaves-20/agent-guard)

**Scan any AI agent skill, plugin, or MCP server for malicious code — before it ever runs on your machine.**

Skills and MCP servers are third-party code executed with your user account's permissions. A malicious one can read your SSH keys, grab `.env` files and browser sessions, exfiltrate data — or hijack your AI agent through a poisoned SKILL.md (prompt injection). This skill makes **scan first, install after** the default workflow, powered by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (skills + the static MCP source scan) and Cisco's [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (the optional live MCP runtime check).

## Two scanners, each where it is strongest

- **[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)** handles skill scans and the **static** MCP source scan: one tool, 64 vulnerability patterns across 16 categories (prompt injection, data exfiltration, privilege escalation, MCP tool poisoning / least-privilege, supply chain with **live OSV.dev CVE lookup**), AST taint tracking, YARA signatures, and optional LLM semantic analysis with risk scoring (0–100).
- **[cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)** handles the optional **live runtime** MCP check. A static scan cannot see MCP tools that a server registers only at runtime; `scan_mcp.py --sandbox` starts the server inside a throwaway Docker container (no host filesystem access) to inspect them.

## What you get

- **Commit-pinned ZIP scanning** — repos are fetched as a ZIP snapshot of one exact commit; `git clone` never touches your machine before a verdict, and the commit that was scanned is the commit that gets installed. No scan/install gap an attacker could slip a push into.
- **Skills *and* MCP servers** — an MCP server is code that must run to be fully inspected, so naive scanning would execute it. `scan_mcp.py` scans the package **source** first (fetched from the registry, nothing executed), with an optional **Docker-sandboxed** live scan — untrusted MCP code never runs unconfined on your machine.
- **Layered analysis** — static patterns, AST taint tracking, YARA signatures, live OSV.dev CVE lookup, and optional LLM-powered semantic analysis.
- **Bring your own LLM** — Anthropic, OpenAI, NVIDIA, or any OpenAI-compatible endpoint (OpenRouter, Groq, Azure, vLLM, LM Studio, local Ollama). The optional runtime MCP scan reuses the same provider automatically.
- **Fail-closed workflow** — scanner errors are never silently treated as "no findings".
- **Prompt-injection aware** — content of scanned repos is treated as data, never as instructions to the reviewing agent.
- **Clear verdicts** — ✅ SAFE / ⚠ REVIEW / 🚫 DO NOT INSTALL, with a risk score and file/line for every finding.
- **Universal installer included** — after a SAFE verdict, one command installs the skill or MCP server to every agent detected on the machine (Claude Code, Claude Desktop, Codex, Antigravity/Gemini, Hermes, OpenClaw), or a subset via `--tools`.

## One scan, every agent

Skills are not a Claude-only concept: they follow the open [SKILL.md standard (agentskills.io)](https://agentskills.io), and [MCP](https://modelcontextprotocol.io) is an open protocol. The same skill or server runs in Claude Code, Codex, Gemini/Antigravity, [Hermes](https://hermes-agent.nousresearch.com), [OpenClaw](https://docs.openclaw.ai), and friends — and the scanner doesn't care which agent the code is destined for.

Many people now work across several agents in parallel, not least because of per-provider rate limits. That normally means installing — and *trusting* — the same third-party code once per agent. agent-guard collapses this into **scan once, verdict once, install everywhere**: one command links the audited commit into every detected agent, so all your agents run exactly the same reviewed code. Use `--tools` to target only specific agents.

## Supported tools (auto-detected)

| Tool | Skills | MCP servers |
|------|--------|-------------|
| Claude Code | `~/.claude/skills/` | `claude mcp add -s user` → `~/.claude.json` |
| Claude Desktop | `~/.claude/skills/` *(shared with Claude Code)* | `%APPDATA%/Claude/claude_desktop_config.json` |
| Codex | `~/.codex/skills/` | `~/.codex/config.toml` |
| Antigravity / Gemini | `~/.gemini/config/skills/` | `~/.gemini/config/mcp_config.json` |
| Hermes (Nous Research) | `~/.hermes/skills/` | manual — `mcp_servers:` block in Hermes `config.yaml` |
| OpenClaw | `~/.openclaw/skills/` | manual — OpenClaw's own MCP tooling |

Detection is automatic — only tools whose configs exist are touched. Claude Desktop reads skills from the same `~/.claude/skills/` as Claude Code, so that shared path is linked once and serves both. JSON configs are backed up (`.bak`) before every write. Hermes and OpenClaw use their own MCP config formats (YAML / CLI), so the installer prints instructions for those instead of modifying configs blindly.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) — installs the scanners in isolated environments (uv ships its own Python, and fetches the Python 3.12 SkillSpector needs)
- Python 3.10+ — for running `scripts/install_skill.py`, `scripts/scan_skill.py`, and `scripts/scan_mcp.py`
- An LLM provider of your choice — optional, enables LLM-powered analysis (see [LLM provider support](#llm-provider-support)); without one, skill scans run with `--no-llm`
- [Docker](https://docs.docker.com/get-docker/) — **optional**, only for the MCP sandbox (`scan_mcp.py ... --sandbox`, Stage 2). Skill scans and the default Stage 1 MCP source scan do **not** need Docker.

## Quick start

**Option A — via [skills.sh](https://skills.sh) (any of 70+ agents):**

```bash
# Installs the skill into every agent the CLI detects (Claude Code, Codex,
# Hermes, OpenClaw, Cursor, ...). Works without git.
npx skills add elliottwaves-20/agent-guard
```

This installs the skill files. The skill drives the [SkillSpector](https://github.com/NVIDIA/SkillSpector) and [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) binaries, so run the one-time setup afterwards to install them:

```bash
cd ~/.claude/skills/agent-guard   # or wherever the CLI placed it
./setup.sh                          # Windows PowerShell: .\setup.ps1
cp .env.example .env                # optional: pick an LLM provider
```

**Option B — clone and install manually:**

```bash
git clone https://github.com/elliottwaves-20/agent-guard
cd agent-guard

./setup.sh          # Windows PowerShell: .\setup.ps1

cp .env.example .env   # optional: pick an LLM provider for deeper analysis

# Register agent-guard itself into every detected agent (auto-detects your tools):
python scripts/install_skill.py skill .
```

## Usage

### Scan a GitHub repo before installing

```bash
# Load LLM provider config (optional, enables semantic analysis)
set -a && source .env && set +a

REPO="user/repo-name"
WORKDIR=$(mktemp -d)

# Pin the current commit of the default branch (works for main, master, anything)
SHA=$(curl -fsSL "https://api.github.com/repos/${REPO}/commits/HEAD" \
      | grep -m1 '"sha"' | cut -d'"' -f4)

# Download exactly that commit as ZIP — no git hooks, no git attack surface
curl -fsSL "https://github.com/${REPO}/archive/${SHA}.zip" -o "$WORKDIR/scan.zip"
unzip -q "$WORKDIR/scan.zip" -d "$WORKDIR/src"

# Scan the extracted skill directory. The wrapper handles UTF-8, provider quirks,
# and fail-closed [SAFE] / [BLOCK] verdict parsing.
python scripts/scan_skill.py --all "$WORKDIR/src"

# Cleanup (keep $SHA for installation)
rm -rf "$WORKDIR"
```

Scanner errors or empty output mean **no verdict** — never treat a failed scan as safe. A non-zero exit *with* a report is a real verdict (SkillSpector exits 1 when the risk score is above 50).

The wrapper writes SkillSpector JSON to a temporary report, so Windows console encoding issues and Anthropic's incompatible SkillSpector LLM path are handled automatically.

### Scan an MCP server before installing

MCP servers need different handling than skills. A skill is Markdown that only gets *read*; an MCP server is code that must *run* to expose its tools — so "just start it and scan" would already execute untrusted code. `scan_mcp.py` enforces a safe order:

**Stage 1 (default — nothing from the package runs):** fetch the source straight from the registry and run SkillSpector's static scan on it.

```bash
# PyPI MCP server:
python scripts/scan_mcp.py pypi mcp-server-name

# npm MCP server:
python scripts/scan_mcp.py npm @scope/mcp-server-name

# source already on disk / a hosted remote MCP:
python scripts/scan_mcp.py local ./path/to/mcp-source
python scripts/scan_mcp.py remote https://example.com/mcp
```

**Stage 2 (optional — live runtime check):** start the server inside a throwaway **Docker container with no access to your filesystem**, then scan the tools and prompts it registers at runtime — the gap a static scan cannot cover (powered by cisco-ai-mcp-scanner).

```bash
python scripts/scan_mcp.py pypi mcp-server-name --sandbox -- uvx mcp-server-name
```

`scan_mcp.py` reuses the provider you configured in `.env` for both stages. A clean Stage 1 scan does **not** prove runtime safety — reach for `--sandbox` when a server is unfamiliar. Install only after a SAFE verdict.

### Install after a SAFE verdict

Install the same commit that was scanned:

```bash
git clone https://github.com/user/repo-name ~/path/to/workspace/repo-name
git -C ~/path/to/workspace/repo-name -c advice.detachedHead=false checkout "$SHA"

# All detected agents at once:
python scripts/install_skill.py skill ~/path/to/workspace/repo-name

# Or only specific agents:
python scripts/install_skill.py skill ~/path/to/workspace/repo-name --tools claude-code hermes
```

**MCP server (PyPI, isolated via uvx) — only after `scan_mcp.py` returned SAFE:**

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

SkillSpector aggregates a whole directory into one report, so scan each skill on its own for per-skill verdicts (and to avoid walking `node_modules`):

```bash
find ~/.claude/skills -maxdepth 2 -name SKILL.md \
  | xargs -I{} dirname {} | sort -u \
  | while read -r d; do echo "== $d =="; python scripts/scan_skill.py "$d"; done
```

## LLM provider support

Configure one provider in `.env`; the wrappers choose the safe path for each scanner. `scan_skill.py` and the static stage of `scan_mcp.py` use SkillSpector with OpenAI/NVIDIA LLM support when available, and static-only scanning otherwise. `scan_mcp.py` also bridges your choice to the runtime MCP scanner.

| Provider | `.env` settings | Notes |
|----------|----------------|-------|
| **Anthropic** | `SKILLSPECTOR_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`, `SKILLSPECTOR_MODEL=claude-haiku-4-5-20251001` | SkillSpector static-only; Cisco runtime MCP scan uses Anthropic via LiteLLM |
| **OpenAI** | `SKILLSPECTOR_PROVIDER=openai`, `OPENAI_API_KEY`, `SKILLSPECTOR_MODEL=gpt-4o-mini` | |
| **OpenAI-compatible / Ollama** | `SKILLSPECTOR_PROVIDER=openai`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `SKILLSPECTOR_MODEL` | OpenRouter, Groq, Azure, vLLM, LM Studio, local Ollama |
| **NVIDIA** | `SKILLSPECTOR_PROVIDER=nv_inference` *(or `nv_build`)*, `NVIDIA_INFERENCE_KEY` | SkillSpector's native path |

> **SkillSpector's LLM layer works only with OpenAI or NVIDIA.** Its semantic analyzers request structured outputs whose JSON schema Anthropic's OpenAI-compatible endpoint rejects, so with an Anthropic key the skill and static MCP scans run **static-only** (still strong: patterns, taint tracking, YARA, OSV.dev CVE lookup). The Anthropic key still powers the optional runtime MCP scan (`--sandbox` / `remote`) via LiteLLM. For SkillSpector's LLM analysis, use OpenAI or NVIDIA.

See `.env.example` for full details. **Verdict quality depends on model quality.** This tool makes security decisions — prefer a capable model. Small local models catch fewer threats; if in doubt, combine a weak LLM verdict with a manual source review. No provider at all is fine too: `--no-llm` runs static patterns, taint tracking, YARA, and the OSV.dev CVE lookup offline.

## Security model

1. **Scanned content is data, never instructions** — a malicious SKILL.md cannot talk the reviewing agent into a SAFE verdict.
2. **Fail closed** — scanner crash/error ⇒ no verdict, not "no findings".
3. **Scan = install** — the pinned commit SHA bridges scan and installation; if the repo moves in between, re-scan.
4. **ZIP before verdict, clone after** — plain ZIP downloads execute nothing, while `git clone` has historically had RCE edge cases (e.g. CVE-2024-32002 via recursive submodules). Cloning is reserved for repos that already passed.

## Why this skill triggers capability warnings

Automated skill scanners (Socket, Snyk, ClawScan, and others) flag this skill with capability warnings. That is expected, and it is worth understanding rather than hiding — a security tool should be the most transparent skill you install.

The warnings describe what the skill genuinely does:

- **It runs external binaries.** The skill drives [SkillSpector](https://github.com/NVIDIA/SkillSpector) (skills + static MCP scan) and [cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (optional live MCP runtime check) — that *is* its job. Both are official, open-source security tools installed isolated via `uv`. SkillSpector is **pinned to an exact commit**: it is Alpha with no releases, so pinning makes "scan = install" apply to the scanner itself (review and bump deliberately); the Cisco MCP scanner is pulled from PyPI at the latest version.
- **It installs across multiple agents.** The bundled installer links the audited skill into every agent you have — the "one scan, every agent" feature. Scanners read cross-platform installation as expanded reach; here it is the intended behavior, and you can limit it with `--tools`.
- **It can route data to an LLM.** Optional LLM analysis sends the *scanned* skill's contents to the LLM provider **you** configure (Anthropic, OpenAI, NVIDIA, a local Ollama model, or none at all). No data leaves your machine unless you opt in and choose the provider.

You cannot drive these flags to green without removing the tool's reason to exist. What keeps it trustworthy is everything in the [Security model](#security-model) above: scanned content is treated as data, the workflow fails closed, repos are pinned and ZIP-scanned before any clone, and the skill ships **no hidden or invisible characters** of its own.

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

| Severity | Risk score | Meaning | Action |
|----------|-----------|---------|--------|
| CRITICAL | 81–100 | Clear threat | Do not install |
| HIGH | 51–80 | Probable threat | Read source code, then decide |
| MEDIUM | 21–50 | Structural patterns | Check context — often false positive |
| LOW | 0–20 | Minor / metadata | Usually safe to ignore |

## License

[MIT](LICENSE)
