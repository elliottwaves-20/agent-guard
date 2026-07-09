# agent-guard

[![skills.sh](https://skills.sh/b/elliottwaves-20/agent-guard)](https://skills.sh/elliottwaves-20/agent-guard)

**Scan any AI agent skill, plugin, MCP server, or CLI tool for malicious code — before it ever runs on your machine.**

Skills, MCP servers, and the CLI tools agents install (npm/PyPI/Go packages, cargo crates, release binaries, `curl | bash` installers) are third-party code executed with your user account's permissions. A malicious one can read your SSH keys, grab `.env` files and browser sessions, exfiltrate data — or hijack your AI agent through a poisoned SKILL.md (prompt injection). This skill makes **scan first, install after** the default workflow, powered by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (skills + static source scans), Cisco's [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (the optional live MCP runtime check), and Datadog's [GuardDog](https://github.com/DataDog/guarddog) plus VirusTotal/[malcontent](https://github.com/chainguard-dev/malcontent) (CLI tools — see [Scan a CLI tool before installing](#scan-a-cli-tool-before-installing)).

## Contents

- [The right professional scanner for each target](#the-right-professional-scanner-for-each-target)
- [What you get](#what-you-get)
- [One scan, every agent](#one-scan-every-agent)
- [Supported tools (auto-detected)](#supported-tools-auto-detected)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Scan a GitHub repo before installing](#scan-a-github-repo-before-installing)
  - [Scan a skill catalog](#scan-a-skill-catalog)
  - [Scan any URL](#scan-any-url)
  - [Audit downloaded or installed items](#audit-downloaded-or-installed-items)
  - [Exit codes](#exit-codes)
  - [Scan an MCP server before installing](#scan-an-mcp-server-before-installing)
  - [Scan a CLI tool before installing](#scan-a-cli-tool-before-installing)
  - [Install after a SAFE verdict](#install-after-a-safe-verdict)
  - [Audit all installed skills](#audit-all-installed-skills)
- [LLM provider support](#llm-provider-support)
- [Detection limits — what a SAFE verdict does *not* mean](#detection-limits--what-a-safe-verdict-does-not-mean)
- [Security model](#security-model)
- [Why this skill triggers capability warnings](#why-this-skill-triggers-capability-warnings)
- [MCP isolation rules](#mcp-isolation-rules)
- [Severity guide](#severity-guide)

## The right professional scanner for each target

agent-guard never writes its own detection — it routes every install target to the professional scanner best suited for it and turns the result into one consistent fail-closed verdict:

- **[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)** handles skill scans and the **static** MCP source scan: one tool, 64 vulnerability patterns across 16 categories (prompt injection, data exfiltration, privilege escalation, MCP tool poisoning / least-privilege, supply chain with **live OSV.dev CVE lookup**), AST taint tracking, YARA signatures, and optional LLM semantic analysis with risk scoring (0–100). Also covers `curl | bash` install scripts and cargo crate sources.
- **[cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)** handles the optional **live runtime** MCP check. A static scan cannot see MCP tools that a server registers only at runtime; `scan_mcp.py --sandbox` starts the server inside a throwaway Docker container (no host filesystem access) to inspect them.
- **[Datadog GuardDog](https://github.com/DataDog/guarddog)** handles **CLI-tool package scans** (npm, PyPI, Go): malware heuristics + YARA over package source and registry metadata, via the official Docker image on Windows.
- **VirusTotal + [malcontent](https://github.com/chainguard-dev/malcontent)** handle **release binaries**: hash reputation against 70+ AV vendors, optionally (`--deep`) a capability analysis of what the binary can actually do.

## What you get

- **Commit-pinned ZIP scanning** — repos are fetched as a ZIP snapshot of one exact commit; `git clone` never touches your machine before a verdict, and the commit that was scanned is the commit that gets installed. No scan/install gap an attacker could slip a push into.
- **Skills, MCP servers, *and* CLI tools** — an MCP server is code that must run to be fully inspected, so naive scanning would execute it. `scan_mcp.py` scans the package **source** first (fetched from the registry, nothing executed), with an optional **Docker-sandboxed** live scan — untrusted MCP code never runs unconfined on your machine. `scan_cli.py` extends the same scan-first gate to the CLI tools agents install: npm/PyPI/Go packages, cargo crates, release binaries, and `curl | bash` installers, all downloaded but **never executed** before their verdict.
- **Layered analysis** — static patterns, AST taint tracking, YARA signatures, live OSV.dev CVE lookup, and LLM-powered semantic analysis when configured.
- **Best scanner for each layer** — SkillSpector's full LLM-assisted skill/static scan requires OpenAI or NVIDIA credentials; Cisco's optional runtime MCP scan uses LiteLLM and can use any supported provider.
- **Fail-closed workflow** — scanner errors are never silently treated as "no findings".
- **Prompt-injection aware** — content of scanned repos is treated as data, never as instructions to the reviewing agent.
- **Clear verdicts** — ✅ SAFE / ⚠ REVIEW / 🚫 DO NOT INSTALL, with a risk score and file/line for every finding.
- **Universal installer included** — after a SAFE verdict, one command installs the skill or MCP server to every agent detected on the machine (Claude Code, Claude Desktop, Codex, Antigravity/Gemini, Hermes, OpenClaw), or a subset via `--tools`. Local MCP servers are installed through isolated launchers (`uvx`, `uv tool`, `npx`) so one server's dependencies do not pollute or break another.

## One scan, every agent

Skills are not a Claude-only concept: they follow the open [SKILL.md standard (agentskills.io)](https://agentskills.io), and [MCP](https://modelcontextprotocol.io) is an open protocol. The same skill or server runs in Claude Code, Codex, Gemini/Antigravity, [Hermes](https://hermes-agent.nousresearch.com), [OpenClaw](https://docs.openclaw.ai), and friends — and the scanner doesn't care which agent the code is destined for.

Many people now work across several agents in parallel, not least because of per-provider rate limits. That normally means installing — and *trusting* — the same third-party code once per agent. agent-guard collapses this into **scan once, verdict once, install everywhere**: one command links the audited commit into every detected agent, so all your agents run exactly the same reviewed code. Use `--tools` to target only specific agents.

## Supported tools (auto-detected)

| Tool | Skills | MCP servers |
|------|--------|-------------|
| Claude Code | `~/.claude/skills/` | `claude mcp add -s user` → `~/.claude.json` |
| Claude Desktop | `~/.claude/skills/` *(shared with Claude Code)* | Windows: `%APPDATA%/Claude/` · macOS: `~/Library/Application Support/Claude/` · Linux: `$XDG_CONFIG_HOME` or `~/.config/Claude/` — `claude_desktop_config.json` |
| Codex | `~/.codex/skills/` | `~/.codex/config.toml` |
| Antigravity / Gemini | `~/.gemini/config/skills/` | `~/.gemini/config/mcp_config.json` |
| Hermes (Nous Research) | `~/.hermes/skills/` | manual — `mcp_servers:` block in Hermes `config.yaml` |
| OpenClaw | `~/.openclaw/skills/` | manual — OpenClaw's own MCP tooling |

Detection is automatic — only tools whose configs exist are touched. Claude Desktop reads skills from the same `~/.claude/skills/` as Claude Code, so that shared path is linked once and serves both. JSON configs are backed up (`.bak`) before every write. Hermes and OpenClaw use their own MCP config formats (YAML / CLI), so the installer prints instructions for those instead of modifying configs blindly.

## Prerequisites

Required for the normal scan/install workflow:

- [uv](https://docs.astral.sh/uv/) — installs SkillSpector and Cisco mcp-scanner in isolated tool environments. uv also fetches the Python 3.12 runtime that SkillSpector needs.
- Python 3.10+ — runs the agent-guard wrapper scripts: `scripts/install_skill.py`, `scripts/scan_skill.py`, `scripts/scan_mcp.py`, and `scripts/scan_url.py`.
- OpenAI or NVIDIA credentials for full SkillSpector LLM coverage. Without them, skill and static MCP source scans still run static-only.
- A LiteLLM-compatible runtime provider for Cisco live MCP checks: `MCP_SCANNER_LLM_API_KEY` plus `MCP_SCANNER_LLM_MODEL`. This can be OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Ollama, or another LiteLLM-supported provider.

Optional, depending on what you scan or install:

- [Docker](https://docs.docker.com/get-docker/) — only for Docker-isolated live stdio MCP checks (`scan_mcp.py ... --sandbox`). Skill scans and default Stage 1 MCP source scans do not need Docker. The Docker daemon must be **running** before a sandbox scan (on Windows/macOS: start Docker Desktop first); `failed to connect to the docker API` means it is not.
- `VIRUSTOTAL_API_KEY` — optional malware-reputation checks for bundled binaries, archives, PDFs, images, and similar non-source files. VirusTotal's Public API is free for registered users but rate-limited; see [LLM provider support](#llm-provider-support).
- Node.js/npm — optional. Needed if you install or run npm MCP servers through `npx`, install the Firecrawl CLI with npm, or use the Node Playwright rendered-page fallback for protected marketplaces.
- Firecrawl CLI or Node Playwright — optional renderers for JavaScript-heavy/protected marketplace pages. Direct GitHub/archive/raw SKILL.md/npm/PyPI URLs work without them.
- Git — optional, but needed for `install_skill.py mcp-git` / `uv tool install --from git+...` and for manual clone/checkout workflows after a SAFE verdict.

Platform notes:

- **macOS / Linux** are fully supported: run `bash setup.sh`; symlinks work
  natively, and Claude Desktop configs are detected at their platform paths
  (see the table above).
- **Windows on ARM64**: `yara-python` (a SkillSpector dependency) publishes no
  `win_arm64` wheels, so the setup scripts detect ARM64 and install
  SkillSpector with an x86-64 Python that Windows 11 runs under transparent
  x64 emulation — prebuilt wheels then work without a C compiler. Everything
  else (Cisco scanner, Docker sandbox, installer) runs natively on ARM64.

## Quick start

> **Windows:** run the bash examples in this README from **Git Bash** (bundled
> with Git for Windows). PowerShell users: use `.\setup.ps1` for setup; most
> other examples are bash-flavored.

**Option A — via [skills.sh](https://skills.sh) (any of 70+ agents):**

```bash
# Installs the skill into every agent the CLI detects (Claude Code, Codex,
# Hermes, OpenClaw, Cursor, ...). Works without git.
npx skills add elliottwaves-20/agent-guard
```

This installs the skill files. The skill drives the [SkillSpector](https://github.com/NVIDIA/SkillSpector) and [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) binaries, so run the one-time setup afterwards to install them:

```bash
cd ~/.claude/skills/agent-guard   # or wherever the CLI placed it
bash setup.sh                       # Windows PowerShell: .\setup.ps1
cp .env.example .env                # set SkillSpector + optional Cisco runtime LLMs
```

The wrappers auto-load **your own** `.env` (created from `.env.example`,
gitignored — never part of the repo) from the skill/repo directory when
present. For a custom location, set `AGENT_GUARD_ENV_FILE=/path/to/.env`.

**No API keys yet?** Scans still work: without LLM credentials SkillSpector
runs its full static layer (64 patterns, AST taint tracking, YARA, live OSV.dev
CVE lookup) — only the LLM semantic layer and the Cisco runtime check need keys.
Add keys later for full coverage.

**Option B — clone and install manually:**

```bash
git clone https://github.com/elliottwaves-20/agent-guard
cd agent-guard

bash setup.sh       # Windows PowerShell: .\setup.ps1

cp .env.example .env   # set SkillSpector + optional Cisco runtime LLMs

# Register agent-guard itself into every detected agent (auto-detects your tools):
python scripts/install_skill.py skill .
```

The scan wrappers auto-load **your own** `.env` (created from `.env.example`,
gitignored — never part of the repo) from the repo directory, the current
working directory, or `AGENT_GUARD_ENV_FILE` if you keep secrets elsewhere.

**Smoke test** — verify the whole chain (uv tools, resolver, scanner) with a
small, known-harmless skill:

```bash
python scripts/scan_url.py "https://github.com/anthropics/skills/tree/main/skills/brand-guidelines" --dry-run
```

Expected: the skill resolves to a commit-pinned snapshot and the scan ends with
`[SAFE] risk 0/100` plus an install hint. Exit code `2` instead means a
setup/config problem — see [Exit codes](#exit-codes).

Some marketplaces protect listing pages with JavaScript or bot checks. Direct
source URLs still work without extra tooling, but protected marketplace pages
need a renderer so agent-guard can read the page before scanning it. The URL
scanner first tries a normal static fetch, then a rendered-page fallback if one
is available.

Supported renderer options:

- Firecrawl CLI, installed via npm and authenticated, then exposed through
  `AGENT_GUARD_FETCH_COMMAND`.
- Node Playwright installed locally; agent-guard can use it as a fallback when
  no external fetch command is configured.

Firecrawl example:

```bash
npm install -g firecrawl
firecrawl login
export AGENT_GUARD_FETCH_COMMAND='firecrawl scrape --format markdown --only-main-content --wait-for 3000 {url}'
```

If you do not install Firecrawl globally, use the normal npm/npx form:

```bash
export AGENT_GUARD_FETCH_COMMAND='npx firecrawl scrape --format markdown --only-main-content --wait-for 3000 {url}'
```

For the built-in Playwright fallback, install the browser binary once with the
normal Playwright CLI flow:

```bash
npx playwright install chromium
```

agent-guard first uses a local `playwright` Node package when present. If it is
not installed in the project, the resolver tries the npx package path and then a
temporary npm package install for that render attempt. That keeps the repository
provider-neutral while still supporting protected JavaScript-heavy marketplaces.

Without a working renderer, protected marketplace pages fail closed with no
verdict; direct GitHub/archive/raw SKILL.md/npm/PyPI URLs still work normally.

## Usage

### Scan a GitHub repo before installing

```bash
# Optional: load LLM provider config into the shell. The wrappers also auto-load
# .env from the repo/skill directory when present.
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

### Scan a skill catalog

Some repositories are catalogs or "awesome lists": they contain links to many
skills but no installable root `SKILL.md`. Treat those as indexes, not skills.
They must not be linked into an agent's skills directory.

```bash
python scripts/scan_skill.py --catalog "$WORKDIR/src"
```

Catalog mode scans the catalog text itself and lists linked GitHub repositories.
That verdict applies only to the catalog document. Pick concrete linked skills,
fetch a pinned commit for each, run `scan_skill.py` / `scan_skill.py --all`, and
install only the specific `SKILL.md` directory that passed.

### Scan any URL

Use the URL resolver when you do not know whether a link points to a skill, an
MCP package, an archive, or a marketplace/catalog page:

```bash
python scripts/scan_url.py "https://github.com/user/repo/tree/main/skills/foo" \
  --keep-source ~/Github/scanned-skill-foo --dry-run
python scripts/scan_url.py "https://pypi.org/project/some-mcp-server/" --dry-run
python scripts/scan_url.py "https://www.npmjs.com/package/@scope/server" --dry-run
python scripts/scan_url.py "https://example.com/marketplace/listing" --dry-run
```

Supported automatic resolution:

- GitHub repo/tree/blob links are fetched as commit-pinned ZIP snapshots.
- Direct `.zip`, `.tar`, `.tar.gz`, and `.tgz` archives are safely extracted.
- PyPI and npm package pages are routed to the MCP source scanner.
- Unknown web pages are treated as marketplace/catalog pages: the page text is
  scanned, and agent-guard extracts concrete local/source candidates (GitHub,
  npm, PyPI, archives), remote MCP URLs (`/mcp` / `/sse`), and visible install
  commands where possible. Nothing is installable from the listing itself.

Marketplace pages are discovery surfaces, not install targets. A SAFE catalog
verdict only covers the listing text. It is **not** a security verdict for the
listed MCP or skill.

MCP listings need one more classification step:

- **Remote HTTP/SSE MCP**: there are no local install files to source-scan.
  Scan the concrete URL with Cisco runtime scanning:
  `python scripts/scan_mcp.py remote https://example.com/mcp`.
- **Locally installable stdio MCP**: there must be an artifact somewhere
  (npm/PyPI package, GitHub/GitLab repo, archive, Cargo/NuGet package, OCI
  image, MCPB release, or a local download). Scan that artifact/source first;
  then run sandbox runtime inspection for unfamiliar servers.
- **Marketplace listing without source/remote/command**: agent-guard fails
  closed with `NO INSTALLABLE SOURCE`. The page may be harmless, but no real
  MCP security verdict is possible until a concrete source, package, remote
  URL, or install command is provided.

For marketplace pages, `scan_url.py` scans discovered candidates automatically
by default. `--dry-run` only means "do not install or modify agent configs";
security scans still run. Use `--no-scan-candidates` only when you explicitly
want to inspect the listing and candidate plan without following candidates.
Use `--sandbox` to run live Docker-isolated Cisco runtime scans for discovered
stdio install commands after their source/package scan.

After a SAFE scan of an installable skill or MCP, interactive runs ask whether
to install. The default is **not** "install everywhere": choose selected agent
targets, or explicitly choose all detected agents. In non-interactive shells,
agent-guard prints the safe install command instead of modifying configs.
MCP install prompts always use isolated runners: PyPI via `uvx`, npm via
`npx --silent -y`, and GitHub-only Python MCPs via `uv tool install --from`
before registering the resulting local tool path.

By default URL scans use a temporary directory. Use `--keep-source <dir>` when
you want to install the exact source that was scanned after a SAFE verdict.

### Audit downloaded or installed items

If you already downloaded a skill or MCP source but did not install it yet:

```bash
# Dry-run: print the scan command only
python scripts/audit_installed.py download ./downloaded-source

# Execute the safe scan against the local path
python scripts/audit_installed.py --execute download ./downloaded-source
```

For already installed items:

```bash
# Inventory installed skills/MCPs and print scan + removal guidance
python scripts/audit_installed.py installed

# Execute scans for installed skills and inferable MCPs
python scripts/audit_installed.py --execute installed
```

Installed skill directories are scanned in place. Installed MCPs are never run
directly on the host: package/source scans are inferred where possible, and
runtime checks are routed through `scan_mcp.py sandbox`. The audit also prints
removal guidance for each detected item; review and remove malicious entries
from the relevant agent config before restarting the affected agent.

Scanner errors or empty output mean **no verdict** — never treat a failed scan as safe. A non-zero exit *with* a report is a real verdict (SkillSpector exits 1 when the risk score is above 50).

### Exit codes

A non-zero exit is usually a **verdict, not a tool failure** — important when
wiring agent-guard into scripts or CI:

| Exit code | Meaning | Action |
|-----------|---------|--------|
| `0` | SAFE verdict | Install is reasonable |
| `1` | BLOCK/REVIEW verdict — real findings were reported | Read the findings, decide deliberately |
| `2` | **No verdict** — scanner/LLM/config error, fail-closed | Fix the cause and re-run; never install |

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

The Docker daemon must be running (start Docker Desktop on Windows/macOS). The
first sandbox run builds the scan image and pre-fetches dependencies, which can
take a few minutes; later runs reuse the image and are much faster.

Stage 1 uses SkillSpector. For full LLM-assisted Stage 1 coverage, configure OpenAI or NVIDIA under `SKILLSPECTOR_*`. Stage 2 uses Cisco mcp-scanner with `MCP_SCANNER_LLM_*` for LLM/behavioral analysis. If you set `VIRUSTOTAL_API_KEY`, Cisco mcp-scanner can also check bundled binaries, archives, PDFs, and similar non-source files against VirusTotal by hash. A clean Stage 1 scan does **not** prove runtime safety — reach for `--sandbox` when a server is unfamiliar. Install only after a SAFE verdict.

### Scan a CLI tool before installing

Agents increasingly install plain command-line tools instead of MCP servers — npm/PyPI/Go packages, cargo crates, GitHub release binaries, and `curl | bash` installers. `scan_cli.py` gives those installs the same scan-first workflow by routing each source to the professional scanner best suited for it (agent-guard never writes its own detection):

```bash
# npm / PyPI / Go packages -> Datadog GuardDog (heuristics + YARA + registry metadata):
python scripts/scan_cli.py npm left-pad
python scripts/scan_cli.py pypi requests==2.32.0
python scripts/scan_cli.py go github.com/user/module

# GitHub release binary -> download (never executed), SHA256, VirusTotal hash check:
python scripts/scan_cli.py binary https://github.com/user/tool/releases/download/v1.0/tool.exe
# --deep adds a malcontent capability analysis (Docker):
python scripts/scan_cli.py binary <url> --deep

# curl | bash installer -> SkillSpector static scan; the script is never executed:
python scripts/scan_cli.py script https://example.com/install.sh

# cargo crate -> static source scan fallback (GuardDog has no cargo support):
python scripts/scan_cli.py cargo ripgrep@14.1.0
```

Exit codes follow the same contract as every other agent-guard scanner: `0` SAFE, `1` BLOCK verdict, `2` no verdict (fail closed).

Requirements per mode:

- **npm / pypi / go** use [GuardDog](https://github.com/DataDog/guarddog). It runs natively if `guarddog` is on PATH (Linux/macOS: `pipx install guarddog`); on **Windows, Docker is GuardDog's only supported install**, so the wrapper falls back to the official image `ghcr.io/datadog/guarddog` automatically (first scan pulls it — start Docker Desktop first). GuardDog's `capability-*` rules are transparency notes ("can read files / spawn processes") that fire on nearly every real library — the wrapper prints them but only lets **malware-heuristic** rules drive the BLOCK verdict; review the capability list for anything implausible for the package's purpose. Exception: `capability-process-hooks` (a setup.py install/develop hook — code that runs at `pip install` time, the classic PyPI malware vector) **does block**; this was verified against DataDog's own malicious-package dataset, where a real sample fires only that rule.
- **binary** needs `VIRUSTOTAL_API_KEY` (free tier: 4 lookups/min). `--deep` needs Docker for [malcontent](https://github.com/chainguard-dev/malcontent).
- **script** and **cargo** use the SkillSpector static scan already set up by `setup.sh` / `setup.ps1`.

**Complementary runtime gates (not integrated, recommended alongside):** a scan-first verdict and an install-time gate catch different things. [Socket Firewall Free (`sfw`)](https://github.com/SocketDev/sfw-free) wraps package managers (`sfw npm install X`, `sfw pip install X`, `sfw cargo fetch`) and blocks known-malicious packages at install time using Socket's live threat feed — a second net behind any GuardDog verdict. [tirith](https://github.com/sheeki03/tirith) hooks the shell itself and intercepts pipe-to-shell, homograph URLs, and typosquats before any command runs (AGPL-3.0; daemon mode is Unix-only, PowerShell hooks on Windows).

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
  --arg "package-name" \
  --env "API_KEY=your-key"
```

Pass each server argument as its own repeated `--arg`. The legacy `--args` form
consumes *everything* after it (including `--env` and `--dry-run`), so the
installer rejects installer options placed after `--args` instead of silently
misconfiguring the server.

**MCP server (npm, isolated via npx):**

```bash
python scripts/install_skill.py mcp \
  --name "my-server" \
  --command "npx" \
  --arg=--silent \
  --arg=-y \
  --arg="@scope/package-name"
```

**GitHub-only Python MCP (not on PyPI):**

```bash
python scripts/install_skill.py mcp-git \
  --name "my-server" \
  --git-url "git+https://github.com/user/repo@<scanned-sha>" \
  --package "package-name" \
  --executable "server-executable"
```

`mcp-git` first runs `uv tool install --from ...` in uv's isolated tool
environment, then writes the resulting executable path into each selected agent
config. This avoids relying on `git` being available inside GUI agent process
environments.

**Remote HTTP/SSE MCP (no local dependencies):**

```bash
python scripts/install_skill.py mcp-remote \
  --name "remote-server" \
  --url "https://example.com/mcp"
```

**Dry run first** to preview every change:

```bash
python scripts/install_skill.py mcp --name foo --command uvx --arg bar --dry-run
python scripts/install_skill.py mcp-git --name foo --git-url git+https://github.com/user/repo@sha --package foo --dry-run
python scripts/install_skill.py mcp-remote --name foo --url https://example.com/mcp --dry-run
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

agent-guard has two separate LLM configuration surfaces, plus one practical
optional malware-reputation layer:

| Scanner layer | What it covers | Configuration |
|---------------|----------------|---------------|
| **NVIDIA SkillSpector** | skill scans and static MCP source scans | OpenAI or NVIDIA key is required for full SkillSpector LLM coverage |
| **Cisco mcp-scanner LLM** | live MCP runtime scans (`remote` / `--sandbox`) | `MCP_SCANNER_LLM_*`; any LiteLLM-supported provider |
| **VirusTotal analyzer** | optional malware reputation for bundled binaries, archives, PDFs, and similar non-source files | `VIRUSTOTAL_API_KEY` |

SkillSpector still runs its static layer without a compatible LLM: patterns, taint tracking, YARA, and OSV.dev CVE lookup remain active. That is useful, but it is not the full LLM-assisted SkillSpector check. Configure `SKILLSPECTOR_PROVIDER=openai` with `OPENAI_API_KEY`, or `SKILLSPECTOR_PROVIDER=nv_inference` / `nv_build` with `NVIDIA_INFERENCE_KEY`, for full static/skill coverage.

Cisco's runtime scanner is independent. Set `MCP_SCANNER_LLM_API_KEY`, `MCP_SCANNER_LLM_MODEL`, and optionally `MCP_SCANNER_LLM_BASE_URL` / `MCP_SCANNER_LLM_API_VERSION` for OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Ollama, or any LiteLLM-supported model. The key and model provider must match: use a Claude/Anthropic model such as `claude-haiku-4-5` with an Anthropic key, or a GPT/OpenAI model with an OpenAI key. For local LLM endpoints such as Ollama, Cisco still expects `MCP_SCANNER_LLM_API_KEY` to be set; use a harmless dummy value such as `ollama` or `test`.

VirusTotal is optional but useful for private users because it fills a different gap than source scanning: known malware in bundled binary or archive-like files. Cisco's VirusTotal analyzer sends SHA256 hashes by default, not file contents; uploads happen only if `MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=true` is explicitly set.

VirusTotal's Public API is available at no cost after creating a VirusTotal Community account. Get the key from [your personal API key page](https://www.virustotal.com/gui/my-apikey) while signed in. Public API limits are **500 requests/day** and **4 requests/minute**, and VirusTotal restricts it to non-commercial/non-business-workflow use. Premium keys are for professional/commercial use: quotas are governed by the licensed plan, and Premium exposes more threat context, advanced hunting/malware-discovery features, sample downloads, richer observable relationships, and SLA-backed data readiness. For agent-guard's default use case, the free key is enough to add lightweight hash reputation checks for bundled binaries; Premium is only relevant if you already have a professional VirusTotal workflow.

After setting `VIRUSTOTAL_API_KEY`, test the optional malware-reputation layer
through agent-guard's wrapper. It calls Cisco's VirusTotal analyzer directly and
avoids known CLI regressions in Cisco's standalone VirusTotal subcommand:

```bash
set -a && source .env && set +a
python scripts/scan_mcp.py virustotal ./downloaded-source
```

PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY = "<your VirusTotal key>"
python scripts/scan_mcp.py virustotal .
```

Advanced / enterprise: Cisco mcp-scanner also supports Cisco AI Defense's hosted inspect API analyzer through `MCP_SCANNER_API_KEY` and optional `MCP_SCANNER_ENDPOINT`. agent-guard does not require this, and most personal setups should ignore it unless they already have Cisco AI Defense access.

See `.env.example` for full details. **Verdict quality depends on model quality.** This tool makes security decisions — prefer capable models. Small local models catch fewer threats; if in doubt, combine a weak LLM verdict with a manual source review.

## Detection limits — what a SAFE verdict does *not* mean

No scanner — not agent-guard, not the professional tools it wraps — can guarantee a package is harmless. A SAFE verdict means **"nothing known-bad was found"**, never "proven safe". The specific, honest limits per stage:

| Stage | Limit |
|-------|-------|
| VirusTotal (`binary`, MCP non-source files) | Recognises only **known** malware hashes. A novel or targeted binary passes unnoticed. Prefer signed releases of well-known projects. |
| malcontent (`binary --deep`) | Capability analysis, not proof. **Windows PE coverage is weaker than Linux ELF** — treat a clean `.exe` result with extra care. |
| GuardDog (`npm`/`pypi`/`go`) | Heuristics + YARA over known attack patterns. A clean result is not proof of harmlessness, and GuardDog does not cover cargo. `capability-*` findings are printed as informational and do **not** block (exception: `capability-process-hooks` — install-time code execution — blocks) — a malicious package whose only tell is an implausible remaining capability needs your judgment on that list. |
| cargo fallback | **Static source scan only.** Registry metadata — maintainer changes, publish anomalies, typosquat rankings — is not checked. Use `sfw cargo install <crate>` as an install-time net. |
| `script` scan | **Static.** A second-stage payload the installer downloads at runtime is invisible; scan those URLs separately. |
| SkillSpector static scans | Cannot see behavior that only appears at runtime (MCP: use `--sandbox`). Static-only mode (no LLM configured) misses semantic attacks that pattern rules don't encode. |
| Live MCP sandbox scan | Contains host-filesystem access, **not** network egress; the LLM-based analysis is itself probabilistic. |

Where a stage in a scan output has such a limit, the wrapper prints it inline (`LIMIT:` / `NOTE:` lines) — so the verdict and its caveat always travel together.

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
- **It can route data to an LLM.** SkillSpector sends scanned skill/static-source contents only when you configure a compatible OpenAI or NVIDIA provider. Cisco's runtime MCP scan sends runtime tool/prompt data to the `MCP_SCANNER_LLM_*` provider you configure. No data leaves your machine unless you opt in and choose the provider.

You cannot drive these flags to green without removing the tool's reason to exist. What keeps it trustworthy is everything in the [Security model](#security-model) above: scanned content is treated as data, the workflow fails closed, repos are pinned and ZIP-scanned before any clone, and the skill ships **no hidden or invisible characters** of its own.

## MCP isolation rules

Never install MCP dependencies globally. Always use isolated runners so MCP
servers cannot create dependency conflicts with each other or with your system
Python/Node installation:

| Source | Command |
|--------|---------|
| PyPI package | `uvx package-name` |
| PyPI (module start) | `uv run --with dep1 --with dep2 python -m module` |
| GitHub (not on PyPI) | `uv tool install --from "git+URL" name` |
| npm | `npx --silent -y package-name` |
| Remote HTTP/SSE | URL in agent config; no local dependencies |

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
