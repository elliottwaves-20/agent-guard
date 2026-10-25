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
    - [Dynamic install analysis](#dynamic-install-analysis)
  - [Install after a SAFE verdict](#install-after-a-safe-verdict)
  - [Audit all installed skills](#audit-all-installed-skills)
- [LLM provider support](#llm-provider-support)
- [Detection limits — what a SAFE verdict does *not* mean](#detection-limits--what-a-safe-verdict-does-not-mean)
- [Security model](#security-model)
- [Why this skill triggers capability warnings](#why-this-skill-triggers-capability-warnings)
- [Reviewing self-scan findings](#reviewing-self-scan-findings)
- [Running the tests](#running-the-tests)
- [MCP isolation rules](#mcp-isolation-rules)
- [Severity guide](#severity-guide)

## The right professional scanner for each target

agent-guard never writes its own detection — it routes every install target to the professional scanner best suited for it and turns the result into one consistent fail-closed verdict:

- **[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)** handles skill scans and the **static** MCP source scan: one tool, 71 vulnerability patterns across 17 categories (prompt injection, data exfiltration, privilege escalation, MCP tool poisoning / least-privilege, supply chain with **live OSV.dev CVE lookup**, bundled hooks and settings), AST taint tracking, YARA signatures, hidden/nested-archive inspection, and LLM semantic analysis with risk scoring (0–100) — by default through the coding-agent CLI you already have, no API key. Also covers `curl | bash` install scripts and cargo crate sources.
- **[cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)** handles the optional **live runtime** MCP check. A static scan cannot see MCP tools that a server registers only at runtime; `scan_mcp.py --sandbox` starts the server inside a throwaway Docker container (no host filesystem access, every network destination recorded) to inspect them.
- **[Datadog GuardDog](https://github.com/DataDog/guarddog)** handles **CLI-tool package scans** (npm, PyPI, Go, cargo): malware heuristics + YARA over package source and registry metadata, via the official Docker image on Windows.
- **[OpenSSF package-analysis](https://github.com/ossf/package-analysis)** handles the **dynamic install analysis** of npm and PyPI packages: the package is installed and imported inside gVisor, and what it reads, writes, resolves, connects to and starts is judged against rules calibrated on clean packages.
- **VirusTotal + [malcontent](https://github.com/chainguard-dev/malcontent)** handle **release binaries**: hash reputation against 70+ AV vendors (an unseen hash gives NO VERDICT, never SAFE), optionally (`--deep`) a capability analysis of what the binary can actually do.

## What you get

- **Commit-pinned ZIP scanning** — repos are fetched as a ZIP snapshot of one exact commit; `git clone` never touches your machine before a verdict, and the commit that was scanned is the commit that gets installed. No scan/install gap an attacker could slip a push into.
- **Skills, MCP servers, *and* CLI tools** — an MCP server is code that must run to be fully inspected, so naive scanning would execute it. `scan_mcp.py` scans the package **source** first (fetched from the registry, nothing executed), with an optional **Docker-sandboxed** live scan — untrusted MCP code never runs unconfined on your machine. `scan_cli.py` extends the same scan-first gate to the CLI tools agents install: npm/PyPI/Go packages, cargo crates, release binaries, and `curl | bash` installers, all downloaded but **never executed** before their verdict.
- **Layered analysis** — static patterns, AST taint tracking, YARA signatures, live OSV.dev CVE lookup, and LLM-powered semantic analysis when configured.
- **No API key for the main scan** — SkillSpector's LLM layer runs by default through the coding-agent CLI you are already logged into (`claude` or `opencode`) as an isolated, tool-less subprocess, so your subscription covers it. Hosted providers (Anthropic, OpenAI, Azure OpenAI, NVIDIA, Bedrock, Ollama, any OpenAI-compatible endpoint, ...) work with a key if you prefer; the verifier pass uses the same connection. Only Cisco's optional runtime MCP scan (LiteLLM) strictly needs an API key.
- **Fail-closed workflow** — scanner errors are never silently treated as "no findings".
- **Prompt-injection aware** — content of scanned repos is treated as data, never as instructions to the reviewing agent.
- **Clear verdicts** — ✅ SAFE / ⚠ REVIEW / 🚫 DO NOT INSTALL, with a risk score and file/line for every finding.
- **Universal installer included** — after a SAFE verdict, one command installs the skill or MCP server to every agent detected on the machine. Skills are distributed by the pinned `skills` CLI (vercel-labs/skills), which maintains the directory layout of 80+ agents, so a scanned skill reaches all of them; MCP servers and a built-in fallback linker cover Claude Code, Claude Desktop, Codex, Antigravity, Gemini CLI, Hermes and OpenClaw. Restrict the targets with `--tools` — our own ids or any agent name the CLI knows (`cursor`, `windsurf`, …). Local MCP servers are installed through isolated launchers (`uvx`, `uv tool`, `npx`) so one server's dependencies do not pollute or break another.

## One scan, every agent

Skills are not a Claude-only concept: they follow the open [SKILL.md standard (agentskills.io)](https://agentskills.io), and [MCP](https://modelcontextprotocol.io) is an open protocol. The same skill or server runs in Claude Code, Codex, Gemini/Antigravity, [Hermes](https://hermes-agent.nousresearch.com), [OpenClaw](https://docs.openclaw.ai), and friends — and the scanner doesn't care which agent the code is destined for.

Many people now work across several agents in parallel, not least because of per-provider rate limits. That normally means installing — and *trusting* — the same third-party code once per agent. agent-guard collapses this into **scan once, verdict once, install everywhere**: one command links the audited commit into every detected agent, so all your agents run exactly the same reviewed code. Use `--tools` to target only specific agents.

## Supported tools (auto-detected)

| Tool | Skills | MCP servers |
|------|--------|-------------|
| Claude Code | `~/.claude/skills/` | `claude mcp add -s user` → `~/.claude.json` |
| Claude Desktop | `~/.claude/skills/` *(shared with Claude Code)* | Windows: `%APPDATA%/Claude/` · macOS: `~/Library/Application Support/Claude/` · Linux: `$XDG_CONFIG_HOME` or `~/.config/Claude/` — `claude_desktop_config.json` |
| Codex | `~/.codex/skills/` | `~/.codex/config.toml` |
| Antigravity (App + `agy` CLI) | `~/.gemini/config/skills/` | `~/.gemini/config/mcp_config.json` |
| Gemini CLI | `~/.gemini/skills/` | `~/.gemini/settings.json` (`httpUrl` for remote servers) |
| Hermes (Nous Research) | `~/.hermes/skills/` | manual — `mcp_servers:` block in Hermes `config.yaml` |
| OpenClaw | `~/.openclaw/skills/` | manual — OpenClaw's own MCP tooling |

The table lists the agents agent-guard configures itself: MCP registration, and the fallback linker for skills. Skill *distribution* normally goes through the pinned `skills` CLI, which detects and serves 80+ agents beyond this table; the paths below are then topped up only where that CLI leaves an agent's own directory empty.

Detection is automatic — only tools whose configs exist are touched. Claude Desktop reads skills from the same `~/.claude/skills/` as Claude Code, so that shared path is linked once and serves both. Antigravity and the Gemini CLI both live under `~/.gemini/` but share no file: the Antigravity App and its `agy` CLI read `~/.gemini/config/`, the Gemini CLI reads `~/.gemini/skills/` and `~/.gemini/settings.json`, so each is detected and installed separately. JSON configs are backed up (`.bak`) before every write. Hermes and OpenClaw use their own MCP config formats (YAML / CLI), so the installer prints instructions for those instead of modifying configs blindly.

### Skill distribution: the pinned `skills` CLI

Getting one scanned skill into every agent on a machine is a solved problem, and
solving it again ourselves is how a skill ends up installed into a path no agent
reads — a failure with no error message. So after the verdict, distribution is
delegated to the [`skills` CLI](https://github.com/vercel-labs/skills): it writes
one canonical copy to `~/.agents/skills/<name>`, links every agent it detects
(NTFS junction on Windows, automatic copy fallback), and maintains that agent
table upstream for 80+ agents.

Running a third-party CLI inside a security tool is gated:

| Gate | What it does |
|------|--------------|
| Version pin | `npx -y skills@<pinned version>` — a `skills` on PATH is deliberately ignored, because no pin covers it |
| Registry digests | the release's `shasum` and `integrity` must match the pinned values |
| Own scan | GuardDog scans that exact version through `scan_cli`; a BLOCK passes only when its blocking findings match `scripts/reviewed/skills-cli-<version>.json`, which names each accepted finding, its file, the matched text and the reason |
| Reduced environment | `npm_config_ignore_scripts=true` (no lifecycle script can run) and no credential variables (`GITHUB_TOKEN`, `GH_TOKEN`, API keys) are passed |
| Copy verification | every scanned file must appear byte-identical in the canonical copy |
| Top-up | paths verified here (for example `~/.codex/skills`, `~/.gemini/config/skills`) are linked from the canonical store when the CLI leaves them empty |

If any gate does not hold — unknown finding, digest mismatch, missing `npx`,
timeout, non-zero exit — delegation is skipped and the built-in linker installs
into the agents in the table above. An installation never fails because of this;
only the distribution method changes, and the output says which one ran. Set
`AGENT_GUARD_SKILLS_CLI=0` to always use the built-in linker.

Raising the pin is a reviewed step: `python scripts/verify_skills_cli.py --latest`
compares the pin with the registry, and `--update <version>` scans a candidate
and prints a reviewed-findings draft. It writes nothing on its own.

## Prerequisites

Required for the normal scan/install workflow:

- [uv](https://docs.astral.sh/uv/) — installs SkillSpector and Cisco mcp-scanner in isolated tool environments. uv also fetches the Python 3.12 runtime that SkillSpector needs.
- Python 3.10+ — runs the agent-guard wrapper scripts: `scripts/install_skill.py`, `scripts/scan_skill.py`, `scripts/scan_mcp.py`, `scripts/scan_cli.py`, and `scripts/scan_url.py`.
- For full SkillSpector LLM coverage: a logged-in coding-agent CLI on PATH (`claude` or `opencode` — auto-detected, no API key) **or** a hosted-provider key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `NVIDIA_INFERENCE_KEY`, ...). Without either, skill and static MCP source scans still run static-only but end with exit 2 (no verdict) unless `AGENT_GUARD_STATIC_ONLY=1` is set.
- A LiteLLM-compatible runtime provider for Cisco live MCP checks (API key required; Cisco has no CLI-login path): `MCP_SCANNER_LLM_API_KEY` plus `MCP_SCANNER_LLM_MODEL`. This can be OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Ollama, or another LiteLLM-supported provider.

Optional, depending on what you scan or install:

- [Docker](https://docs.docker.com/get-docker/) — needed for the dynamic install analysis that npm/PyPI scans run by default (`scan_cli.py npm|pypi`, `scan_mcp.py npm|pypi`, the package path of `scan_url.py`; without Docker they end in no verdict unless you pass `--no-dynamic`), for Docker-isolated live stdio MCP checks (`scan_mcp.py ... --sandbox`), for GuardDog package scans (`scan_cli.py npm/pypi/go`) on Windows where Docker is GuardDog's only supported install (Linux/macOS can use a native `guarddog` on PATH instead), and for the optional malcontent binary analysis (`scan_cli.py binary --deep`). Skill scans, `scan_mcp.py local|remote`, and `scan_cli.py script` do not need Docker; Cargo uses GuardDog and needs Docker on Windows. The Docker daemon must be **running** first (on Windows/macOS: start Docker Desktop); `failed to connect to the docker API` means it is not. Disk: the dynamic analysis image is about 1 GB and its package cache volume (`agent-guard-dynamic-cache`) grows to a few GB; that analysis runs a **privileged** container (`--privileged --cgroupns=host`), which gVisor needs to build its own sandbox inside it.
- `VIRUSTOTAL_API_KEY` — required for `scan_cli.py binary` (release-binary hash reputation) and optional malware-reputation checks for bundled binaries, archives, PDFs, images, and similar non-source files in MCP scans. VirusTotal's Public API is free for registered users but rate-limited (4 lookups/min); an unseen hash or an API error gives NO VERDICT (exit 2), never SAFE; see [LLM provider support](#llm-provider-support).
- Node.js/npm — optional. Needed if you install or run npm MCP servers through `npx`, install the Firecrawl CLI with npm, or explicitly configure a preinstalled Node renderer for protected marketplaces.
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
# Optional: configure the environment variables described below.
```

Prefer environment variables for provider settings and API keys. This keeps
credentials outside the project directory. See the configuration section below.

**No API keys needed if you are logged in to a coding-agent CLI.** If `claude` or `opencode` is on PATH and
logged in, the wrapper auto-detects it and runs SkillSpector's LLM layer through
that CLI — your existing subscription, in a separate tool-less process. Without
any of those, SkillSpector still runs its full static layer (71 patterns, AST
taint tracking, YARA, live OSV.dev CVE lookup), but the scan ends with exit 2
(no verdict, never SAFE) because no AI analysis ran. Set
`AGENT_GUARD_STATIC_ONLY=1` to accept a static-only result deliberately; only
the optional Cisco runtime check strictly needs an API key.

**Option B — clone and install manually:**

```bash
git clone https://github.com/elliottwaves-20/agent-guard
cd agent-guard

bash setup.sh       # Windows PowerShell: .\setup.ps1

# Optional: configure provider/runtime environment variables (see below).

# Register agent-guard itself into every detected agent (auto-detects your tools):
python scripts/install_skill.py skill .
```

### Configuration: prefer environment variables

No configuration file is required. Keys always belong in the environment; model
and provider choices can alternatively live in the personal config file
described below. Set the variables on the process that
launches the scanner, in your user's environment, or through your CI's secret
injection. Use these names (see `.env.example` for all optional settings):

| Variable | Purpose |
| --- | --- |
| `SKILLSPECTOR_PROVIDER` | Optional explicit CLI/provider choice: `claude_cli`, `opencode_cli`, `gemini_cli` (only when named), or a hosted provider. `codex_cli` and `antigravity_cli` are refused. |
| `SKILLSPECTOR_MODEL` | Optional model override; unset uses the provider/CLI default. |
| `MCP_SCANNER_LLM_API_KEY` and `MCP_SCANNER_LLM_MODEL` | Separate credentials/model for optional Cisco runtime scans. |
| `VIRUSTOTAL_API_KEY` | Hash reputation checks for binary downloads (unseen hash or API error = NO VERDICT, exit 2). |

**Windows:** open **Environment Variables → User variables** and add the
settings there. For a non-secret provider preference, PowerShell also supports:

```powershell
[Environment]::SetEnvironmentVariable('SKILLSPECTOR_PROVIDER', 'claude_cli', 'User')
$env:SKILLSPECTOR_PROVIDER = 'claude_cli'  # also apply to this PowerShell session
```

Enter API keys through the environment-variable dialog or a masked prompt;
do not type real keys into commands that will be saved in shell history.
Restart already-running terminals and agent apps after changing user variables:
they retain the environment they inherited at startup.

**macOS/Linux:** export the variables in the shell that launches the scanner;
for example `export SKILLSPECTOR_PROVIDER=claude_cli`. Obtain secrets from your
secret manager or a silent prompt instead of putting their values in command
history or a repository. CI jobs should inject them from their secret store.

Environment variables keep keys out of project files, but are not an encrypted
vault: processes running as your account may still access them. The untrusted
MCP target container does not receive the scanner's credentials.

**Optional personal config file (LLM profiles, local distribution):** one TOML
file outside the repository holds what is personal to a machine. Copy
`config.example.toml` to the first of these locations that applies:

| Location | When |
| --- | --- |
| `AGENT_GUARD_CONFIG=<path>` | explicit file (must exist) |
| `%APPDATA%\agent-guard\config.toml` | Windows |
| `$XDG_CONFIG_HOME/agent-guard/config.toml`, then `~/.config/agent-guard/config.toml` | Linux / macOS |

`[llm.use]` picks a profile per scanner — `skills` (SkillSpector), `mcp` (Cisco
runtime check), `campaign` (budgeted scans with `scripts/llm_scan.py`) — and a
profile describes only the connection: a coding-agent CLI login, any
OpenAI-compatible endpoint, or a scanner-native provider. Changing model or
provider is a config edit; `AGENT_GUARD_LLM=<profile>` (or
`AGENT_GUARD_LLM_SKILLS` / `_MCP` / `_CAMPAIGN`) switches for one run. An active
profile replaces stale `SKILLSPECTOR_*` / `MCP_SCANNER_LLM_*` settings. The file
never holds a key: a profile names the variable (`key_env`), and values that look
like credentials make the whole file invalid. Check the result with:

```bash
python scripts/llm_check.py                 # which LLM each scanner uses; no network
python scripts/llm_check.py --probe skills  # ONE request through SkillSpector's own client
python scripts/llm_check.py --probe mcp     # ONE request through the Cisco scanner's client
```

A probe spends one request of the configured provider and never runs on its own.
The optional `[distribution]` section is for machines that already run their own
store-and-link setup; see [Install after a SAFE verdict](#install-after-a-safe-verdict).
A config that exists but is invalid stops every wrapper before it scans;
`AGENT_GUARD_NO_USER_CONFIG=1` ignores the default locations. Without the file,
everything above works as described.

**Optional file fallback:** copy `.env.example` to `.env` in the trusted
installation directory, or explicitly set `AGENT_GUARD_ENV_FILE` to another
trusted file. Process variables take precedence. Working and parent directories
are not searched, so a scan target cannot configure its own scanner through an
adjacent file. The wrappers parse the file as data; do not source it as shell code.

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

A renderer runs only when the operator explicitly configures
`AGENT_GUARD_FETCH_COMMAND`. Point it at a trusted, preinstalled Firecrawl CLI
or your own Playwright renderer. For example, after separately installing and
authenticating Firecrawl:

```bash
export AGENT_GUARD_FETCH_COMMAND='firecrawl scrape --format markdown --only-main-content --wait-for 3000 {url}'
```

The command is operator configuration and can execute code. Do not populate it
from the page being scanned or use a command that downloads dependencies.
The resolver never installs renderer packages during a scan.

Without a working renderer, protected marketplace pages fail closed with no
verdict; direct GitHub/archive/raw SKILL.md/npm/PyPI URLs still work normally.

## Usage

### Scan a GitHub repo before installing

```bash
# Optional: load LLM provider config into the shell. The wrappers also auto-load
# .env from the repo/skill directory when present.
# Wrappers parse the trusted installation .env automatically.

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
# a version in the URL (pypi.org/project/x/1.2.3/, npmjs.com/package/x/v/1.2.3) is scanned exactly
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
want to inspect the listing and candidate plan without following candidates;
the exit code is then 2 (the candidates were not scanned), or 1 if the listing
text itself is blocked.
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
# Dry-run: print the scan command only (NOT EXECUTED, exit 2)
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

Scanner errors or empty output mean **no verdict** — never treat a failed scan as safe. Exit 1 with a report is a real verdict; exit 2 is never one, with or without a report (skill scans exit 0 = SAFE: score <= 50, no HIGH/CRITICAL finding, every file inspected; 1 = BLOCK: score > 50, a DO_NOT_INSTALL recommendation, any single HIGH/CRITICAL finding, or a partial inspection limited to passages the shell parser gave up on; 2 = no verdict: errors, missing AI analysis or any other incomplete inspection).

### Exit codes

A non-zero exit is usually a **verdict, not a tool failure** — important when
wiring agent-guard into scripts or CI:

| Exit code | Meaning | Action |
|-----------|---------|--------|
| `0` | SAFE verdict | Install is reasonable |
| `1` | BLOCK/REVIEW verdict — real findings, or a partial inspection limited to passages the shell parser gave up on | Read the findings (or the listed passages), decide deliberately |
| `2` | **No verdict** — scanner/LLM/config error, or anything not fully checked; fail-closed | Fix the cause and re-run; no automatic installation. Managed updates also support explicit manual review below. |

**Decide by the exit code, not the text.** Exit `2` may print as `[WARN] NO VERDICT`, `[WARN] INCONCLUSIVE` or `[BLOCK] NO VERDICT`; treat it as "do not install". Cases that give `2` instead of `0`:

- **No completed AI analysis.** A SAFE verdict needs an AI analysis that actually ran (any provider; only the report's `metadata.llm_available` counts). Without it the scan ends `static only` with exit 2, and scheduled updates (`update_skills.py`) quarantine the candidate while the old version stays active. `AGENT_GUARD_STATIC_ONLY=1` states that static checking is deliberately enough: it disables the AI analysis and accepts a dynamic stage you skipped with `--no-dynamic` (exit 0 instead of 2) for a clean static result. It does not skip the dynamic stage by itself.
- **Skipped dynamic stage.** `--no-dynamic` (`scan_url.py`, `scan_mcp.py`, `scan_cli.py`) gives at least exit 2 unless `AGENT_GUARD_STATIC_ONLY=1` is set (a BLOCK from the static stage still wins, exit 1).
- **Nothing was scanned.** `audit_installed.py` without `--execute` (NOT EXECUTED, for every listed scan), unreadable configs (also an `mcpServers` that is not an object) and entries whose source cannot be inferred: a `uvx`/`npx` entry with `--with`, an index, registry or find-links option, several different `npx -p` packages, an option the tool does not know, or an index or registry variable in `env`. With no skill or MCP server found there is nothing to scan and the exit code is 0. In `scan_url.py`: a repo with neither a skill nor a package manifest (unsupported repo layout), a skill collection with non-documentation files outside the skill folders (prompt and instruction files such as `CLAUDE.md`, `.cursorrules` or `commands/*.md`, and `marketplace.json`/`plugin.json` with anything but metadata keys, are not documentation), and marketplace candidates left out by `--max-candidates` or by `--no-scan-candidates`.
- **Incomplete hash lookup.** A missing, malformed or inconsistent hash-lookup summary, an unseen hash, a suspicious-only file, a file skipped by the file limit, or a directory in which agent-guard finds more checkable files than Cisco looked at (Cisco silently skips files under dot directories and `__pycache__`, symlinks and files whose type it cannot tell; agent-guard counts them itself, never follows symlinks, and gives exit 2 instead of SAFE).
- **Stale scanner rules.** GuardDog and malcontent run with `docker run --pull=always`; if the image cannot be pulled (offline) there is no verdict, never SAFE.

The wrapper writes SkillSpector JSON to a temporary report, so Windows console encoding issues, provider resolution, and SkillSpector's execution/coverage ledger are handled automatically.

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

**Stage 1b (default for `pypi` / `npm` — needs Docker):** the package is installed and imported inside OpenSSF package-analysis, a gVisor sandbox with nothing worth stealing, and its recorded behaviour is judged (see [Dynamic install analysis](#dynamic-install-analysis)). `--no-dynamic` skips this stage and gives exit 2 unless `AGENT_GUARD_STATIC_ONLY=1` is set.

**Stage 2 (optional — live runtime check):** start the server inside a throwaway **Docker container with no access to your filesystem**, then scan the tools and prompts it registers at runtime — the gap a static scan cannot cover (powered by cisco-ai-mcp-scanner).

The trusted Cisco analyzer runs on the host and connects over Docker stdio.
Only the target server runs in the container; scanner API keys are never
forwarded into it. The container is removed after the check, including when
the analyzer fails or times out. Package caches are private to that container
and discarded afterwards, so a malicious target cannot poison a shared cache
for a subsequent scan.

**The target's network traffic is recorded.** A small capture container
(Alpine and tcpdump, pinned by digest and version) owns the network namespace
and the target joins it, so the launcher can still download the server. Only
the PyPI and npm registries are allowed by default. Any other DNS lookup —
even one that fails — any other connection, UDP datagram or ICMP packet
blocks the verdict and is listed. A capture that does not start, drops
packets or is cut short gives no verdict. Allow more destinations for one run
with `--allow-host HOST[:PORT]` (default port 443, repeatable) or permanently
with `AGENT_GUARD_SANDBOX_ALLOW=host1,host2`; `--no-network` runs the target
with no network at all (only for commands that need no downloads). DNS traffic
counts as the sandbox's own resolver only on a private address; if the resolver
is a public address (on Linux the Docker bridge copies the host's DNS servers),
list it in `AGENT_GUARD_DNS_RESOLVERS=ip1,ip2` (UDP queries only: their names are still checked, and TCP to port 53 of that address stays a finding). Inside the
sandbox uv may not download Python builds and npm skips its update check, so
neither reaches for hosts outside the list.

```bash
python scripts/scan_mcp.py pypi mcp-server-name==1.2.3 --sandbox -- uvx mcp-server-name==1.2.3
# a server that legitimately calls its own API:
python scripts/scan_mcp.py pypi mcp-server-name==1.2.3 --sandbox --allow-host api.example.com -- uvx mcp-server-name==1.2.3
```

In `pypi` / `npm` mode, `--allow-host` applies to Stage 1b as well.

The Docker daemon must be running (start Docker Desktop on Windows/macOS). The
first sandbox run builds the scan image and pre-fetches dependencies, which can
take a few minutes; later runs reuse the image and are much faster.

Stage 1 uses SkillSpector with the same provider resolution as skill scans (your coding-agent CLI by default, or a hosted provider under `SKILLSPECTOR_*`). Stage 2 uses Cisco mcp-scanner with an `[llm.use] mcp` profile or `MCP_SCANNER_LLM_*` for LLM/behavioral analysis. If you set `VIRUSTOTAL_API_KEY`, Cisco mcp-scanner can also check bundled binaries, archives, PDFs, and similar non-source files against VirusTotal by hash. A clean Stage 1 scan does **not** prove runtime safety — reach for `--sandbox` when a server is unfamiliar. Install only after a SAFE verdict.

### Scan a CLI tool before installing

Agents increasingly install plain command-line tools instead of MCP servers — npm/PyPI/Go packages, cargo crates, GitHub release binaries, and `curl | bash` installers. `scan_cli.py` gives those installs the same scan-first workflow by routing each source to the professional scanner best suited for it (agent-guard never writes its own detection):

```bash
# npm / PyPI / Go packages -> Datadog GuardDog (heuristics + YARA + registry metadata);
# npm and PyPI then also get the dynamic install analysis (Docker; --no-dynamic skips it and gives exit 2 unless AGENT_GUARD_STATIC_ONLY=1):
python scripts/scan_cli.py npm left-pad
python scripts/scan_cli.py pypi requests==2.32.0
python scripts/scan_cli.py go github.com/user/module

# GitHub release binary -> download (never executed), SHA256, VirusTotal hash check:
python scripts/scan_cli.py binary https://github.com/user/tool/releases/download/v1.0/tool.exe
# --deep adds a malcontent capability analysis (Docker):
python scripts/scan_cli.py binary <url> --deep

# curl | bash installer -> SkillSpector static scan; the script is never executed:
python scripts/scan_cli.py script https://example.com/install.sh

# cargo crate -> GuardDog crates scan (heuristics + registry metadata) + SkillSpector static source scan:
python scripts/scan_cli.py cargo ripgrep@14.1.0
```

Exit codes follow the same contract as every other agent-guard scanner: `0` SAFE, `1` BLOCK verdict, `2` no verdict (fail closed).

Requirements per mode:

- **npm / pypi / go / cargo** use [GuardDog](https://github.com/DataDog/guarddog). It runs natively if `guarddog` is on PATH (Linux/macOS: `pipx install guarddog`); on **Windows, Docker is GuardDog's only supported install**, so the wrapper falls back to the official image `ghcr.io/datadog/guarddog` automatically (pulled fresh on every run with `--pull=always`, so rules stay current; offline means NO VERDICT — start Docker Desktop first). GuardDog's `capability-*` rules are transparency notes ("can read files / spawn processes") that fire on nearly every real library — the wrapper prints them but only lets **malware-heuristic** rules drive the BLOCK verdict; review the capability list for anything implausible for the package's purpose. Exception: `capability-process-hooks` (a setup.py install/develop hook — code that runs at `pip install` time, the classic PyPI malware vector) **does block**; this was verified against DataDog's own malicious-package dataset, where a real sample fires only that rule.
- **binary** needs `VIRUSTOTAL_API_KEY` (free tier: 4 lookups/min). `--deep` needs Docker for [malcontent](https://github.com/chainguard-dev/malcontent); its image is pulled fresh on every run (`--pull=always`), offline means NO VERDICT. VirusTotal only knows files it has seen: an unseen hash, a rate-limit/API error, a suspicious-only result or a file skipped by the file limit gives NO VERDICT (exit 2), never SAFE.
- **script** uses the SkillSpector static scan already set up by `setup.sh` / `setup.ps1`. **cargo** runs both: GuardDog's `crates` scan and a SkillSpector static scan of the crate source; the worse verdict wins.

#### Dynamic install analysis

Static scanners read an install script; they cannot see what it does. For npm
and PyPI packages agent-guard therefore also installs and imports the package
inside [OpenSSF package-analysis](https://github.com/ossf/package-analysis)
(gVisor inside a Docker container, image pinned by digest) and judges what was
recorded. The stage is **on by default** in `scan_cli.py npm|pypi`,
`scan_mcp.py npm|pypi` (Stage 1b) and the package path of `scan_url.py`, where
the install offer appears only after both stages and the pinned version is the
one analysed.

It reports:

- reads of credential stores (`~/.ssh`, `~/.aws`, `.npmrc`, `.netrc`, wallets,
  browser profiles, ...). The package manager itself reads a few of these during
  install (calibrated on clean packages); exactly those are excused, in the
  install phase only,
- writes outside the package areas (`/app`, package caches, `/tmp`) — shell
  profiles, `/etc`, `~/.ssh`, system binaries,
- DNS lookups and connections beyond the ecosystem's registry (`--allow-host`
  adds more),
- network tools (`curl`, `wget`, `nc`, ...) started by the package,
- the fake credentials the sandbox plants in the environment turning up in a
  DNS name or a command line (exfiltration).

Any of these blocks the verdict; the combined exit code is the worst of all
stages (BLOCK before NO VERDICT before SAFE). The optional `execute` phase
may end early when the package closes stdout — MCP stdio servers do — because
OpenSSF's own script then fails; what was recorded until then is judged and the
output says so in a `LIMIT:` line. A failed or missing install or import phase, a
completed phase without its `Files`, `DNS`, `Sockets` or `Commands` list, a
result for another package or version, a timeout
(`AGENT_GUARD_DYNAMIC_TIMEOUT`, default 1200 s) or missing Docker gives **no
verdict**; `--no-dynamic` skips the stage knowingly and says so, and gives exit 2 unless `AGENT_GUARD_STATIC_ONLY=1`. The first run
pulls the image and fills the cache (about 2–3 minutes); later runs of small
packages take seconds. The analysed package really reaches the network — the
sandbox holds nothing worth stealing, and what the package contacts is exactly
what this stage reports.

**Complementary runtime gates (not integrated, recommended alongside):** a scan-first verdict and an install-time gate catch different things. [Socket Firewall Free (`sfw`)](https://github.com/SocketDev/sfw-free) wraps package managers (`sfw npm install X`, `sfw pip install X`, `sfw cargo fetch`) and blocks known-malicious packages at install time using Socket's live threat feed — a second net behind any GuardDog verdict. [tirith](https://github.com/sheeki03/tirith) hooks the shell itself and intercepts pipe-to-shell, homograph URLs, and typosquats before any command runs (AGPL-3.0; daemon mode is Unix-only, PowerShell hooks on Windows).

### Install after a SAFE verdict

Install the same commit that was scanned. The local skill installer performs a
fresh scan of a staging copy, checks that its contents did not change during
scanning, and publishes that same copy before linking it. Choose an installation
name or workspace different from the source location. An explicitly reviewed
baseline can be passed to the skill installer with `--baseline /review/accepted.json`:

```bash
git clone https://github.com/user/repo-name ~/path/to/workspace/repo-name
git -C ~/path/to/workspace/repo-name -c advice.detachedHead=false checkout "$SHA"

# All detected agents at once:
python scripts/install_skill.py skill ~/path/to/workspace/repo-name

# Or only specific agents (own ids, or any agent name the skills CLI knows):
python scripts/install_skill.py skill ~/path/to/workspace/repo-name --tools claude-code hermes
python scripts/install_skill.py skill ~/path/to/workspace/repo-name --tools cursor windsurf

# Verify or raise the pinned distribution CLI:
python scripts/verify_skills_cli.py
python scripts/verify_skills_cli.py --latest
```

**Your own skill distribution (optional).** If a machine already runs its own
store-and-link setup (one skill store, links into every agent, profiles), add a
`[distribution]` section with `mode = "sync"` to the
[personal config file](#configuration-prefer-environment-variables):

```toml
[distribution]
mode = "sync"
inbox = "~/.claude/skills"                          # a directory your sync collects from
sync = ["pwsh", "-NoProfile", "-File", "/path/to/your-sync.ps1"]  # argv, no shell
# sync_timeout = 600
```

A SAFE skill is then published into `inbox` and `sync` runs once, instead of the
`skills` CLI or the built-in linker; `--tools` and `--workspace` are refused.
The sync runs without credentials in its environment, only its output lines
about the installed skill are shown. A sync that changes a scanned file, adds
a file the scan never saw, or leaves no skill at the inbox path stops the
installer, and so does a failing or timed-out sync (exit 2, no `[OK]` line;
nothing is deleted, review the copy by hand). The skill stays in the inbox, but
it is not reported as installed. Without a `sync` command the skill is only
published to the inbox. An invalid section stops the installer (exit 2).

**Keeping skills up to date (`update_skills.py`).** With three more keys in the
same section, installed skills get scanned updates:

```toml
origins = "/path/to/skills-origins.json"   # which skill comes from which GitHub repo
backup = "/path/to/replaced-versions"      # old versions are moved here, never deleted
quarantine = "/path/to/blocked-versions"   # blocked versions are kept here for review
```

```bash
python scripts/update_skills.py --import-lock ~/.agents/.skill-lock.json  # adopt skills-CLI installs
python scripts/update_skills.py --add NAME --source owner/repo            # new skill, same path
python scripts/update_skills.py --all --json report.json                   # weekly run
```

Each skill is fetched by the pinned `skills` CLI in *project mode* into a
throw-away directory, pinned to the source's current commit (`owner/repo#<sha>`)
— no agent directory and no global lock is touched. The staged files are
compared with the installed copy; only a difference is scanned, and only a
SAFE version replaces the installed one. Anything else keeps the installed
version active:

- **BLOCK:** the new version goes to `quarantine` (with its report) and the
  skill is reported as `blocked` in every run (while sibling skills from the
  same source continue to update) until you decide: `--accept NAME --reason TEXT`
  installs it after review, `--reject NAME` keeps the old one and silences that
  exact version, `--remove NAME` stops managing the skill. An accepted version
  approves the exact content hash of each of its files for later versions of
  that skill; changed or new files are judged anew, and hard evidence always
  blocks.
- **No verdict:** the candidate and any available raw report are kept in
  quarantine too. The review item records the scanner wrapper exit code,
  coverage, analyzer exceptions and LLM failure when available. Status stays
  `no-verdict`, exit 2, including later runs without another scan. After reviewing
  that exact candidate, `--accept NAME --reason TEXT` installs it with the same
  hash check and backup as a BLOCK; describe what you checked in the reason.
  This is an explicit manual decision, never a SAFE scanner verdict or a blanket
  exception for parser errors. Changed candidates and inspection gaps still
  require review. `--reject NAME` dismisses only that version (retaining its
  quarantine files), and `--remove NAME` stops managing the skill.
  Configure `quarantine` first; without it the run reports a failure and remains
  retryable rather than creating a review item with no candidate.
- **Fetch error:** reported, exit 2; no reviewable candidate was obtained.

Exit codes: 0 everything current or updated, 1 something waits for a decision,
2 something could not be checked. The `--json` report lists each skill's
status (`unchanged`, `updated`, `installed`, `blocked`, `paused`, `rejected`,
`failed`, `no-verdict`) for a scheduler or notifier to act on.

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
| **NVIDIA SkillSpector** | skill scans and static MCP source scans | `SKILLSPECTOR_PROVIDER` — default `claude_cli` / `opencode_cli` (your CLI login, no key); or any hosted provider in the table below with its credentials |
| **Cisco mcp-scanner LLM** | live MCP runtime scans (`remote` / `--sandbox`) | an `[llm.use] mcp` profile (`kind = "api"`: an OpenAI-compatible endpoint or any LiteLLM-supported provider, with its key) or `MCP_SCANNER_LLM_*` |
| **VirusTotal analyzer** | optional malware reputation for bundled binaries, archives, PDFs, and similar non-source files | `VIRUSTOTAL_API_KEY` |

**Access paths.** Every path below that can reach a model can run the skill scan and the verifier (the verifier runs through SkillSpector's own client with the scan's environment, so it shares the skill-scan connection; `python scripts/llm_check.py` shows both rows).

| Access | Type | Skill scan | Verifier | MCP runtime (Cisco) | Campaign |
|--------|------|------------|----------|---------------------|----------|
| Claude Code CLI (`claude`) | CLI login | yes (auto-detected) | yes | no | no |
| OpenCode CLI (`opencode`) | CLI login | yes (auto-detected) | yes | no | no |
| Gemini CLI (`gemini`) | CLI login | only when named explicitly | yes | no | no |
| Anthropic, OpenAI, Azure OpenAI, AWS Bedrock, Google Gemini via ADC (`gemini`), NVIDIA, Ollama, Anthropic proxy | API provider | yes (Anthropic, OpenAI, NVIDIA auto-detected by key) | yes | where LiteLLM supports the provider (Cisco needs an `[llm.use] mcp` API profile or `MCP_SCANNER_LLM_*` settings) | OpenAI protocol only |
| OpenAI-compatible endpoint (OpenRouter, Groq, Together, Mistral, DeepSeek, LM Studio, vLLM, ...) | API provider | yes (`openai_compatible`) | yes | yes (LiteLLM) | yes |
| Codex CLI (`codex`) | refused | no | no | no | no |
| Antigravity CLI (`agy`) | refused | no | no | no | no |

Notes on individual paths:

- **OpenCode** is supported at exactly version 1.18.33 (SkillSpector fails closed on any other version) and is run with a deny-all tool policy. It works with OpenCode's API providers. Logins through OpenCode's built-in auth plugins (ChatGPT Plus/Pro, GitHub Copilot) do not reach their provider under the pinned SkillSpector, which switches those plugins off ([NVIDIA/SkillSpector#809](https://github.com/NVIDIA/SkillSpector/issues/809)). The free OpenCode Zen models refuse SkillSpector's sandbox, so pick another model.
- **Gemini CLI**: Google no longer offers the Gemini CLI subscription login to private users, so it is never auto-picked and works only when you name `gemini_cli`. For the Gemini API use a key with the OpenAI-compatible endpoint, or the `gemini` provider through Google Cloud Application Default Credentials.
- **Codex CLI is refused** because its read-only sandbox still lets model-driven commands read files on the machine, which scanned content could steer ([NVIDIA/SkillSpector#737](https://github.com/NVIDIA/SkillSpector/issues/737)). **Antigravity CLI is refused** because `agy` prints nothing to a pipe, so SkillSpector cannot read its answer.
- **Campaigns** speak the OpenAI protocol only; most API providers offer a compatible endpoint.
- Non-secret provider settings (an endpoint, region, or deployment) go into the profile's `settings` table; keys only through `key_env`. URL settings must be `https` (plain `http` only for `localhost`, `127.0.0.1`, or `::1`). See `config.example.toml`.

With a [personal config file](#configuration-prefer-environment-variables), `[llm.use]` names one profile per layer instead (`skills`, `mcp`, plus `campaign` for budgeted scans) and the environment variables in this table are only read for keys; `python scripts/llm_check.py` shows what each scanner will use. Token limits for models SkillSpector does not know yet come from the profile (`context`, `max_output`), and `reasoning = true` lets the Cisco scanner treat a new model as a reasoning model that its pinned LiteLLM does not recognise yet.

**SkillSpector provider resolution** (`scripts/_skillspector.py`): `AGENT_GUARD_STATIC_ONLY=1` declares static checking deliberately enough: it disables the LLM layer, lifts the exit-2 rule for "no AI analysis ran" and accepts a dynamic stage skipped with `--no-dynamic` (it does not skip that stage by itself); static analyzers can still use configured lookups such as OSV. An active config profile decides next and ignores stale `SKILLSPECTOR_*` settings. Otherwise an explicit `SKILLSPECTOR_PROVIDER` is used and validated (a CLI provider needs its binary on PATH, a hosted one its key). With no provider named, a hosted key in the environment wins (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `NVIDIA_INFERENCE_KEY`, in that order), then the first of `claude`, `opencode` found on PATH. `SKILLSPECTOR_PROVIDER=gemini` means the Google Cloud ADC API provider, not the Gemini CLI (that one is `gemini_cli`). If nothing is usable the scan runs static-only and ends with no verdict (exit 2) unless `AGENT_GUARD_STATIC_ONLY=1` is set. With `SKILLSPECTOR_MODEL` you can pin a model (`<model-id>`); leave it empty to use the CLI's own default. A model from another vendor is ignored with a note. The wrapper also starts SkillSpector inside its own tool environment with the aggregate scan deadline raised from upstream's hard-coded 60 s to `SKILLSPECTOR_MAX_WORKFLOW_SECONDS` (default: `AGENT_GUARD_SCAN_TIMEOUT` minus 60 s), because CLI providers exhaust the 60 s budget on medium-sized skills and would otherwise end in NO VERDICT (upstream: NVIDIA/SkillSpector#460).

**Why a separate LLM process instead of letting the installing agent judge the code?** Two reasons. (1) The LLM layer is not just a summary of the static findings — SkillSpector's semantic analyzers read the raw files and look for the residual gap: prompt injection, exfiltration instructions, and obfuscated intent phrased in natural language that regex/YARA cannot encode. (2) To judge semantically, an LLM must ingest the untrusted content — and the agent that installs the skill is exactly the target a poisoned SKILL.md is written for. The scanner therefore runs the model as a separate process with no tools, no MCP servers, no settings (`claude -p --permission-mode dontAsk --strict-mcp-config --setting-sources=`), feeds the content via stdin, and forces a JSON-schema answer. The verdict is an exit code the agent receives *before* it reads anything. The CLI providers give you that isolation on your existing subscription.

SkillSpector still runs its static layer without any LLM: patterns, taint tracking, YARA, and OSV.dev CVE lookup remain active. That is useful, but it misses semantic attacks that pattern rules do not encode.

Cisco's runtime scanner is independent. Use an `[llm.use] mcp` profile (`kind = "api"`), or set `MCP_SCANNER_LLM_API_KEY`, `MCP_SCANNER_LLM_MODEL`, and optionally `MCP_SCANNER_LLM_BASE_URL` / `MCP_SCANNER_LLM_API_VERSION` for OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Ollama, or any LiteLLM-supported model. The key and model provider must match: use a Claude/Anthropic model such as `claude-haiku-4-5` with an Anthropic key, or a GPT/OpenAI model with an OpenAI key. For local LLM endpoints such as Ollama, Cisco still expects `MCP_SCANNER_LLM_API_KEY` to be set; use a harmless dummy value such as `ollama` or `test`.

VirusTotal is optional but useful for private users because it fills a different gap than source scanning: known malware in bundled binary or archive-like files. Cisco's VirusTotal analyzer sends SHA256 hashes by default, not file contents; uploads happen only if `MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=true` is explicitly set.

VirusTotal's Public API is available at no cost after creating a VirusTotal Community account. Get the key from [your personal API key page](https://www.virustotal.com/gui/my-apikey) while signed in. Public API limits are **500 requests/day** and **4 requests/minute**, and VirusTotal restricts it to non-commercial/non-business-workflow use. Premium keys are for professional/commercial use: quotas are governed by the licensed plan, and Premium exposes more threat context, advanced hunting/malware-discovery features, sample downloads, richer observable relationships, and SLA-backed data readiness. For agent-guard's default use case, the free key is enough to add lightweight hash reputation checks for bundled binaries; Premium is only relevant if you already have a professional VirusTotal workflow.

After setting `VIRUSTOTAL_API_KEY`, test the optional malware-reputation layer
through agent-guard's wrapper. It calls Cisco's VirusTotal analyzer directly and
avoids known CLI regressions in Cisco's standalone VirusTotal subcommand:

```bash
# Wrappers parse the trusted installation .env automatically.
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
| VirusTotal (`binary`, MCP non-source files) | Recognises only **known** malware hashes. An unseen hash gives NO VERDICT (exit 2), never SAFE; a known-and-clean hash can still be a targeted payload that no engine detects yet. Prefer signed releases of well-known projects. |
| malcontent (`binary --deep`) | Capability analysis, not proof. **Windows PE coverage is weaker than Linux ELF** — treat a clean `.exe` result with extra care. |
| GuardDog (`npm`/`pypi`/`go`/`cargo`) | Heuristics + YARA over known attack patterns. A clean result is not proof of harmlessness. `capability-*` findings are printed as informational and do **not** block (exception: `capability-process-hooks` — install-time code execution — blocks) — a malicious package whose only tell is an implausible remaining capability needs your judgment on that list. |
| cargo | GuardDog's crates support is new (3.2.0) and its metadata rules are thinner than for npm/PyPI; the second pass (SkillSpector) is static. `sfw cargo install <crate>` remains a good install-time net. |
| `script` scan | **Static.** A second-stage payload the installer downloads at runtime is invisible; scan those URLs separately. |
| SkillSpector static scans | Cannot see behavior that only appears at runtime (MCP: use `--sandbox`). Static-only mode (`AGENT_GUARD_STATIC_ONLY=1`) misses semantic attacks that pattern rules don't encode. |
| Live MCP sandbox scan | Contains host-filesystem access and **records** every network destination, but does not stop the traffic while it happens: the registries stay reachable, and payloads inside an allowed TLS connection are not inspected. The LLM-based analysis is itself probabilistic. |
| Dynamic install analysis (`npm`/`pypi`) | Sees only what the package does during install, import and a short execution in the sandbox; code that waits for a date, a specific host or a user action stays silent. File accesses carry no process, so a file the package manager itself reads is excused in the install phase for every process. |

Where a stage in a scan output has such a limit, the wrapper prints it inline (`LIMIT:` / `NOTE:` lines) — so the verdict and its caveat always travel together.

## Security model

1. **Scanned content is data, never instructions** — a malicious SKILL.md cannot talk the reviewing agent into a SAFE verdict.
2. **Fail closed** — scanner crash/error ⇒ no verdict, not "no findings". A low-risk report cannot override an error exit or incomplete inspection.
3. **Scan = install** — the pinned commit SHA bridges scan and installation; if the repo moves in between, re-scan.
4. **ZIP before verdict, clone after** — plain ZIP downloads execute nothing, while `git clone` has historically had RCE edge cases (e.g. CVE-2024-32002 via recursive submodules). Cloning is reserved for repos that already passed.

Scanner setup is an explicit bootstrap trust decision: `setup.sh` / `setup.ps1`
install the operator's chosen security tools and their dependencies. These
dependencies have not been approved by agent-guard before setup, and the pinned
SkillSpector source commit is not a lock of all transitive dependencies. Review
the tool sources and setup before running them. The scan-first promise applies
to the target under review after this trusted toolchain is installed.

## Why this skill triggers capability warnings

Automated skill scanners (Socket, Snyk, ClawScan, and others) flag this skill with capability warnings. That is expected, and it is worth understanding rather than hiding — a security tool should be the most transparent skill you install.

The warnings describe what the skill genuinely does:

- **It runs external binaries.** The skill drives [SkillSpector](https://github.com/NVIDIA/SkillSpector) (skills + static MCP scan) and [cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (optional live MCP runtime check) — that *is* its job. Both are official, open-source security tools installed isolated via `uv`. SkillSpector is **pinned to the exact commit behind a tagged release** (see `scripts/_pins.py`), so "scan = install" applies to the scanner itself (review and bump deliberately); the Cisco MCP scanner is pulled from PyPI at the latest version.
- **It starts Docker containers, one of them privileged.** The live MCP check runs the target in a locked-down container next to a packet-capture container (`NET_RAW` only), and the dynamic install analysis runs OpenSSF's image with `--privileged`, which gVisor needs to build its own sandbox inside it. The analysed package runs inside gVisor, not in the privileged container itself.
- **It installs across multiple agents.** The bundled installer links the audited skill into every agent you have — the "one scan, every agent" feature. Scanners read cross-platform installation as expanded reach; here it is the intended behavior, and you can limit it with `--tools`.
- **It can route data to an LLM.** SkillSpector sends scanned skill/static-source contents to the provider you configure — by default the coding-agent CLI you are logged into (so the data goes to that vendor under your own account), otherwise the hosted provider whose key you set. `AGENT_GUARD_STATIC_ONLY=1` disables that LLM layer and accepts a static-only SAFE (and a dynamic stage skipped with `--no-dynamic`); static analyzers can still use configured network lookups such as OSV. Cisco's runtime MCP scan sends runtime tool/prompt data to the provider you configure for it (`[llm.use] mcp` profile or `MCP_SCANNER_LLM_*`).

You cannot drive these flags to green without removing the tool's reason to exist. What keeps it trustworthy is everything in the [Security model](#security-model) above: scanned content is treated as data, the workflow fails closed, repos are pinned and ZIP-scanned before any clone, and the skill ships **no hidden or invisible characters** of its own.

## Reviewing self-scan findings

SkillSpector retains deterministic findings even when its LLM does not
confirm them. A raw agent-guard self-scan can therefore return BLOCK for its
configuration loading, scanner subprocesses and installer capabilities. This
is a review requirement, not evidence that the scanner failed or that the
LLM was unavailable. An `llm-unconfirmed` tag never grants permission to install.

For findings you have inspected and accepted, the single-target skill wrapper
supports an **explicit, reviewer-owned SkillSpector v2 JSON baseline**:

```bash
python scripts/scan_skill.py /path/to/pinned-source --report /review/raw.json
python scripts/scan_skill.py /path/to/pinned-source --baseline /review/accepted.json --report /review/reviewed.json
```

Only exact SHA-256 fingerprints are accepted; wildcard rules and legacy
baselines are rejected. SkillSpector binds each fingerprint to the complete
scanned file content, scanner version, location, severity and evidence. Source
or analyzer changes require renewed review. A new finding still contributes to
the normal risk score and HIGH/CRITICAL gate. A different scanner version or
incomplete LLM analysis produces NO VERDICT. Accepted findings and their reasons
remain visible in both terminal output and the saved report, including on SAFE.

The wrapper never auto-loads a target's baseline. Keep your reviewed baseline
outside the scanned source, and do not trust one merely because its author
ships it. `skillspector baseline <source> --output /review/draft.json` can
generate **candidates for review**; it accepts every current finding, so its
output must be inspected, reduced and given specific reasons before use.
Generate it with the same scanner and LLM policy as the later scan; different
LLM evidence can invalidate an otherwise unchanged fingerprint.

The native generator fingerprints only one occurrence of a finding that
repeats, while the scan matches every occurrence (still true in 2.12.0; see
NVIDIA/SkillSpector#630, #633, #656). A generated draft therefore leaves
repeated occurrences unsuppressed. Review against the saved report; never
compensate with wildcards or treat a partially matching draft as a completed
review. A baseline built with SkillSpector's own `build_baseline_dict` from the
graph's raw `findings` covers every occurrence with the same exact
fingerprints.

For a release self-scan, use a clean export of the intended release tree to
avoid scanning local credentials, caches or session notes, and run it static
(`AGENT_GUARD_STATIC_ONLY=1`): LLM evidence differs between runs and would
invalidate otherwise unchanged fingerprints. Run the raw scan (expected BLOCK
for this security tool), then the reviewed scan (expected SAFE with accepted
findings), and test that changed source and new malicious content still block.
The maintainers keep the reviewed baseline outside this repository, as
recommended above. Passing a reviewed self-scan does not give permission to
accept the same capabilities in unrelated skills.

`--report` writes only to a new file and does not overwrite source or policy.
`--baseline` and `--report` are restricted to one concrete target, not catalog
or collection scans.

## Running the tests

```bash
python scripts/run_all_tests.py          # every test group, fails on any skip
python scripts/run_all_tests.py --live   # adds the real LLM tests (spends provider quota)
```

`run_all_tests.py` runs each group with the interpreter and gates it needs
(the installed scanners, SkillSpector's own tool Python for the budget
contract) and reports `ALL GREEN, NOTHING SKIPPED` only when no test was
skipped; without `--live` it reports `INCOMPLETE` and `NOT GREEN` on purpose,
because the live tests did not run. They use the active `skills` profile of
the personal config (or `AGENT_GUARD_LLM_INTEGRATION_PROFILE`). A plain
`python -m unittest discover -s tests` runs the unit tests only; unit tests
never start Docker or a scanner.

## MCP isolation rules

Never install MCP dependencies globally. Always use isolated runners so MCP
servers cannot create dependency conflicts with each other or with your system
Python/Node installation:

| Source | Command |
|--------|---------|
| PyPI package | `uvx package-name==1.2.3` |
| PyPI (module start) | `uv run --with dep1 --with dep2 python -m module` |
| GitHub (not on PyPI) | `uv tool install --from "git+URL" name` |
| npm | `npx --silent -y package-name@1.2.3` |
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
