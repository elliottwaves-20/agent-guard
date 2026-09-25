#!/usr/bin/env python3
"""
Universal Skill/MCP installer.

Automatically detects which agent tools are installed on the current machine
and installs only where configs exist. No hardcoded usernames or paths.

Usage:
  # Skill (markdown-only):
  python install_skill.py skill <repo-path> [--name NAME] [--workspace DIR]

  # MCP server:
  python install_skill.py mcp --name NAME \
      --command CMD --arg ARG1 --arg ARG2 [--env KEY=VALUE ...]
  python install_skill.py mcp-remote --name NAME --url https://example.com/mcp
  python install_skill.py mcp-git --name NAME \
      --git-url git+https://github.com/user/repo@sha --package PKG [--executable EXE]

  # Limit to specific tools (default: all detected):
  python install_skill.py skill <path> --tools claude-code hermes

  # Dry run (show what would happen without writing):
  python install_skill.py skill <path> --dry-run
  python install_skill.py mcp ... --dry-run

Supported tools (auto-detected):
  - Claude Code        (~/.claude/  -- MCPs registered via `claude mcp add`)
  - Claude Desktop     (%APPDATA%/Claude/, ~/Library/Application Support/Claude/,
                        or $XDG_CONFIG_HOME|~/.config/Claude/ -- per platform)
  - Codex              (~/.codex/config.toml)
  - Antigravity        (~/.gemini/config/ -- App and `agy` CLI share this root)
  - Gemini CLI         (~/.gemini/settings.json, skills in ~/.gemini/skills)
  - Hermes             (~/.hermes/skills -- skills only; MCPs via config.yaml)
  - OpenClaw           (~/.openclaw/skills -- skills only; MCPs via its own CLI)

Skills follow the open SKILL.md standard (agentskills.io) -- one scanned skill
installs into every detected agent at once.

Skill distribution is delegated to the pinned `skills` CLI (vercel-labs/skills)
when it verifies: it maintains the layout of 80+ agents and owns the canonical
store `~/.agents/skills`. See _skills_cli.py for the gate in front of it. The
table above is what this installer configures itself -- MCP registration, and
the fallback linker when delegation is unavailable.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import _skills_cli
from _skillspector import run_skillspector
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: automatic pyproject inference is optional.
    tomllib = None

# ── Base paths (no hardcoded usernames) ──────────────────────────────────────

HOME    = Path.home()
APPDATA = Path(os.environ.get("APPDATA", HOME / "AppData" / "Roaming"))


def claude_desktop_config_path(platform: str = sys.platform) -> Path:
    """Claude Desktop config location per platform."""
    if platform == "win32":
        return APPDATA / "Claude" / "claude_desktop_config.json"
    if platform == "darwin":
        return (HOME / "Library" / "Application Support" / "Claude"
                / "claude_desktop_config.json")
    return (Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config"))
            / "Claude" / "claude_desktop_config.json")


# ── Config paths ──────────────────────────────────────────────────────────────

CLAUDE_CODE_DIR    = HOME / ".claude"
CLAUDE_CODE_SKILLS = CLAUDE_CODE_DIR / "skills"

CLAUDE_DESKTOP_CONFIG = claude_desktop_config_path()

CODEX_DIR    = HOME / ".codex"
CODEX_CONFIG = CODEX_DIR / "config.toml"
CODEX_SKILLS = CODEX_DIR / "skills"

# Antigravity: the desktop App and the `agy` CLI share one global root. Both
# read skills from ~/.gemini/config/skills/<name>/SKILL.md and MCP servers from
# ~/.gemini/config/mcp_config.json (verified in the agy binary's own docs).
ANTIGRAVITY_DIR    = HOME / ".gemini" / "config"
ANTIGRAVITY_CONFIG = ANTIGRAVITY_DIR / "mcp_config.json"
ANTIGRAVITY_SKILLS = ANTIGRAVITY_DIR / "skills"   # official global skills dir
ANTIGRAVITY_CLI_DIR = HOME / ".gemini" / "antigravity-cli"

# Gemini CLI is a separate product with separate paths: user skills live in
# ~/.gemini/skills (alias ~/.agents/skills) and MCP servers in the settings
# file, not in the Antigravity config directory. Installing into Antigravity's
# path leaves a Gemini CLI user with a skill that is never loaded.
GEMINI_CLI_DIR    = HOME / ".gemini"
GEMINI_CLI_CONFIG = GEMINI_CLI_DIR / "settings.json"
GEMINI_CLI_SKILLS = GEMINI_CLI_DIR / "skills"

HERMES_DIR    = HOME / ".hermes"
HERMES_SKILLS = HERMES_DIR / "skills"

OPENCLAW_DIR    = HOME / ".openclaw"
OPENCLAW_SKILLS = OPENCLAW_DIR / "skills"

# Never copy these into the permanent skill location
COPY_IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", "__pycache__", "*.pyc", ".env", ".venv"
)

# ── Tool registry ──────────────────────────────────────────────────────────────
# Skills follow the open SKILL.md standard (agentskills.io), so the same skill
# directory works for every agent below. Claude Desktop reads skills from the
# same ~/.claude/skills as Claude Code, so it shares that path (the installer
# de-duplicates shared paths and links each one once). "skills" is None only for
# agents that genuinely have no skills directory.

TOOLS = {
    "claude-code":    {"label": "Claude Code",       "detect": [CLAUDE_CODE_DIR],       "skills": CLAUDE_CODE_SKILLS},
    "claude-desktop": {"label": "Claude Desktop",    "detect": [CLAUDE_DESKTOP_CONFIG], "skills": CLAUDE_CODE_SKILLS},
    "codex":          {"label": "Codex",             "detect": [CODEX_CONFIG],          "skills": CODEX_SKILLS},
    "antigravity":    {"label": "Antigravity",       "detect": [ANTIGRAVITY_CONFIG, ANTIGRAVITY_SKILLS, ANTIGRAVITY_CLI_DIR],
                       "binaries": ["agy"],          "skills": ANTIGRAVITY_SKILLS},
    "gemini-cli":     {"label": "Gemini CLI",        "detect": [GEMINI_CLI_CONFIG, GEMINI_CLI_SKILLS],
                       "binaries": ["gemini"],       "skills": GEMINI_CLI_SKILLS},
    "hermes":         {"label": "Hermes",            "detect": [HERMES_DIR],            "skills": HERMES_SKILLS},
    "openclaw":       {"label": "OpenClaw",          "detect": [OPENCLAW_DIR],          "skills": OPENCLAW_SKILLS},
}


def tool_present(tid: str) -> bool:
    """An agent counts as installed when one of its own paths exists or its
    CLI is on PATH. Antigravity and the Gemini CLI both live under ~/.gemini
    but share no file, so each is detected only by paths it alone writes."""
    spec = TOOLS[tid]
    if any(path.exists() for path in spec["detect"]):
        return True
    return any(shutil.which(binary) is not None for binary in spec.get("binaries", ()))


def detect_tools(selected: list = None) -> dict:
    """Return {tool_id: present} for the selected tools (default: all).

    Only ids this installer configures itself are considered; names meant for
    the skills CLI are filtered out by split_targets() before they get here."""
    ids = list(TOOLS) if selected is None else [t for t in selected if t in TOOLS]
    return {tid: tool_present(tid) for tid in ids}


def split_targets(selected: list = None) -> tuple:
    """Separate our own tool ids from names only the skills CLI knows.

    `--tools cursor windsurf` is valid: the delegated CLI carries 80+ agents,
    and restricting the user to the handful we configure ourselves would throw
    that coverage away. Returns (own ids, names for the CLI)."""
    if selected is None:
        return None, None
    own = [t for t in selected if t in TOOLS]
    extra = [t for t in selected if t not in TOOLS]
    return own, own + extra


def present_labels(present: dict) -> list:
    return [TOOLS[tid]["label"] for tid, ok in present.items() if ok]


def workspace_default() -> Path:
    """Find the best default workspace for permanent clones.

    AGENT_GUARD_WORKSPACE wins when set. Otherwise the usual places are
    probed, including a Documents folder under OneDrive in any locale."""
    explicit = os.environ.get("AGENT_GUARD_WORKSPACE", "").strip()
    if explicit:
        p = Path(explicit).expanduser()
        return p
    candidates = sorted((HOME / "OneDrive").glob("*/Github")) if (HOME / "OneDrive").is_dir() else []
    candidates += [
        HOME / "Documents" / "Github",
        HOME / "Github",
        HOME / "repos",
    ]
    for p in candidates:
        if p.is_dir():
            return p
    # Select only; install_skill creates directories only during a real copy.
    fallback = HOME / "Github"
    return fallback


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str, dry: bool = False):
    prefix = "[DRY] " if dry else ""
    print(f"{prefix}{msg}", flush=True)


def make_link(target: Path, link: Path, dry: bool):
    """Create a directory symlink; fall back to an NTFS junction on Windows
    (symlinks require Developer Mode or admin rights there)."""
    if link.exists() or link.is_symlink():
        if link.resolve() != target.resolve():
            sys.exit(f"ERROR: existing skill link targets different content: {link}")
        log(f"  skip (exists): {link}", dry)
        return
    log(f"  link: {link} -> {target}", dry)
    if dry:
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name == "nt":
            with tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / "junction.ps1"
                script.write_text(
                    "param([string]$LinkPath, [string]$TargetPath)\n"
                    "New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath "
                    "-ErrorAction Stop | Out-Null\n", encoding="utf-8")
                r = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                     str(script), str(link), str(target)],
                    capture_output=True, text=True,
                )
            if r.returncode == 0:
                log("  (NTFS junction created -- symlink permission not available)")
                return
        sys.exit(
            f"ERROR: could not link {link} -> {target}\n"
            "  On Windows, enable Developer Mode (Settings > System > For developers)\n"
            "  or run this script once from an elevated prompt."
        )


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: {path} is not valid JSON ({e}). Fix it manually -- nothing was modified.")


def write_json(path: Path, data: dict, dry: bool):
    """Write JSON atomically, keeping a .bak of the previous version."""
    log(f"  write: {path}", dry)
    if dry:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(path.name + ".bak")
        fd, backup_tmp = tempfile.mkstemp(prefix=".guard-backup-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(path.read_bytes())
            os.chmod(backup_tmp, stat.S_IMODE(path.stat().st_mode))
            os.replace(backup_tmp, backup)
        finally:
            if os.path.exists(backup_tmp):
                os.unlink(backup_tmp)
        log(f"  backup: {backup}")
    fd, tmp = tempfile.mkstemp(prefix=".guard-config-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        if path.exists():
            os.chmod(tmp, stat.S_IMODE(path.stat().st_mode))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def toml_str(value: str) -> str:
    """Escape a value as a TOML basic string (JSON string escaping is a
    compatible subset)."""
    return json.dumps(str(value))


def toml_key(key: str) -> str:
    """Bare key if possible, quoted key otherwise."""
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)


def add_to_json_config(config_path: Path, name: str, entry: dict,
                       dry: bool, include_disabled: bool = False):
    """Insert MCP entry into a claude_desktop_config.json-style file."""
    data = read_json(config_path)
    servers = data.setdefault("mcpServers", {})
    if name in servers:
        log(f"  skip (already present): {name} in {config_path.name} -- remove the entry manually to re-add", dry)
        return
    payload = dict(entry)
    if include_disabled:
        payload["disabled"] = False
    servers[name] = payload
    write_json(config_path, data, dry)
    log(f"  added '{name}' to {config_path.name}", dry)


def gemini_cli_entry(entry: dict) -> dict:
    """Translate an MCP entry into Gemini CLI's settings.json dialect.

    Remote servers are registered through `httpUrl` (streamable HTTP), the same
    transport `claude mcp add --transport http` uses. Gemini CLI's `url` key
    means SSE, so reusing it would configure the wrong transport."""
    payload = dict(entry)
    url = payload.pop("url", None)
    if url:
        payload["httpUrl"] = url
    return payload


def add_to_gemini_cli_settings(name: str, entry: dict, dry: bool):
    """Insert MCP entry into ~/.gemini/settings.json (Gemini CLI user scope)."""
    add_to_json_config(GEMINI_CLI_CONFIG, name, gemini_cli_entry(entry), dry)


def add_to_codex_toml(name: str, entry: dict, dry: bool):
    """Append MCP block to ~/.codex/config.toml."""
    lines = CODEX_CONFIG.read_text(encoding="utf-8").splitlines()
    section = f"[mcp_servers.{toml_key(name)}]"
    if any(line.strip() == section for line in lines):
        log(f"  skip (already present): {name} in config.toml -- edit the file manually to update", dry)
        return

    block = [f"\n{section}"]
    if entry.get("url"):
        block.append(f"url = {toml_str(entry['url'])}")
    else:
        block.append(f"command = {toml_str(entry['command'])}")
    if entry.get("args"):
        args_str = ", ".join(toml_str(a) for a in entry["args"])
        block.append(f"args = [{args_str}]")
    block.append("enabled = true")
    if entry.get("env"):
        block.append(f"\n[mcp_servers.{toml_key(name)}.env]")
        for k, v in entry["env"].items():
            block.append(f"{toml_key(k)} = {toml_str(v)}")

    log(f"  appending '{name}' to config.toml", dry)
    if not dry:
        with open(CODEX_CONFIG, "a", encoding="utf-8") as f:
            f.write("\n".join(block) + "\n")


def add_to_claude_code(name: str, entry: dict, dry: bool):
    """Register the MCP with Claude Code via `claude mcp add` (user scope).

    Claude Code reads MCP servers from ~/.claude.json (managed by the CLI),
    not from ~/.claude/settings.json -- writing settings.json has no effect.
    """
    if entry.get("env"):
        # The CLI accepts env values only in argv. Write the documented user
        # configuration instead so credentials never enter process arguments.
        add_to_json_config(HOME / ".claude.json", name, entry, dry)
        return
    claude = shutil.which("claude")
    if entry.get("url"):
        manual = f"claude mcp add -s user --transport http {name} {entry['url']}"
    else:
        manual = f"claude mcp add -s user {name} -- {entry['command']} {' '.join(entry.get('args', []))}"

    if claude is None:
        log("  Claude Code: 'claude' CLI not found on PATH -- register manually:")
        log(f"    {manual}")
        return

    cmd = [claude, "mcp", "add", "-s", "user"]
    if entry.get("url"):
        cmd += ["--transport", "http", name, entry["url"]]
    else:
        cmd += [name, "--", entry["command"], *entry.get("args", [])]

    log(f"  register '{name}' via Claude Code (environment values omitted)", dry)
    if dry:
        return
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        log(f"  added '{name}' to Claude Code (user scope)")
    elif "already exists" in out.lower():
        log(f"  skip (already present): {name} in Claude Code")
    else:
        log(f"  WARNING: claude mcp add failed: {out.strip()}")


def normalize_git_source(url: str) -> str:
    if not re.search(r"@[0-9a-fA-F]{40}(?:#subdirectory=[A-Za-z0-9_./-]+)?$", url):
        sys.exit("ERROR: Git installs require the full 40-character scanned commit SHA; branches and tags are not pins.")
    if "#subdirectory=" in url:
        subdir = url.split("#subdirectory=", 1)[1]
        if subdir.startswith("/") or any(part in ("", ".", "..") for part in subdir.split("/")):
            sys.exit("ERROR: Git subdirectory must stay inside the scanned repository.")
    if url.startswith("git+"):
        return url
    return f"git+{url}"


def uv_tool_dir() -> Path:
    uv = shutil.which("uv")
    if uv:
        r = subprocess.run([uv, "tool", "dir"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    if os.name == "nt":
        return APPDATA / "uv" / "tools"
    return HOME / ".local" / "share" / "uv" / "tools"


def tool_scripts_dir(package: str) -> Path:
    base = uv_tool_dir() / package
    return base / "Scripts" if os.name == "nt" else base / "bin"


def executable_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" and not name.lower().endswith(".exe") else name


def infer_python_project(path: Path) -> tuple[str | None, str | None]:
    pyproject = path / "pyproject.toml"
    if tomllib is None or not pyproject.is_file():
        return None, None
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return None, None
    project = data.get("project") or {}
    name = project.get("name")
    scripts = project.get("scripts") or {}
    script = next(iter(scripts), None)
    return name, script


def install_mcp_git(name: str, git_url: str, package: str, dry: bool,
                    selected: list = None, executable: str | None = None,
                    module: str | None = None):
    """Install a Git-backed Python MCP using uv's isolated tool environment,
    then register the resulting local executable/interpreter with agents."""
    git_source = normalize_git_source(git_url)
    cmd = ["uv", "tool", "install", "--from", git_source, package]
    print(f"\n-- Git MCP '{name}' --")
    log(f"  run: {' '.join(cmd)}", dry)
    if not dry:
        uv = shutil.which("uv")
        if uv is None:
            sys.exit("ERROR: uv not found on PATH. Install uv before installing Git-backed MCPs.")
        r = subprocess.run([uv, "tool", "install", "--from", git_source, package])
        if r.returncode != 0:
            sys.exit(f"ERROR: uv tool install failed for {git_source}")

    scripts = tool_scripts_dir(package)
    if module:
        python_name = "python.exe" if os.name == "nt" else "python"
        entry = {"command": str(scripts / python_name), "args": ["-m", module]}
    else:
        exe = executable_name(executable or package)
        entry = {"command": str(scripts / exe), "args": []}
        if not dry and not Path(entry["command"]).exists():
            candidates = sorted(p.name for p in scripts.glob("*")) if scripts.exists() else []
            sys.exit(
                "ERROR: installed uv tool executable not found: "
                f"{entry['command']}\n"
                "Pass --executable or --module. Candidates: "
                f"{', '.join(candidates) or 'none'}"
            )
    install_mcp(name, entry, dry=dry, selected=selected)


# ── Subcommands ───────────────────────────────────────────────────────────────

def skill_tree_digest(root: Path) -> dict[str, str]:
    """Hash every staged file and reject indirect filesystem entries."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or path.resolve() != path.absolute():
            sys.exit("ERROR: indirect filesystem entry in staged skill")
        key = path.relative_to(root).as_posix()
        result[key] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "directory"
    return result


def top_up_verified_paths(source: Path, name: str, present: dict, dry: bool):
    """Link the paths we verified ourselves but the skills CLI leaves empty.

    Two cases. Agents whose `skillsDir` is `.agents/skills` count as
    "universal" upstream: the CLI writes only the canonical copy and skips
    their own directory, so nothing appears in e.g. ~/.codex/skills. And
    Antigravity is installed to ~/.gemini/antigravity*/skills, while the path
    this machine's Antigravity actually reads is ~/.gemini/config/skills
    (three occurrences in the App's language server; the `agy` binary
    documents the same global path).

    Both are silent failures -- the user sees a successful installation and the
    agent never loads the skill. A skill reachable through two paths is
    harmless by comparison, so anything still missing is linked here."""
    canonical = _skills_cli.CANONICAL_SKILLS_DIR
    seen = set()
    for tid, ok in present.items():
        skills_dir = TOOLS[tid]["skills"]
        if not ok or skills_dir is None or str(skills_dir) in seen:
            continue
        seen.add(str(skills_dir))
        if skills_dir == canonical:
            continue
        link = skills_dir / name
        if link.exists() or link.is_symlink():
            log(f"  skills CLI covered: {link}", dry)
            continue
        make_link(source, link, dry)


def verify_distributed_copy(scanned: Path, canonical: Path):
    """Every scanned file must reach the canonical store byte for byte.

    The skills CLI copies the tree itself, so the verdict only covers what is
    actually installed if the copy matches. Extra files (the CLI's own
    bookkeeping) are reported, not treated as tampering."""
    if not canonical.is_dir():
        sys.exit(f"ERROR: skills CLI reported success but {canonical} does not exist; nothing verified.")
    expected = skill_tree_digest(scanned)
    actual = skill_tree_digest(canonical)
    for key, digest in expected.items():
        if actual.get(key) != digest:
            sys.exit(
                "ERROR: distributed copy does not match the scanned skill "
                f"({key} differs in {canonical}). Remove it and re-run."
            )
    extra = sorted(set(actual) - set(expected))
    if extra:
        log(f"  note: canonical copy has {len(extra)} extra entry/entries "
            f"(first: {extra[0]})")
    log(f"  verified: canonical copy matches the scanned skill ({canonical})")


def install_skill(repo_path: Path, name: str, workspace: Path, dry: bool,
                  selected: list = None, *, baseline: Path | None = None):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) or name.endswith((".", " ")):
        sys.exit("ERROR: skill name must be a single safe directory name")
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        sys.exit(f"ERROR: {repo_path} is not a directory")
    if not (repo_path / "SKILL.md").is_file() and not (repo_path / "skill.md").is_file():
        sys.exit(
            f"ERROR: {repo_path} is not an installable skill directory "
            "(missing SKILL.md). For collections, scan with scan_skill.py --all "
            "and install a specific skill subdirectory."
        )

    own_targets, cli_targets = split_targets(selected)
    present = detect_tools(own_targets)
    permanent = (workspace / name).resolve()
    if permanent.parent != workspace.resolve():
        sys.exit("ERROR: installation target escapes the selected workspace")
    if permanent != repo_path and permanent.exists():
        sys.exit("ERROR: destination already exists; scan that directory explicitly before reusing it. Nothing was linked.")
    for parent, dirs, files in os.walk(repo_path, followlinks=False):
        ignored = COPY_IGNORE(parent, dirs + files)
        dirs[:] = [item for item in dirs if item not in ignored]
        for item in dirs + [item for item in files if item not in ignored]:
            path = Path(parent) / item
            if path.is_symlink() or path.resolve() != path.absolute():
                sys.exit(f"ERROR: skill contains an indirect filesystem entry; review a materialized copy: {path}")

    print(f"\n-- Skill '{name}' --")
    if cli_targets is None and _skills_cli.enabled():
        print("   Target tools: every agent the skills CLI detects "
              f"(built-in fallback: {present_labels(present) or 'none detected'})")
    else:
        print(f"   Target tools: {present_labels(present) or 'none detected'}")
    if dry:
        log(f"  stage, scan and publish {repo_path} -> {permanent}", dry)
    else:
        # Never link the live input directory. Publish the scanned staging tree
        # by rename, without re-reading the caller-controlled source after scanning.
        if permanent == repo_path:
            sys.exit("ERROR: choose a different installation name or workspace; live source directories cannot be linked directly.")
        workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".guard-stage-", dir=workspace) as staging:
            candidate = Path(staging) / name
            shutil.copytree(repo_path, candidate, symlinks=False, ignore=COPY_IGNORE)
            before = skill_tree_digest(candidate)
            scan_args = {"baseline": baseline} if baseline is not None else {}
            if run_skillspector(candidate, **scan_args) != 0:
                sys.exit("ERROR: staged skill did not receive a SAFE verdict; nothing was installed.")
            if skill_tree_digest(candidate) != before:
                sys.exit("ERROR: staged skill changed during scanning; nothing was installed.")
            if permanent.exists():
                sys.exit("ERROR: installation destination appeared during scanning; nothing was replaced.")
            candidate.rename(permanent)

    # Distribution is delegated to the `skills` CLI when it is usable: it owns
    # the canonical store, the per-agent links, and the platform quirks we
    # would otherwise have to verify per agent. The built-in linker below stays
    # as the fallback for machines without npx (or with delegation disabled).
    delegated, _agents = _skills_cli.distribute(
        permanent, dry, selected=cli_targets, present=present)
    if delegated:
        canonical = _skills_cli.CANONICAL_SKILLS_DIR / name
        if not dry:
            verify_distributed_copy(permanent, canonical)
        top_up_verified_paths(canonical if (dry or canonical.is_dir()) else permanent,
                              name, present, dry)
    else:
        # One link per UNIQUE skills directory. Claude Code and Claude Desktop
        # both read ~/.claude/skills, so that shared path is linked once and
        # serves both.
        seen = set()
        for tid, ok in present.items():
            skills_dir = TOOLS[tid]["skills"]
            if not ok or skills_dir is None or str(skills_dir) in seen:
                continue
            seen.add(str(skills_dir))
            make_link(permanent, skills_dir / name, dry)

    if dry:
        print(f"\n[DRY] Skill '{name}' NOT installed (dry run); the steps above show what would happen.")
    else:
        print(f"\n[OK] Skill '{name}' installed.")
    print(f"     Update later: git -C {permanent} fetch -- then RE-SCAN before checking out")


def install_mcp(name: str, entry: dict, dry: bool, selected: list = None):
    present = detect_tools(selected)

    print(f"\n-- MCP '{name}' --")
    print(f"   Target tools: {present_labels(present) or 'none detected'}")
    if entry.get("url"):
        print(f"   URL: {entry['url']}")
    else:
        print(f"   Command: {entry['command']} {' '.join(entry.get('args', []))}")
    if entry.get("env"):
        print("   Note: env values are stored in plaintext in the tool configs.")

    if present.get("claude-code"):
        add_to_claude_code(name, entry, dry)
    if present.get("claude-desktop"):
        add_to_json_config(CLAUDE_DESKTOP_CONFIG, name, entry, dry)
    if present.get("codex"):
        add_to_codex_toml(name, entry, dry)
    if present.get("antigravity"):
        add_to_json_config(ANTIGRAVITY_CONFIG, name, entry, dry, include_disabled=True)
    if present.get("gemini-cli"):
        add_to_gemini_cli_settings(name, entry, dry)

    # Hermes and OpenClaw manage MCP servers through their own config formats
    # (YAML / CLI tooling) -- this installer does not modify those. Point the
    # user at the right place instead of writing blind.
    if present.get("hermes"):
        log("  Hermes: not auto-configured. Add the server under the "
            "'mcp_servers:' block of your Hermes config.yaml.")
    if present.get("openclaw"):
        log("  OpenClaw: not auto-configured. Register the server with "
            "OpenClaw's own MCP tooling (see docs.openclaw.ai).")

    if dry:
        print(f"\n[DRY] MCP '{name}' NOT installed (dry run); the steps above show what would happen.")
    else:
        print(f"\n[OK] MCP '{name}' processed for all target tools.")
        print("     Restart affected apps to activate.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Universal Skill/MCP installer -- detects installed tools automatically"
    )
    parser.add_argument(
        "--workspace", type=Path, default=None,
        help="Directory for permanent skill storage (default: auto-detect)"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    tool_choices = list(TOOLS)

    # skill
    p_skill = sub.add_parser("skill", help="Install a markdown skill globally")
    p_skill.add_argument("repo_path", type=Path, help="Path to scanned + approved skill repo")
    p_skill.add_argument("--baseline", type=Path, help="Explicit reviewer-owned exact-fingerprint baseline")
    p_skill.add_argument("--name", help="Override name (default: directory name)")
    p_skill.add_argument("--tools", nargs="*", default=None, metavar="TOOL",
                         help=f"Limit installation to specific agents (default: every "
                              f"agent the skills CLI detects). Own ids: "
                              f"{', '.join(tool_choices)}; any other name is passed "
                              f"to the skills CLI as an agent name (e.g. cursor, windsurf).")
    p_skill.add_argument("--dry-run", action="store_true")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Install an MCP server to all detected tools")
    p_mcp.add_argument("--name", required=True, help="Server name in configs")
    p_mcp.add_argument("--command", required=True,
                       help="Launcher: 'uvx', 'uv', 'npx', or full path")
    p_mcp.add_argument("--args", nargs=argparse.REMAINDER, default=[], metavar="ARG",
                       help="Arguments for the command. Put this last; use '--args -- ...' "
                            "when the MCP command itself has option-style arguments.")
    p_mcp.add_argument("--arg", action="append", default=[], metavar="ARG",
                       help="Single command argument; repeat for option-style args, "
                            "for example --arg=--from --arg=git+https://...")
    p_mcp.add_argument("--env", nargs="*", default=[], metavar="KEY=VALUE",
                       help="Environment variables")
    p_mcp.add_argument("--tools", nargs="*", choices=tool_choices, default=None,
                       metavar="TOOL",
                       help=f"Limit installation to specific tools "
                            f"(default: all detected). Choices: {', '.join(tool_choices)}")
    p_mcp.add_argument("--dry-run", action="store_true")

    # remote MCP
    p_remote = sub.add_parser("mcp-remote", help="Install a remote HTTP/SSE MCP server")
    p_remote.add_argument("--name", required=True, help="Server name in configs")
    p_remote.add_argument("--url", required=True, help="Remote MCP URL")
    p_remote.add_argument("--env", nargs="*", default=[], metavar="KEY=VALUE",
                          help="Environment variables for clients that support them")
    p_remote.add_argument("--tools", nargs="*", choices=tool_choices, default=None,
                          metavar="TOOL",
                          help=f"Limit installation to specific tools "
                               f"(default: all detected). Choices: {', '.join(tool_choices)}")
    p_remote.add_argument("--dry-run", action="store_true")

    # Git-backed Python MCP
    p_git = sub.add_parser("mcp-git", help="Install a Git-backed Python MCP through uv tool")
    p_git.add_argument("--name", required=True, help="Server name in configs")
    p_git.add_argument("--git-url", required=True, help="Git URL pinned with the full scanned @commit-SHA")
    p_git.add_argument("--package", required=True,
                       help="Python package name passed to uv tool install")
    p_git.add_argument("--executable",
                       help="Executable created by uv tool install (default: package name)")
    p_git.add_argument("--module",
                       help="Use the uv tool Python interpreter with -m MODULE instead of an executable")
    p_git.add_argument("--tools", nargs="*", choices=tool_choices, default=None,
                       metavar="TOOL",
                       help=f"Limit installation to specific tools "
                            f"(default: all detected). Choices: {', '.join(tool_choices)}")
    p_git.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    workspace = args.workspace or workspace_default()

    if args.mode == "skill":
        name = args.name or args.repo_path.resolve().name
        install_skill(args.repo_path, name, workspace, args.dry_run,
                      selected=args.tools, baseline=args.baseline)

    elif args.mode == "mcp":
        installer_flags = {
            "--dry-run",
            "--tools",
            "--tool",
            "--workspace",
        }
        for token in args.args or []:
            if token in installer_flags or any(
                token.startswith(flag + "=") for flag in installer_flags
            ):
                sys.exit(
                    "ERROR: installer option appears after --args and would be "
                    "treated as an MCP server argument. Move installer options "
                    "before --args, or use repeated --arg=VALUE entries instead."
                )

        env = {}
        for kv in (args.env or []):
            k, sep, v = kv.partition("=")
            if not sep or not k.strip():
                sys.exit(f"ERROR: --env expects KEY=VALUE, got: {kv!r}")
            env[k.strip()] = v.strip()

        mcp_args = list(args.arg or [])
        if args.args:
            mcp_args.extend(args.args[1:] if args.args[:1] == ["--"] else args.args)
        entry = {"command": args.command, "args": mcp_args}
        if env:
            entry["env"] = env

        install_mcp(args.name, entry, args.dry_run, selected=args.tools)

    elif args.mode == "mcp-remote":
        env = {}
        for kv in (args.env or []):
            k, sep, v = kv.partition("=")
            if not sep or not k.strip():
                sys.exit(f"ERROR: --env expects KEY=VALUE, got: {kv!r}")
            env[k.strip()] = v.strip()
        entry = {"url": args.url}
        if env:
            entry["env"] = env
        install_mcp(args.name, entry, args.dry_run, selected=args.tools)

    elif args.mode == "mcp-git":
        if args.executable and args.module:
            sys.exit("ERROR: choose either --executable or --module, not both")
        install_mcp_git(args.name, args.git_url, args.package, args.dry_run,
                        selected=args.tools, executable=args.executable,
                        module=args.module)


if __name__ == "__main__":
    main()
