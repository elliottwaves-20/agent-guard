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
      --command CMD --args ARG1 ARG2 [--env KEY=VALUE ...]

  # Limit to specific tools (default: all detected):
  python install_skill.py skill <path> --tools claude-code hermes

  # Dry run (show what would happen without writing):
  python install_skill.py skill <path> --dry-run
  python install_skill.py mcp ... --dry-run

Supported tools (auto-detected):
  - Claude Code        (~/.claude/  -- MCPs registered via `claude mcp add`)
  - Claude Desktop     (%APPDATA%/Claude/claude_desktop_config.json)
  - Codex              (~/.codex/config.toml)
  - Antigravity/Gemini (~/.gemini/config/mcp_config.json)
  - Hermes             (~/.hermes/skills -- skills only; MCPs via config.yaml)
  - OpenClaw           (~/.openclaw/skills -- skills only; MCPs via its own CLI)

Skills follow the open SKILL.md standard (agentskills.io) -- one scanned skill
installs into every detected agent at once.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ── Base paths (no hardcoded usernames) ──────────────────────────────────────

HOME    = Path.home()
APPDATA = Path(os.environ.get("APPDATA", HOME / "AppData" / "Roaming"))

# ── Config paths ──────────────────────────────────────────────────────────────

CLAUDE_CODE_DIR    = HOME / ".claude"
CLAUDE_CODE_SKILLS = CLAUDE_CODE_DIR / "skills"

CLAUDE_DESKTOP_CONFIG = APPDATA / "Claude" / "claude_desktop_config.json"

CODEX_DIR    = HOME / ".codex"
CODEX_CONFIG = CODEX_DIR / "config.toml"
CODEX_SKILLS = CODEX_DIR / "skills"

ANTIGRAVITY_DIR    = HOME / ".gemini" / "config"
ANTIGRAVITY_CONFIG = ANTIGRAVITY_DIR / "mcp_config.json"
ANTIGRAVITY_SKILLS = ANTIGRAVITY_DIR / "skills"   # official global skills dir

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
    "claude-code":    {"label": "Claude Code",          "detect": CLAUDE_CODE_DIR,       "skills": CLAUDE_CODE_SKILLS},
    "claude-desktop": {"label": "Claude Desktop",       "detect": CLAUDE_DESKTOP_CONFIG, "skills": CLAUDE_CODE_SKILLS},
    "codex":          {"label": "Codex",                "detect": CODEX_CONFIG,          "skills": CODEX_SKILLS},
    "antigravity":    {"label": "Antigravity / Gemini", "detect": ANTIGRAVITY_CONFIG,    "skills": ANTIGRAVITY_SKILLS},
    "hermes":         {"label": "Hermes",               "detect": HERMES_DIR,            "skills": HERMES_SKILLS},
    "openclaw":       {"label": "OpenClaw",             "detect": OPENCLAW_DIR,          "skills": OPENCLAW_SKILLS},
}


def detect_tools(selected: list = None) -> dict:
    """Return {tool_id: present} for the selected tools (default: all)."""
    ids = selected or list(TOOLS)
    return {tid: TOOLS[tid]["detect"].exists() for tid in ids}


def present_labels(present: dict) -> list:
    return [TOOLS[tid]["label"] for tid, ok in present.items() if ok]


def workspace_default() -> Path:
    """Find the best default workspace for permanent clones."""
    candidates = [
        HOME / "OneDrive" / "Dokumente" / "Github",
        HOME / "OneDrive" / "Documents" / "Github",
        HOME / "Documents" / "Github",
        HOME / "Github",
        HOME / "repos",
    ]
    for p in candidates:
        if p.exists():
            return p
    # Fallback: create ~/Github
    fallback = HOME / "Github"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str, dry: bool = False):
    prefix = "[DRY] " if dry else ""
    print(f"{prefix}{msg}", flush=True)


def make_link(target: Path, link: Path, dry: bool):
    """Create a directory symlink; fall back to an NTFS junction on Windows
    (symlinks require Developer Mode or admin rights there)."""
    if link.exists() or link.is_symlink():
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
            r = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
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
        shutil.copy2(path, backup)
        log(f"  backup: {backup}")
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


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


def add_to_codex_toml(name: str, entry: dict, dry: bool):
    """Append MCP block to ~/.codex/config.toml."""
    lines = CODEX_CONFIG.read_text(encoding="utf-8").splitlines()
    section = f"[mcp_servers.{toml_key(name)}]"
    if any(line.strip() == section for line in lines):
        log(f"  skip (already present): {name} in config.toml -- edit the file manually to update", dry)
        return

    block = [f"\n{section}"]
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
    claude = shutil.which("claude")
    if claude is None:
        log("  Claude Code: 'claude' CLI not found on PATH -- register manually:")
        log(f"    claude mcp add -s user {name} -- {entry['command']} {' '.join(entry.get('args', []))}")
        return

    cmd = [claude, "mcp", "add", "-s", "user"]
    for k, v in (entry.get("env") or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [name, "--", entry["command"], *entry.get("args", [])]

    log(f"  run: {' '.join(cmd)}", dry)
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


# ── Subcommands ───────────────────────────────────────────────────────────────

def install_skill(repo_path: Path, name: str, workspace: Path, dry: bool,
                  selected: list = None):
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        sys.exit(f"ERROR: {repo_path} is not a directory")

    present = detect_tools(selected)
    permanent = (workspace / name).resolve()

    print(f"\n-- Skill '{name}' --")
    print(f"   Target tools: {present_labels(present) or 'none detected'}")

    # Copy to permanent location (skip if the repo already lives there)
    if permanent == repo_path or permanent.exists():
        log(f"  permanent dir: {permanent}")
    else:
        log(f"  copy {repo_path} -> {permanent}", dry)
        if not dry:
            shutil.copytree(repo_path, permanent, symlinks=True, ignore=COPY_IGNORE)

    # One link per UNIQUE skills directory. Claude Code and Claude Desktop both
    # read ~/.claude/skills, so that shared path is linked once and serves both.
    seen = set()
    for tid, ok in present.items():
        skills_dir = TOOLS[tid]["skills"]
        if not ok or skills_dir is None or str(skills_dir) in seen:
            continue
        seen.add(str(skills_dir))
        make_link(permanent, skills_dir / name, dry)

    print(f"\n[OK] Skill '{name}' installed.")
    print(f"     Update later: git -C {permanent} fetch -- then RE-SCAN before checking out")


def install_mcp(name: str, entry: dict, dry: bool, selected: list = None):
    present = detect_tools(selected)

    print(f"\n-- MCP '{name}' --")
    print(f"   Target tools: {present_labels(present) or 'none detected'}")
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

    # Hermes and OpenClaw manage MCP servers through their own config formats
    # (YAML / CLI tooling) -- this installer does not modify those. Point the
    # user at the right place instead of writing blind.
    if present.get("hermes"):
        log("  Hermes: not auto-configured. Add the server under the "
            "'mcp_servers:' block of your Hermes config.yaml.")
    if present.get("openclaw"):
        log("  OpenClaw: not auto-configured. Register the server with "
            "OpenClaw's own MCP tooling (see docs.openclaw.ai).")

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
    p_skill.add_argument("--name", help="Override name (default: directory name)")
    p_skill.add_argument("--tools", nargs="*", choices=tool_choices, default=None,
                         metavar="TOOL",
                         help=f"Limit installation to specific tools "
                              f"(default: all detected). Choices: {', '.join(tool_choices)}")
    p_skill.add_argument("--dry-run", action="store_true")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Install an MCP server to all detected tools")
    p_mcp.add_argument("--name", required=True, help="Server name in configs")
    p_mcp.add_argument("--command", required=True,
                       help="Launcher: 'uvx', 'uv', 'npx', or full path")
    p_mcp.add_argument("--args", nargs="*", default=[], metavar="ARG",
                       help="Arguments for the command")
    p_mcp.add_argument("--env", nargs="*", default=[], metavar="KEY=VALUE",
                       help="Environment variables")
    p_mcp.add_argument("--tools", nargs="*", choices=tool_choices, default=None,
                       metavar="TOOL",
                       help=f"Limit installation to specific tools "
                            f"(default: all detected). Choices: {', '.join(tool_choices)}")
    p_mcp.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    workspace = args.workspace or workspace_default()

    if args.mode == "skill":
        name = args.name or args.repo_path.resolve().name
        install_skill(args.repo_path, name, workspace, args.dry_run,
                      selected=args.tools)

    elif args.mode == "mcp":
        env = {}
        for kv in (args.env or []):
            k, sep, v = kv.partition("=")
            if not sep or not k.strip():
                sys.exit(f"ERROR: --env expects KEY=VALUE, got: {kv!r}")
            env[k.strip()] = v.strip()

        entry = {"command": args.command, "args": args.args}
        if env:
            entry["env"] = env

        install_mcp(args.name, entry, args.dry_run, selected=args.tools)


if __name__ == "__main__":
    main()
