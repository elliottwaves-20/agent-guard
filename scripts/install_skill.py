#!/usr/bin/env python3
"""
Universal Skill/MCP installer.

Automatically detects which agent tools are installed on the current machine
and installs only where configs exist. No hardcoded usernames or paths.

Usage:
  # Skill (markdown-only):
  python install_skill.py skill <repo-path> [--name NAME] [--workspace DIR]

  # MCP server:
  python install_skill.py mcp <repo-path> --name NAME \
      --command CMD --args ARG1 ARG2 [--env KEY=VALUE ...] \
      [--workspace DIR]

  # Dry run (show what would happen without writing):
  python install_skill.py skill <path> --dry-run
  python install_skill.py mcp ... --dry-run

Supported tools (auto-detected):
  - Claude Code        (~/.claude/)
  - Claude Desktop     (%APPDATA%/Claude/claude_desktop_config.json)
  - Codex              (~/.codex/config.toml)
  - Antigravity/Gemini (~/.gemini/config/mcp_config.json)
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

# ── Base paths (no hardcoded usernames) ──────────────────────────────────────

HOME    = Path.home()
APPDATA = Path(os.environ.get("APPDATA", HOME / "AppData" / "Roaming"))

# ── Config paths ──────────────────────────────────────────────────────────────

CLAUDE_CODE_DIR      = HOME / ".claude"
CLAUDE_CODE_SETTINGS = CLAUDE_CODE_DIR / "settings.json"
CLAUDE_CODE_SKILLS   = CLAUDE_CODE_DIR / "skills"

CLAUDE_DESKTOP_CONFIG = APPDATA / "Claude" / "claude_desktop_config.json"

CODEX_DIR    = HOME / ".codex"
CODEX_CONFIG = CODEX_DIR / "config.toml"
CODEX_SKILLS = CODEX_DIR / "skills"

ANTIGRAVITY_CONFIG = HOME / ".gemini" / "config" / "mcp_config.json"

# ── Tool detection ─────────────────────────────────────────────────────────────

def detect_tools() -> dict[str, bool]:
    """Return which agent tools are present on this machine."""
    return {
        "Claude Code":    CLAUDE_CODE_DIR.exists(),
        "Claude Desktop": CLAUDE_DESKTOP_CONFIG.exists(),
        "Codex":          CODEX_CONFIG.exists(),
        "Antigravity":    ANTIGRAVITY_CONFIG.exists(),
    }


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


def make_symlink(target: Path, link: Path, dry: bool):
    if link.exists() or link.is_symlink():
        log(f"  skip (exists): {link}", dry)
        return
    log(f"  symlink: {link} -> {target}", dry)
    if not dry:
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)


def read_json(path: Path) -> dict:
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def write_json(path: Path, data: dict, dry: bool):
    log(f"  write: {path}", dry)
    if not dry:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


def add_to_json_config(config_path: Path, name: str, entry: dict,
                       dry: bool, include_disabled: bool = False):
    """Insert MCP entry into a claude_desktop_config.json-style file."""
    data = read_json(config_path)
    servers = data.setdefault("mcpServers", {})
    if name in servers:
        log(f"  skip (already present): {name} in {config_path.name}", dry)
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
    section = f"[mcp_servers.{name}]"
    if any(line.strip() == section for line in lines):
        log(f"  skip (already present): {name} in config.toml", dry)
        return

    block = [f"\n{section}"]
    block.append(f'command = "{entry["command"]}"')
    if entry.get("args"):
        args_str = ", ".join(f'"{a}"' for a in entry["args"])
        block.append(f"args = [{args_str}]")
    block.append("enabled = true")
    if entry.get("env"):
        block.append(f"\n[mcp_servers.{name}.env]")
        for k, v in entry["env"].items():
            block.append(f'{k} = "{v}"')

    log(f"  appending '{name}' to config.toml", dry)
    if not dry:
        with open(CODEX_CONFIG, "a", encoding="utf-8") as f:
            f.write("\n".join(block) + "\n")


def add_to_claude_code(name: str, entry: dict, dry: bool):
    """Add MCP entry to ~/.claude/settings.json."""
    data = read_json(CLAUDE_CODE_SETTINGS)
    servers = data.setdefault("mcpServers", {})
    if name in servers:
        log(f"  skip (already present): {name} in settings.json", dry)
        return
    servers[name] = entry
    write_json(CLAUDE_CODE_SETTINGS, data, dry)
    log(f"  added '{name}' to Claude Code settings.json", dry)


# ── Subcommands ───────────────────────────────────────────────────────────────

def install_skill(repo_path: Path, name: str, workspace: Path, dry: bool):
    tools = detect_tools()
    permanent = workspace / name

    print(f"\n-- Skill '{name}' --")
    print(f"   Detected tools: {[t for t, ok in tools.items() if ok]}")

    # Copy to permanent location
    if permanent.exists():
        log(f"  permanent dir exists: {permanent}")
    else:
        log(f"  copy {repo_path} -> {permanent}", dry)
        if not dry:
            shutil.copytree(repo_path, permanent, symlinks=True)

    # Symlinks — only for tools that are present
    if tools["Claude Code"]:
        make_symlink(permanent, CLAUDE_CODE_SKILLS / name, dry)
    if tools["Codex"]:
        make_symlink(permanent, CODEX_SKILLS / name, dry)

    # Claude Desktop and Antigravity don't use a skills directory
    # (they share ~/.claude/ or use the plugin system)

    print(f"\n[OK] Skill '{name}' installed.")
    print(f"     Update later: cd {permanent} && git pull")


def install_mcp(name: str, entry: dict, workspace: Path, dry: bool):
    tools = detect_tools()

    print(f"\n-- MCP '{name}' --")
    print(f"   Detected tools: {[t for t, ok in tools.items() if ok]}")
    print(f"   Command: {entry['command']} {' '.join(entry.get('args', []))}")

    if tools["Claude Code"]:
        add_to_claude_code(name, entry, dry)
    if tools["Claude Desktop"]:
        add_to_json_config(CLAUDE_DESKTOP_CONFIG, name, entry, dry)
    if tools["Codex"]:
        add_to_codex_toml(name, entry, dry)
    if tools["Antigravity"]:
        add_to_json_config(ANTIGRAVITY_CONFIG, name, entry, dry, include_disabled=True)

    print(f"\n[OK] MCP '{name}' added to all detected tools.")
    print("     Restart affected apps to activate.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Universal Skill/MCP installer — detects installed tools automatically"
    )
    parser.add_argument(
        "--workspace", type=Path, default=None,
        help="Directory for permanent skill/MCP storage (default: auto-detect)"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # skill
    p_skill = sub.add_parser("skill", help="Install a markdown skill globally")
    p_skill.add_argument("repo_path", type=Path, help="Path to scanned + approved skill repo")
    p_skill.add_argument("--name", help="Override name (default: directory name)")
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
    p_mcp.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    workspace = args.workspace or workspace_default()

    if args.mode == "skill":
        name = args.name or args.repo_path.name
        install_skill(args.repo_path, name, workspace, args.dry_run)

    elif args.mode == "mcp":
        env = {}
        for kv in (args.env or []):
            k, _, v = kv.partition("=")
            env[k.strip()] = v.strip()

        entry: dict = {"command": args.command, "args": args.args}
        if env:
            entry["env"] = env

        install_mcp(args.name, entry, workspace, args.dry_run)


if __name__ == "__main__":
    main()
