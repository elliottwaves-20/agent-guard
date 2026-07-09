#!/usr/bin/env python3
"""Audit already downloaded or installed skills/MCP servers.

Default mode is inventory/dry-run: list what would be scanned and how to remove
it. Use --execute to run scans. MCP runtime execution is only performed through
scan_mcp.py sandbox.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import install_skill
from scan_skill import find_skill_dirs


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def read_codex_mcp_servers(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    servers: dict[str, dict] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        m = re.fullmatch(r"\[mcp_servers\.([^\].]+)\]", stripped)
        if m:
            current = m.group(1).strip('"')
            servers[current] = {}
            continue
        if stripped.startswith("["):
            current = None
            continue
        if current and stripped.startswith("command"):
            servers[current]["command"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and stripped.startswith("url"):
            servers[current]["url"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and stripped.startswith("args"):
            servers[current]["args"] = re.findall(r'"([^"]*)"', stripped)
    return servers


def installed_skill_dirs(selected: list[str] | None = None) -> list[tuple[str, Path]]:
    dirs: list[tuple[str, Path]] = []
    present = install_skill.detect_tools(selected)
    seen: set[Path] = set()
    for tid, ok in present.items():
        skills_root = install_skill.TOOLS[tid]["skills"]
        if not ok or skills_root is None or not skills_root.exists():
            continue
        for skill_md in skills_root.glob("*/SKILL.md"):
            skill_dir = skill_md.parent.resolve()
            if skill_dir in seen:
                continue
            seen.add(skill_dir)
            dirs.append((tid, skill_dir))
    return dirs


def installed_mcp_servers(selected: list[str] | None = None) -> list[tuple[str, str, dict]]:
    present = install_skill.detect_tools(selected)
    servers: list[tuple[str, str, dict]] = []
    if present.get("claude-desktop"):
        for name, entry in (read_json(install_skill.CLAUDE_DESKTOP_CONFIG)
                            .get("mcpServers", {}) or {}).items():
            servers.append(("claude-desktop", name, entry))
    if present.get("antigravity"):
        for name, entry in (read_json(install_skill.ANTIGRAVITY_CONFIG)
                            .get("mcpServers", {}) or {}).items():
            servers.append(("antigravity", name, entry))
    if present.get("codex"):
        for name, entry in read_codex_mcp_servers(install_skill.CODEX_CONFIG).items():
            servers.append(("codex", name, entry))
    claude_json = install_skill.HOME / ".claude.json"
    if present.get("claude-code") and claude_json.exists():
        data = read_json(claude_json)
        for name, entry in (data.get("mcpServers", {}) or {}).items():
            servers.append(("claude-code", name, entry))
    return servers


def mcp_source_scan_command(entry: dict) -> list[str] | None:
    if entry.get("url"):
        return ["python", "scripts/scan_mcp.py", "remote", str(entry["url"])]
    cmd = str(entry.get("command", ""))
    args = [str(a) for a in entry.get("args", [])]
    launcher = launcher_name(cmd)
    local_cmd = local_source_scan_command(cmd, args)
    if local_cmd:
        return local_cmd
    if launcher == "uvx":
        if "--from" in args:
            idx = args.index("--from")
            if idx + 1 < len(args) and args[idx + 1].startswith("git+https://github.com/"):
                return ["python", "scripts/scan_url.py", normalize_git_url(args[idx + 1])]
        packages = [a for a in args if not a.startswith("-")]
        if packages:
            return ["python", "scripts/scan_mcp.py", "pypi", packages[-1]]
    if launcher == "npx":
        packages = [a for a in args if not a.startswith("-")]
        if packages:
            return ["python", "scripts/scan_mcp.py", "npm", packages[-1]]
    return None


def launcher_name(command: str) -> str:
    clean = command.strip().strip("'\"")
    name = Path(clean).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def local_source_scan_command(command: str, args: list[str]) -> list[str] | None:
    candidates = [command, *args]
    for value in candidates:
        clean = value.strip().strip("'\"")
        if clean.lower().endswith((".py", ".js", ".ts")):
            path = Path(clean)
            if path.exists():
                root = package_root_for_file(path)
                if root.name in {"dist", "build"} and root.parent.exists():
                    root = root.parent
                return ["python", "scripts/scan_mcp.py", "local", str(root)]
    return None


def package_root_for_file(path: Path) -> Path:
    parts = path.parts
    if "node_modules" in parts:
        idx = parts.index("node_modules")
        if idx + 1 < len(parts):
            if parts[idx + 1].startswith("@") and idx + 2 < len(parts):
                return Path(*parts[:idx + 3])
            return Path(*parts[:idx + 2])
    return path.parent


def normalize_git_url(value: str) -> str:
    url = value.removeprefix("git+")
    if "@" not in url.removeprefix("https://"):
        return url
    base, ref = url.rsplit("@", 1)
    if ref:
        return f"{base}/tree/{ref}"
    return base


def mcp_sandbox_command(entry: dict) -> list[str] | None:
    if entry.get("url"):
        return None
    cmd = str(entry.get("command", ""))
    args = [str(a) for a in entry.get("args", [])]
    if not cmd:
        return None
    return ["python", "scripts/scan_mcp.py", "sandbox", "--", cmd, *args]


def run(cmd: list[str], execute: bool) -> int:
    print("  " + " ".join(cmd))
    if not execute:
        return 0
    return subprocess.run(cmd).returncode


def removal_hint_skill(path: Path) -> str:
    return f"remove linked skill directory from each agent, then remove permanent copy if unused: {path}"


def removal_hint_mcp(tool: str, name: str) -> str:
    if tool == "claude-code":
        return f"claude mcp remove -s user {name}"
    if tool == "codex":
        return f"remove [mcp_servers.{name}] from {install_skill.CODEX_CONFIG}"
    if tool == "claude-desktop":
        return f"remove mcpServers.{name} from {install_skill.CLAUDE_DESKTOP_CONFIG}"
    if tool == "antigravity":
        return f"remove mcpServers.{name} from {install_skill.ANTIGRAVITY_CONFIG}"
    return "remove from the agent's MCP configuration"


def audit_download(path: Path, kind: str, execute: bool) -> int:
    if not path.exists():
        print(f"ERROR: path not found: {path}", file=sys.stderr)
        return 2
    if kind == "auto":
        if path.is_dir() and (path / "SKILL.md").is_file():
            kind = "skill"
        elif path.is_dir() and find_skill_dirs(path):
            kind = "skill-collection"
        else:
            kind = "mcp"
    if kind == "skill":
        rc = run(["python", "scripts/scan_skill.py", str(path)], execute)
        print(f"  install after SAFE verdict: python scripts/install_skill.py skill {path} --dry-run")
        return rc
    if kind == "skill-collection":
        rc = run(["python", "scripts/scan_skill.py", "--all", str(path)], execute)
        print("  install after SAFE verdict: install specific SAFE skill subdirectories")
        return rc
    if kind == "mcp":
        rc = run(["python", "scripts/scan_mcp.py", "local", str(path)], execute)
        print("  install after SAFE verdict: provide the MCP launch command to "
              "install_skill.py mcp; run scan_mcp.py sandbox first when unfamiliar")
        return rc
    print(f"ERROR: unknown kind: {kind}", file=sys.stderr)
    return 2


def audit_installed(kind: str, execute: bool, selected: list[str] | None) -> int:
    worst = 0
    if kind in {"all", "skills"}:
        print("\n== Installed skills ==")
        skills = installed_skill_dirs(selected)
        if not skills:
            print("  none detected")
        for tool, path in skills:
            print(f"- {path} ({tool})")
            worst = max(worst, run(["python", "scripts/scan_skill.py", str(path)], execute))
            print(f"  removal: {removal_hint_skill(path)}")
    if kind in {"all", "mcps"}:
        print("\n== Installed MCP servers ==")
        servers = installed_mcp_servers(selected)
        if not servers:
            print("  none detected")
        for tool, name, entry in servers:
            if entry.get("url"):
                print(f"- {name} ({tool}): {entry.get('url')}")
            else:
                print(f"- {name} ({tool}): {entry.get('command')} {' '.join(entry.get('args', []))}")
            src_cmd = mcp_source_scan_command(entry)
            if src_cmd:
                worst = max(worst, run(src_cmd, execute))
            else:
                print("  source scan: cannot infer package/source from config")
            sandbox_cmd = mcp_sandbox_command(entry)
            if sandbox_cmd:
                worst = max(worst, run(sandbox_cmd, execute))
            print(f"  removal: {removal_hint_mcp(tool, name)}")
    return worst


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit downloaded or already installed skills/MCPs.")
    parser.add_argument("--execute", action="store_true",
                        help="run scans; default only prints commands/removal guidance")
    parser.add_argument("--tool", dest="tools", action="append",
                        choices=list(install_skill.TOOLS), default=None,
                        help="limit to a tool; repeat for multiple tools")
    parser.add_argument("--tools", dest="tools", action="append",
                        choices=list(install_skill.TOOLS),
                        help="alias for --tool; repeat for multiple tools")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_download = sub.add_parser("download", help="scan a downloaded but not installed path")
    p_download.add_argument("path", type=Path)
    p_download.add_argument("--kind", choices=["auto", "skill", "skill-collection", "mcp"],
                            default="auto")

    p_installed = sub.add_parser("installed", help="audit installed skills/MCP configs")
    p_installed.add_argument("--kind", choices=["all", "skills", "mcps"], default="all")

    args = parser.parse_args()
    selected = args.tools or None
    if args.mode == "download":
        sys.exit(audit_download(args.path, args.kind, args.execute))
    sys.exit(audit_installed(args.kind, args.execute, selected))


if __name__ == "__main__":
    main()
