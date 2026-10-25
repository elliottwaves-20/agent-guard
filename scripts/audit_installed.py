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
from _skillspector import combine_verdicts
from scan_skill import find_skill_dirs


class ConfigReadError(Exception):
    """An existing agent config could not be read; its servers are unknown."""


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ConfigReadError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigReadError(f"cannot read {path}: top level is not an object")
    return data


def read_codex_mcp_servers(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    servers: dict[str, dict] = {}
    current: str | None = None
    env_of: str | None = None   # server whose [mcp_servers.NAME.env] table we are in
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigReadError(f"cannot read {path}: {exc}") from exc
    for line in text.splitlines():
        stripped = line.strip()
        m = re.fullmatch(r"\[mcp_servers\.([^\].]+)\]", stripped)
        if m:
            current = m.group(1).strip('"')
            env_of = None
            servers[current] = {}
            continue
        m = re.fullmatch(r"\[mcp_servers\.([^\].]+)\.env\]", stripped)
        if m:
            current = None
            env_of = m.group(1).strip('"')
            servers.setdefault(env_of, {}).setdefault("env", {})
            continue
        if stripped.startswith("["):
            current = None
            env_of = None
            continue
        if env_of and "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip().strip('"')
            servers[env_of]["env"][key] = ""   # values are never kept, only the names
            continue
        if current and stripped.startswith("command"):
            servers[current]["command"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and stripped.startswith("url"):
            servers[current]["url"] = stripped.split("=", 1)[1].strip().strip('"')
        if current and stripped.startswith("args"):
            servers[current]["args"] = re.findall(r'"([^"]*)"', stripped)
        if current and re.match(r"env\s*=", stripped):
            names = re.findall(r'([A-Za-z0-9_@:./"-]+)\s*=', stripped.split("=", 1)[1])
            servers[current].setdefault("env", {}).update(
                {n.strip('"'): "" for n in names})
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


def mcp_servers_in(data: dict, path: Path) -> dict[str, dict]:
    """The mcpServers table of a JSON config; a malformed one is unknown, not empty."""
    servers = data.get("mcpServers")
    if servers is None:
        return {}
    if not isinstance(servers, dict):
        raise ConfigReadError(f"cannot read {path}: mcpServers is not an object")
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            raise ConfigReadError(f"cannot read {path}: mcpServers.{name} is not an object")
        if not isinstance(entry.get("args", []), list):
            raise ConfigReadError(f"cannot read {path}: mcpServers.{name}.args is not a list")
        if not isinstance(entry.get("env", {}), dict):
            raise ConfigReadError(f"cannot read {path}: mcpServers.{name}.env is not an object")
    return servers


def installed_mcp_servers(selected: list[str] | None = None) -> list[tuple[str, str, dict]]:
    present = install_skill.detect_tools(selected)
    servers: list[tuple[str, str, dict]] = []
    json_configs = [
        ("claude-desktop", install_skill.CLAUDE_DESKTOP_CONFIG),
        ("antigravity", install_skill.ANTIGRAVITY_CONFIG),
        ("gemini-cli", install_skill.GEMINI_CLI_CONFIG),
    ]
    for tid, config in json_configs:
        if present.get(tid):
            for name, entry in mcp_servers_in(read_json(config), config).items():
                servers.append((tid, name, entry))
    if present.get("codex"):
        for name, entry in read_codex_mcp_servers(install_skill.CODEX_CONFIG).items():
            servers.append(("codex", name, entry))
    claude_json = install_skill.HOME / ".claude.json"
    if present.get("claude-code") and claude_json.exists():
        for name, entry in mcp_servers_in(read_json(claude_json), claude_json).items():
            servers.append(("claude-code", name, entry))
    return servers


def mcp_source_scan_command(entry: dict) -> list[str] | None:
    """Scan command for the source an MCP entry runs, or None if it cannot be told.

    None means "cannot verify what runs": the caller must turn it into NO VERDICT.
    """
    # Gemini CLI writes streamable-HTTP servers as "httpUrl" and SSE as "url".
    remote = entry.get("url") or entry.get("httpUrl")
    if remote:
        return ["python", "scripts/scan_mcp.py", "remote", str(remote)]
    cmd = str(entry.get("command", ""))
    args = [str(a) for a in entry.get("args", [])]
    launcher = launcher_name(cmd)
    if launcher in LAUNCHERS:
        # Options and environment come first: anything that can change which
        # package, index or registry is used makes the entry unverifiable,
        # whatever source it appears to name.
        if env_changes_source(launcher, entry.get("env")):
            return None
        package = parse_launch_args(launcher, args)
        if package is None:
            return None
        local_cmd = local_source_scan_command(cmd, args)
        if local_cmd:
            return local_cmd
        if not package:
            return None
        if package.startswith("git+"):
            if launcher == "uvx" and package.startswith("git+https://github.com/"):
                return ["python", "scripts/scan_url.py", normalize_git_url(package)]
            return None   # only a GitHub source is scannable from the entry alone
        return ["python", "scripts/scan_mcp.py", LAUNCHERS[launcher], package]
    return local_source_scan_command(cmd, args)


# Launcher name -> ecosystem handed to scan_mcp.py.
LAUNCHERS = {"uvx": "pypi", "npx": "npm"}

# Option tables per launcher. Names come from `uvx --help` (uv 0.9.x) and
# `npm exec --help` (npm 12); an option in no table is not guessed at, because
# its arity is unknown and the wrong argument could be scanned as the package.
# PACKAGE: the value names the package to run. VALUE: takes a value that does
# not change the source. FLAG: takes no value. UNSCANNABLE: changes or adds a
# source we cannot scan from the entry alone.
UVX_PACKAGE_OPTIONS = {"--from"}
UVX_VALUE_OPTIONS = {
    "-p", "--python", "--python-platform", "--torch-backend", "--index-strategy",
    "--keyring-provider", "-P", "--upgrade-package", "--upgrade-group", "--resolution",
    "--prerelease", "--prerelease-package", "--fork-strategy", "--exclude-newer",
    "--exclude-newer-package", "--no-sources-package", "--reinstall-package",
    "--link-mode", "-C", "--config-setting", "--config-settings-package",
    "--no-build-isolation-package", "--no-build-package", "--no-binary-package",
    "--cache-dir", "--refresh-package", "--color", "--allow-insecure-host",
}
UVX_FLAG_OPTIONS = {
    "--isolated", "--no-env-file", "--lfs", "-V", "--version", "-U", "--upgrade",
    "--no-sources", "--reinstall", "--compile-bytecode", "--no-build-isolation",
    "--no-build", "--no-binary", "--require-build-hashes", "--no-require-build-hashes",
    "-n", "--no-cache", "--refresh", "--managed-python", "--no-managed-python",
    "--no-python-downloads", "-q", "--quiet", "-v", "--verbose", "--system-certs",
    "--offline", "--no-progress", "--no-config", "-h", "--help",
}
UVX_UNSCANNABLE_OPTIONS = {
    "-w", "--with", "--with-editable", "--with-requirements", "--index",
    "--default-index", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--no-index", "-c", "--constraints", "-b", "--build-constraints", "--overrides",
    "--env-file", "--config-file", "--project", "--directory",
}
NPX_PACKAGE_OPTIONS = {"-p", "--package"}
NPX_VALUE_OPTIONS = {"--loglevel", "--cache", "--fetch-timeout", "--fetch-retries",
                     "--allow-scripts"}
NPX_FLAG_OPTIONS = {
    "-y", "--yes", "--no", "--no-install", "--prefer-online", "--prefer-offline",
    "--offline", "--no-offline", "--silent", "-q", "--quiet", "--ignore-scripts",
    "--no-audit", "--no-fund", "--no-progress", "--strict-allow-scripts",
    "--dangerously-allow-all-scripts", "--include-workspace-root",
}
NPX_UNSCANNABLE_OPTIONS = {"--registry", "--userconfig", "--globalconfig", "-c", "--call",
                           "-w", "--workspace", "--workspaces", "--prefix"}
LAUNCH_OPTIONS = {
    "uvx": (UVX_PACKAGE_OPTIONS, UVX_VALUE_OPTIONS, UVX_FLAG_OPTIONS, UVX_UNSCANNABLE_OPTIONS),
    "npx": (NPX_PACKAGE_OPTIONS, NPX_VALUE_OPTIONS, NPX_FLAG_OPTIONS, NPX_UNSCANNABLE_OPTIONS),
}

# Environment variables that point uvx at another index.
UVX_SOURCE_ENV = {"UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
                  "UV_FIND_LINKS", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"}


def env_changes_source(launcher: str, env: object) -> bool:
    if not env:
        return False
    if not isinstance(env, dict):
        return True   # cannot be read, so cannot be ruled out
    for name in env:
        upper = str(name).upper()
        lower = str(name).lower()
        if launcher == "uvx" and upper in UVX_SOURCE_ENV:
            return True
        if launcher == "npx" and lower.startswith("npm_config_") and (
                "registry" in lower
                or lower in {"npm_config_userconfig", "npm_config_globalconfig"}):
            return True
    return False


def parse_launch_args(launcher: str, args: list[str]) -> str | None:
    """Return the package to scan ("" if none is named), or None if the arguments
    cannot be read with certainty.

    Parsing stops at the first positional argument: everything after it belongs
    to the launched command, not to the launcher.
    """
    package_opts, value_opts, flag_opts, unscannable = LAUNCH_OPTIONS[launcher]
    packages: list[str] = []
    positional = ""
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            positional = args[i] if i < len(args) else ""
            break
        if not arg.startswith("-") or arg == "-":
            positional = arg
            break
        name, has_value, value = arg.partition("=")
        if name in unscannable:
            return None
        if name in package_opts or name in value_opts:
            if not has_value:
                if i >= len(args):
                    return None   # value missing
                value = args[i]
                i += 1
            if name in package_opts:
                packages.append(value)
        elif name not in flag_opts:
            return None   # unknown option: arity unknown, so the package is unknown
    if len(set(packages)) > 1:
        return None   # only one package would be scanned
    return packages[0] if packages else positional


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
        print("  NOT EXECUTED -- rerun with --execute for a verdict")
        return 2
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
    worst = 0  # SAFE until a stage says otherwise; merged with combine_verdicts
    if kind in {"all", "skills"}:
        print("\n== Installed skills ==")
        skills = installed_skill_dirs(selected)
        if not skills:
            print("  none detected")
        for tool, path in skills:
            print(f"- {path} ({tool})")
            worst = combine_verdicts(
                worst, run(["python", "scripts/scan_skill.py", str(path)], execute))
            print(f"  removal: {removal_hint_skill(path)}")
    if kind in {"all", "mcps"}:
        print("\n== Installed MCP servers ==")
        try:
            servers = installed_mcp_servers(selected)
        except ConfigReadError as exc:
            print(f"ERROR: {exc}; MCP servers not audited (NO VERDICT)", file=sys.stderr)
            return combine_verdicts(worst, 2)
        if not servers:
            print("  none detected")
        for tool, name, entry in servers:
            if entry.get("url"):
                print(f"- {name} ({tool}): {entry.get('url')}")
            else:
                print(f"- {name} ({tool}): {entry.get('command')} {' '.join(entry.get('args', []))}")
            src_cmd = mcp_source_scan_command(entry)
            if src_cmd:
                worst = combine_verdicts(worst, run(src_cmd, execute))
            else:
                print("  source scan: cannot infer package/source from config")
                worst = combine_verdicts(worst, 2)
            sandbox_cmd = mcp_sandbox_command(entry)
            if sandbox_cmd:
                worst = combine_verdicts(worst, run(sandbox_cmd, execute))
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
    import _console

    _console.utf8_stdio()
    main()
