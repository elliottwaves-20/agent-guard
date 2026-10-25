#!/usr/bin/env python3
"""Scan an arbitrary URL that may point to a skill, MCP, archive, or catalog."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import sys
import tempfile
import urllib.parse
from pathlib import Path

from _skillspector import combine_verdicts, die, skipped_dynamic_verdict as _skipped_dynamic_verdict
from _url_resolver import FetchError, ResolvedSource, resolve_url
from install_skill import (
    TOOLS,
    infer_python_project,
    install_mcp,
    install_mcp_git,
    install_skill,
    workspace_default,
)
import _dynamic
from scan_mcp import fetch_npm, fetch_pypi, run_remote, run_sandbox
from scan_mcp import run_skillspector as run_mcp_static
from scan_skill import find_skill_dirs, scan_catalog
from scan_skill import run_skillspector as run_skill_static


def has_skill_manifest(path: Path) -> bool:
    return path.is_dir() and any(
        p.is_file() and p.name.lower() == "skill.md" for p in path.iterdir()
    )


DOC_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".png", ".jpg", ".jpeg", ".gif",
                ".svg", ".webp"}
DOC_NAME_PREFIXES = ("license", "copying", "notice")
DOC_NAMES = {".gitignore", ".gitattributes", ".gitmodules", ".editorconfig"}
# Extensionless project files that only carry prose.
DOC_BARE_NAMES = {"changelog", "changes", "history", "authors", "contributors"}
DOC_DIRS = {".git", ".github"}
# Text suffixes under which an agent can still read instructions.
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".rst"}
# Agents load these as instructions or prompts, so they are code for our
# purposes even though they look like prose. .svg stays documentation: agent-guard
# installs only skill folders and agents do not execute SVG.
PROMPT_FILE_NAMES = {"claude.md", "agents.md", "gemini.md", ".cursorrules",
                     ".windsurfrules", "copilot-instructions.md"}
PROMPT_DIRS = {"commands", "agents", "prompts", "rules", "hooks", "output-styles",
               ".claude", ".cursor", ".codex", ".gemini", ".windsurf"}
# Parts below .github that are agent input (the rest of .github stays docs).
GITHUB_PROMPT_DIRS = {"prompts", "instructions", "agents"}

# Plugin/marketplace manifests count as documentation only when they hold pure
# metadata: keys such as hooks, mcpServers, lspServers, commands, agents or
# outputStyles can make an agent run commands.
MANIFEST_TOP_KEYS = {"$schema", "name", "owner", "metadata", "description", "version",
                     "author", "homepage", "repository", "license", "keywords",
                     "plugins"}
MANIFEST_PLUGIN_KEYS = {"name", "source", "description", "version", "author", "homepage",
                        "repository", "license", "keywords", "category", "tags",
                        "strict", "skills"}
_STR, _STRS, _DICT, _STR_OR_DICT, _BOOL = "str", "strs", "dict", "str_or_dict", "bool"
MANIFEST_TYPES = {
    "$schema": _STR, "name": _STR, "owner": _DICT, "metadata": _DICT,
    "description": _STR, "version": _STR, "author": _STR_OR_DICT, "homepage": _STR,
    "repository": _STR_OR_DICT, "license": _STR, "keywords": _STRS, "source": _STR_OR_DICT,
    "category": _STR, "tags": _STRS, "strict": _BOOL, "skills": "str_or_strs",
}


def _type_ok(value, kind: str) -> bool:
    if kind == _STR:
        return isinstance(value, str)
    if kind == _STRS:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    if kind == _DICT:
        return isinstance(value, dict)
    if kind == _STR_OR_DICT:
        return isinstance(value, (str, dict))
    if kind == _BOOL:
        return isinstance(value, bool)
    if kind == "str_or_strs":
        return isinstance(value, str) or _type_ok(value, _STRS)
    return False


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def is_pure_manifest_metadata(path: Path) -> bool:
    """True only for valid JSON that holds nothing but allowed metadata keys."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict) or not set(data) <= MANIFEST_TOP_KEYS:
        return False
    for key, value in data.items():
        if key == "plugins":
            if not isinstance(value, list):
                return False
            for entry in value:
                if not isinstance(entry, dict) or not set(entry) <= MANIFEST_PLUGIN_KEYS:
                    return False
                if not all(_type_ok(v, MANIFEST_TYPES[k]) for k, v in entry.items()):
                    return False
        elif not _type_ok(value, MANIFEST_TYPES[key]):
            return False
    return True


def is_documentation_file(rel: Path, root: Path | None = None) -> bool:
    """True when `rel` is prose or metadata that no agent loads as instructions.

    `root` is the source tree; without it manifest contents cannot be checked
    and manifests are never documentation."""
    name = rel.name.lower()
    suffix = rel.suffix.lower()
    parts = [p.lower() for p in rel.parts]
    dirs = parts[:-1]
    in_github_prompts = (parts[:1] == [".github"] and len(parts) > 2
                         and parts[1] in GITHUB_PROMPT_DIRS)
    if name in PROMPT_FILE_NAMES:
        return False
    if suffix in TEXT_SUFFIXES and (in_github_prompts
                                    or any(d in PROMPT_DIRS for d in dirs)):
        return False
    if parts[:1] == [".claude-plugin"] and name in {"marketplace.json", "plugin.json"}:
        if root is None:
            return False
        if name == "plugin.json" or len(parts) == 2:
            return is_pure_manifest_metadata(root / rel)
        return False
    if parts and parts[0] in DOC_DIRS:
        # .github/prompts etc. are agent input, not docs
        return not in_github_prompts
    if name.startswith(DOC_NAME_PREFIXES):
        # license.sh is code, not a license text
        return suffix in {"", *TEXT_SUFFIXES}
    return suffix in DOC_SUFFIXES or name in DOC_NAMES or name in DOC_BARE_NAMES


def files_outside_skills(root: Path, skills: list) -> list[Path]:
    """Non-documentation files that no skill scan covers (relative to root)."""
    skill_dirs = [Path(s).resolve() for s in skills]
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() and not p.is_symlink():
            continue
        resolved = p.resolve()
        if any(sd == resolved.parent or sd in resolved.parents for sd in skill_dirs):
            continue
        rel = p.relative_to(root)
        if is_documentation_file(rel, root):
            continue
        out.append(rel)
    return out


def classify_source(source: ResolvedSource) -> str:
    if source.kind == "catalog":
        return "catalog"
    if source.kind in {"pypi", "npm"}:
        return "mcp-package"
    path = source.source_path
    if path is None:
        return source.kind
    if path.is_file():
        if path.suffix.lower() in {".md", ".markdown"}:
            return "markdown"
        return "file"
    if has_skill_manifest(path):
        return "skill"
    if find_skill_dirs(path):
        return "skill-collection"
    # MCP source is less standardized. pyproject/package manifests are a useful
    # static-source signal, but runtime verification still needs explicit command.
    if (path / "pyproject.toml").is_file() or (path / "package.json").is_file():
        return "mcp-source"
    return "unknown"


def print_skill_install_hint(path: Path, dry_run: bool) -> None:
    cmd = f"python scripts/install_skill.py skill {path}"
    if dry_run:
        cmd += " --dry-run"
    print(f"Install after SAFE verdict: {cmd}")


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def choose_install_tools() -> list[str] | None:
    print("\nInstall target:")
    print("  1. selected agents (recommended)")
    print("  2. all detected agents")
    choice = input("Choose target [1/2, default 1]: ").strip() or "1"
    if choice == "2":
        return None

    print("\nAvailable agent targets:")
    ids = list(TOOLS)
    for idx, tid in enumerate(ids, start=1):
        print(f"  {idx}. {TOOLS[tid]['label']} ({tid})")
    raw = input("Select agents by number or id (comma-separated): ").strip()
    selected: list[str] = []
    for part in [p.strip() for p in raw.split(",") if p.strip()]:
        if part.isdigit() and 1 <= int(part) <= len(ids):
            selected.append(ids[int(part) - 1])
        elif part in TOOLS:
            selected.append(part)
        else:
            print(f"Ignoring unknown target: {part}")
    # An empty answer means "no restriction", not "no agents": returning []
    # would install nowhere, while None keeps the default (every detected
    # agent, through the skills CLI).
    return selected or None


def confirm_install(prompt: str) -> bool:
    answer = input(f"{prompt} Install now? [y/N]: ").strip().lower()
    return answer in {"y", "yes", "j", "ja"}


def offer_skill_install(path: Path, dry_run: bool) -> None:
    name = path.resolve().name
    cmd = f"python scripts/install_skill.py skill {path}"
    if dry_run:
        print(f"Install after SAFE verdict: {cmd} --dry-run")
        return
    if not interactive():
        print(f"Install after SAFE verdict: {cmd}")
        return
    if not confirm_install("[SAFE] Skill scan passed."):
        print("Install skipped by user.")
        return
    selected = choose_install_tools()
    install_skill(path, name, workspace_default(), dry=False, selected=selected)


def offer_mcp_install(name: str, command: str, args: list[str], dry_run: bool) -> None:
    cmd = " ".join([
        "python scripts/install_skill.py mcp",
        f"--name {name}",
        f"--command {command}",
        *[f"--arg={arg}" for arg in args],
    ])
    if dry_run:
        print(f"Install after SAFE verdict: {cmd} --dry-run")
        return
    if not interactive():
        print(f"Install after SAFE verdict: {cmd}")
        return
    if not confirm_install("[SAFE] MCP scan passed."):
        print("Install skipped by user.")
        return
    selected = choose_install_tools()
    install_mcp(name, {"command": command, "args": args}, dry=False, selected=selected)


def offer_remote_mcp_install(name: str, url: str, dry_run: bool) -> None:
    cmd = " ".join([
        "python scripts/install_skill.py mcp-remote",
        f"--name {name}",
        f"--url {url}",
    ])
    if dry_run:
        print(f"Install after SAFE verdict: {cmd} --dry-run")
        return
    if not interactive():
        print(f"Install after SAFE verdict: {cmd}")
        return
    if not confirm_install("[SAFE] Remote MCP scan passed."):
        print("Install skipped by user.")
        return
    selected = choose_install_tools()
    install_mcp(name, {"url": url}, dry=False, selected=selected)


def offer_git_mcp_install(source: ResolvedSource, dry_run: bool) -> None:
    if source.kind != "github" or not source.source_path or not source.install_hint:
        print("MCP source scan complete. Runtime sandbox and install command need "
              "an explicit launch command for this source.")
        return
    package, script = infer_python_project(source.source_path)
    if not package:
        print("MCP source scan complete. No Python package metadata found for "
              "automatic uv tool installation; provide an explicit launch command.")
        return
    git_url = f"git+{source.install_hint}"
    name = mcp_name_from_package(package)
    parts = [
        "python scripts/install_skill.py mcp-git",
        f"--name {name}",
        f"--git-url {git_url}",
        f"--package {package}",
    ]
    if script:
        parts.append(f"--executable {script}")
    cmd = " ".join(parts)
    if dry_run:
        print(f"Install after SAFE verdict: {cmd} --dry-run")
        return
    if not interactive():
        print(f"Install after SAFE verdict: {cmd}")
        return
    if not confirm_install("[SAFE] Git-backed MCP source scan passed."):
        print("Install skipped by user.")
        return
    selected = choose_install_tools()
    install_mcp_git(name, git_url, package, dry=False, selected=selected,
                    executable=script)


def package_page_from_command(command: str) -> tuple[str, str] | None:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not parts:
        return None
    runner = Path(parts[0]).name.lower()
    args = parts[1:]
    if runner in {"npx", "npx.cmd"}:
        package = npm_package_from_args(args)
        if package:
            return "npm", f"https://www.npmjs.com/package/{package}"
    if runner in {"uvx", "uvx.exe"}:
        package = uvx_package_from_args(args)
        if package:
            return "pypi", f"https://pypi.org/project/{package}/"
    return None


def npm_package_from_args(args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--package", "-p"}:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in {"--userconfig", "--cache", "--prefix"}:
                skip_next = True
            continue
        return arg
    return None


def uvx_package_from_args(args: list[str]) -> str | None:
    for index, arg in enumerate(args):
        if arg == "--from":
            return args[index + 1] if index + 1 < len(args) else None
        if arg.startswith("--from="):
            return arg.partition("=")[2] or None
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--from"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def print_marketplace_candidate_summary(source: ResolvedSource) -> bool:
    source_urls = source.source_urls or source.urls or []
    remote_urls = source.remote_urls or []
    install_commands = source.install_commands or []
    has_candidate = bool(source_urls or remote_urls or install_commands)

    print("\n" + "=" * 60)
    if source_urls:
        print(f"Local/source install candidates discovered: {len(source_urls)}")
        print("These can be source-scanned by resolving the concrete URL:")
        for url in source_urls[:50]:
            print(f"  - {url}")
    if remote_urls:
        print(f"Remote MCP candidates discovered: {len(remote_urls)}")
        print("Remote HTTP/SSE MCPs have no local install files; run Cisco "
              "remote runtime scan against the concrete URL:")
        for url in remote_urls[:50]:
            print(f"  - python scripts/scan_mcp.py remote {url}")
    if install_commands:
        print(f"Install command candidates discovered: {len(install_commands)}")
        print("Derive a package/source scan from these commands before install; "
              "use --sandbox for runtime inspection:")
        for command in install_commands[:50]:
            print(f"  - {command}")
    if not has_candidate:
        print("[BLOCK] NO INSTALLABLE SOURCE -- marketplace/catalog page was "
              "read and scanned as text, but no concrete local package/source, "
              "remote MCP URL, or install command was discovered. This is not a "
              "verdict for the listed skill or MCP. Use a direct "
              "GitHub/archive/raw SKILL.md/npm/PyPI/remote MCP URL, or a "
              "marketplace page that exposes one.")
    else:
        print("Catalog text verdict is not a final security verdict for the "
              "listed MCP/skill. Scan one concrete candidate above before "
              "installing.")
    return has_candidate


def scan_marketplace_candidates(source: ResolvedSource, sandbox: bool,
                                max_candidates: int, dry_run: bool) -> int:
    source_urls = list(source.source_urls or source.urls or [])
    remote_urls = list(source.remote_urls or [])
    install_commands = list(source.install_commands or [])
    for command in install_commands:
        package_page = package_page_from_command(command)
        if package_page:
            _, url = package_page
            if url not in source_urls:
                source_urls.append(url)
    candidates = (
        [("source", item) for item in source_urls]
        + [("remote", item) for item in remote_urls]
        + [("command", item) for item in install_commands]
    )
    if not candidates:
        return 2

    print("\n" + "=" * 60)
    print(f"Scanning marketplace candidates: {min(len(candidates), max_candidates)} "
          f"of {len(candidates)}")
    worst = 0
    scanned = 0
    for kind, item in candidates:
        if scanned >= max_candidates:
            print(f"Skipped {len(candidates) - scanned} candidate(s) due to --max-candidates.")
            break
        scanned += 1
        print("\n" + "-" * 60)
        print(f"Candidate {scanned}: {kind} -> {item}")
        if kind == "source":
            rc = scan_candidate_source_url(item)
        elif kind == "remote":
            if not sandbox:
                print("[BLOCK] NO VERDICT -- discovered remote endpoint was not contacted. "
                      "Use --sandbox for explicit runtime inspection or scan the chosen remote URL directly.")
                worst = combine_verdicts(worst, 2)
                continue
            rc = run_remote(item)
            if rc == 0:
                offer_remote_mcp_install(mcp_name_from_url(item), item, dry_run=dry_run)
        else:
            rc = scan_install_command(item, sandbox=sandbox, dry_run=dry_run)
        worst = combine_verdicts(worst, rc)

    left_out = len(candidates) - scanned
    if left_out:
        worst = combine_verdicts(worst, 2)

    print("\n" + "=" * 60)
    if worst == 0:
        print("[SAFE] Marketplace candidate scan completed without blocking findings.")
    else:
        tag = "BLOCK" if worst == 1 else "NO VERDICT"
        print(f"[{tag}] One or more marketplace candidates failed or were incomplete "
              f"(worst exit {worst}).")
    return worst


def scan_candidate_source_url(url: str) -> int:
    with tempfile.TemporaryDirectory() as d:
        try:
            source = resolve_url(url, Path(d))
        except FetchError as e:
            print(f"[BLOCK] candidate fetch failed: {e}")
            return 2
        return scan_resolved(source, "auto", dry_run=True)


def scan_install_command(command: str, sandbox: bool, dry_run: bool) -> int:
    print("Install command discovered; deriving source scan where possible.")
    package_page = package_page_from_command(command)
    rc = 2
    if package_page:
        _, url = package_page
        print(f"Derived package source: {url}")
        rc = scan_candidate_source_url(url)
    else:
        print("[WARN] Could not derive a source package from this command.")
    if sandbox:
        try:
            args = shlex.split(command, posix=True)
        except ValueError:
            print("[BLOCK] Could not parse install command for sandbox runtime scan.")
            return combine_verdicts(rc, 2)
        sandbox_rc = run_sandbox(args)
        rc = combine_verdicts(rc, sandbox_rc)
    else:
        print("[WARN] Runtime sandbox scan not run. Re-run with --sandbox for live MCP "
              "tool/prompt inspection.")
    if rc == 0:
        print("Use the pinned installation proposal from the derived package scan above. "
              "The catalog's original command may select different code or extra arguments.")
    return rc


def mcp_name_from_command(parts: list[str]) -> str:
    package = None
    runner = Path(parts[0]).name.lower()
    if runner in {"npx", "npx.cmd"}:
        package = npm_package_from_args(parts[1:])
    elif runner in {"uvx", "uvx.exe"}:
        package = uvx_package_from_args(parts[1:])
    return (package or Path(parts[0]).name).replace("/", "-").replace("@", "")


def mcp_name_from_package(package: str) -> str:
    return package.replace("/", "-").replace("@", "")


def mcp_name_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    stem = parts[-1] if parts else parsed.netloc
    if stem in {"mcp", "sse"}:
        stem = parts[-2] if len(parts) > 1 else parsed.netloc
    name = re_sub_non_name(stem or parsed.netloc)
    return name or "remote-mcp"


def re_sub_non_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value).strip("-")


def persist_source(source: ResolvedSource, keep_source: Path | None) -> Path | None:
    if keep_source is None or source.source_path is None:
        return source.source_path
    target = keep_source.resolve()
    if target.exists():
        raise SystemExit(f"ERROR: --keep-source target already exists: {target}")
    if source.source_path.is_dir():
        shutil.copytree(source.source_path, target, symlinks=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source.source_path, target)
    print(f"Persisted scanned source: {target}")
    return target


def run_dynamic_stage(ecosystem: str, pinned: str, enabled: bool) -> int:
    """Install analysis of exactly the version the static scan fetched."""
    if not enabled:
        return _skipped_dynamic_verdict()
    print("\n-- Dynamic install analysis (OpenSSF sandbox) --")
    return _dynamic.run(ecosystem, pinned)


def scan_resolved(source: ResolvedSource, kind: str, dry_run: bool,
                  keep_source: Path | None = None, sandbox: bool = False,
                  scan_candidates: bool = True, max_candidates: int = 10,
                  dynamic: bool = True) -> int:
    if kind in {"catalog", "markdown"}:
        # An explicit kind must not shrink a repo or directory to a README check.
        detected = classify_source(source)
        if detected not in {"catalog", "markdown", "file"}:
            print(f"[BLOCK] NO VERDICT -- --kind {kind} would check only the README "
                  f"of a {detected} source.")
            return 2
    if kind == "auto":
        kind = classify_source(source)
    stable_path = persist_source(source, keep_source)
    if stable_path is not None:
        source.source_path = stable_path
    print(f"Resolved source: {source.label or source.kind}")
    if source.pinned_ref:
        print(f"Pinned/source ref: {source.pinned_ref}")
    print(f"Detected type: {kind}")

    if source.kind == "pypi":
        with tempfile.TemporaryDirectory() as d:
            pinned = fetch_pypi(source.install_hint, Path(d))
            rc = run_mcp_static(Path(d))
        rc = combine_verdicts(rc, run_dynamic_stage("pypi", pinned, dynamic))
        if rc == 0:
            offer_mcp_install(source.install_hint.split("==")[0], "uvx", [pinned], dry_run)
        return rc

    if source.kind == "npm":
        with tempfile.TemporaryDirectory() as d:
            pinned = fetch_npm(source.install_hint, Path(d))
            rc = run_mcp_static(Path(d))
        rc = combine_verdicts(rc, run_dynamic_stage("npm", pinned, dynamic))
        if rc == 0:
            offer_mcp_install(pinned.rpartition("@")[0], "npx",
                              ["--silent", "-y", pinned], dry_run)
        return rc

    path = source.source_path
    if path is None:
        die(f"resolved source has no local path: {source}")

    if kind == "skill":
        rc = run_skill_static(path)
        if rc == 0:
            offer_skill_install(path, dry_run)
        return rc

    if kind == "skill-collection":
        worst = 0
        skills = find_skill_dirs(path)
        if not skills:
            print("[BLOCK] NO VERDICT -- no skill found in the skill collection.")
            return 2
        for d in skills:
            print(f"\n== {d} ==")
            worst = combine_verdicts(worst, run_skill_static(d))
        unscanned = files_outside_skills(path, skills)
        if unscanned:
            print("\n[BLOCK] NO VERDICT -- files outside the skill folders were not scanned:")
            for rel in unscanned[:20]:
                print(f"  {rel}")
            if len(unscanned) > 20:
                print(f"  ... and {len(unscanned) - 20} more")
            worst = combine_verdicts(worst, 2)
        print("\n" + "=" * 60)
        print(f"Scanned {len(skills)} skill(s). Worst verdict -> exit {worst} "
              f"({'all SAFE' if worst == 0 else 'BLOCK' if worst == 1 else 'NO VERDICT'}).")
        if worst == 0:
            print("Install concrete SAFE skill directories individually, for example:")
            if dry_run:
                print_skill_install_hint(skills[0], dry_run=True)
            elif interactive() and confirm_install("[SAFE] Skill collection scan passed."):
                selected = choose_install_tools()
                for skill_dir in skills:
                    install_skill(skill_dir, skill_dir.resolve().name,
                                  workspace_default(), dry=False, selected=selected)
            else:
                print_skill_install_hint(skills[0], dry_run=False)
        return worst

    if kind == "mcp-source":
        rc = run_mcp_static(path)
        if rc == 0:
            offer_git_mcp_install(source, dry_run)
        return rc

    if kind == "unknown":
        print("[BLOCK] NO VERDICT -- unsupported repo layout: no skill, no package "
              "manifest. A README-only check is not a verdict.")
        return 2

    if kind in {"catalog", "markdown", "file"}:
        rc = scan_catalog(path)
        if source.kind == "catalog":
            has_candidate = print_marketplace_candidate_summary(source)
            if not has_candidate:
                return 2
            if rc != 0:
                tag = "BLOCK" if rc == 1 else "NO VERDICT"
                print(f"[{tag}] Catalog scan did not end SAFE; candidate "
                      "scans and install prompts are skipped.")
                return rc
            if scan_candidates:
                candidate_rc = scan_marketplace_candidates(
                    source, sandbox=sandbox, max_candidates=max_candidates,
                    dry_run=dry_run
                )
                return combine_verdicts(rc, candidate_rc)
            print("\n[BLOCK] NO VERDICT -- --no-scan-candidates: the listed candidates "
                  "were NOT scanned, so only the listing text has a verdict:")
            for label, items in (
                ("source", source.source_urls or source.urls or []),
                ("remote MCP", source.remote_urls or []),
                ("install command", source.install_commands or []),
            ):
                for item in items:
                    print(f"  - unscanned {label} candidate: {item}")
            return combine_verdicts(rc, 2)
        return rc

    die(f"unsupported detected type: {kind}")
    return 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve and scan a URL pointing to a skill, MCP, archive, or catalog."
    )
    parser.add_argument("url")
    parser.add_argument("--kind", choices=[
        "auto", "skill", "skill-collection", "mcp-source", "catalog", "markdown"
    ], default="auto")
    parser.add_argument("--dry-run", action="store_true",
                        help="print install command previews where applicable")
    parser.add_argument("--keep-source", type=Path, default=None,
                        help="copy the resolved pinned source to this path before scanning; "
                             "useful when you want to install the exact scanned source")
    parser.add_argument("--no-scan-candidates", action="store_true",
                        help="for marketplace/catalog pages, only scan the listing text and "
                             "print candidates instead of scanning them")
    parser.add_argument("--sandbox", action="store_true",
                        help="opt into runtime inspection of discovered remote MCPs and "
                             "live Cisco stdio scans in Docker for install commands")
    parser.add_argument("--no-dynamic", action="store_true",
                        help="skip the dynamic install analysis of PyPI/npm packages "
                             "(it needs Docker); the result is NO VERDICT "
                             "unless AGENT_GUARD_STATIC_ONLY=1")
    parser.add_argument("--max-candidates", type=int, default=10,
                        help="maximum marketplace candidates to scan automatically; "
                             "candidates left out give exit 2")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as d:
        try:
            source = resolve_url(args.url, Path(d))
        except FetchError as e:
            die(f"{e}. Do NOT install; retry with a reachable source URL.")
        sys.exit(scan_resolved(source, args.kind, dry_run=args.dry_run,
                               keep_source=args.keep_source,
                               sandbox=args.sandbox,
                               scan_candidates=not args.no_scan_candidates,
                               max_candidates=args.max_candidates,
                               dynamic=not args.no_dynamic))


if __name__ == "__main__":
    import _console

    _console.utf8_stdio()
    main()
