#!/usr/bin/env python3
"""
Skill security scanner -- scan first, install after (for skills / plugins).

Wraps NVIDIA SkillSpector so skill scans get the same provider-aware, clean,
cross-platform handling as the MCP wrapper:
  - UTF-8 is forced (SkillSpector's terminal report crashes on a legacy Windows
    cp1252 console otherwise),
  - the LLM layer runs through the configured SKILLSPECTOR_PROVIDER -- by
    default a coding-agent CLI (claude_cli / codex_cli / gemini_cli) using the
    user's existing login, or any hosted provider with an API key; without a
    usable provider it runs static-only (patterns, taint, YARA, OSV.dev),
  - a fail-closed [SAFE] / [BLOCK] verdict is parsed from JSON, including
    SkillSpector's execution/coverage ledger and LLM-completeness metadata.

A skill is only *read*, never executed, so this never runs the scanned code.

Usage:
  python scan_skill.py <path>        # scan one skill (dir / .zip / .md / repo subdir)
  python scan_skill.py --all <dir>   # scan each skill (SKILL.md dir) under <dir>

After a SAFE verdict, install with:
  python install_skill.py skill <path>
"""

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from _skillspector import die, run_skillspector

GITHUB_LINK_RE = re.compile(r"https://github\.com/[^\s)\]>\"']+")


def find_skill_dirs(root: Path) -> list:
    """Directories that contain a SKILL.md, excluding node_modules.

    Each is scanned on its own: SkillSpector aggregates a whole directory into a
    single report, so per-skill scans are what give per-skill verdicts."""
    out = set()
    for p in root.rglob("SKILL.md"):
        if "node_modules" in p.parts:
            continue
        out.add(p.parent)
    return sorted(out)


def github_repo_key(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url.rstrip(".,;"))
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def find_catalog_links(path: Path) -> list[str]:
    texts: list[str] = []
    if path.is_file():
        texts.append(path.read_text(encoding="utf-8", errors="replace"))
    else:
        for name in ("README.md", "readme.md", "README.markdown", "readme.markdown"):
            candidate = path / name
            if candidate.is_file():
                texts.append(candidate.read_text(encoding="utf-8", errors="replace"))
    seen: set[tuple[str, str]] = set()
    links: list[str] = []
    for text in texts:
        for match in GITHUB_LINK_RE.finditer(text):
            url = match.group(0).rstrip(".,;")
            key = github_repo_key(url)
            if key is None or key in seen:
                continue
            seen.add(key)
            links.append(url)
    return links


def scan_catalog(path: Path) -> int:
    """Audit a catalog/index repository without treating it as installable.

    Catalogs contain links to skills, collections, articles, or MCP projects.
    They are useful discovery sources, but they are not a SAFE verdict for any
    linked repo. Each linked install target must be fetched, pinned, scanned,
    and installed separately.
    """
    readme = path if path.is_file() else None
    if path.is_dir():
        for name in ("README.md", "readme.md", "README.markdown", "readme.markdown"):
            candidate = path / name
            if candidate.is_file():
                readme = candidate
                break
    if readme is None:
        die(f"catalog scan needs a markdown README or file: {path}")

    print(f"Catalog scan (not installable as a skill): {path}")
    verdict = run_skillspector(readme)
    links = find_catalog_links(path)
    print("\n" + "=" * 60)
    print(f"Catalog links discovered: {len(links)} GitHub repo(s)")
    if links:
        print("Linked repos are candidates only. Scan and install each concrete "
              "SKILL.md directory separately.")
        for url in links[:50]:
            print(f"  - {url}")
        if len(links) > 50:
            print(f"  ... {len(links) - 50} more")
    print("Catalog verdict does not apply to linked skills.")
    return verdict


def main():
    ap = argparse.ArgumentParser(
        description="Scan a skill for malicious code before installing it.")
    ap.add_argument("path", help="skill path: a directory, .zip, .md, or repo subdir")
    ap.add_argument("--all", action="store_true",
                    help="treat <path> as a tree and scan each skill (every "
                         "SKILL.md directory) under it separately")
    ap.add_argument("--catalog", action="store_true",
                    help="treat <path> as a non-installable skill catalog/index: "
                         "scan the catalog text and list linked GitHub repos")
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        die(f"path not found: {target}")

    if args.catalog:
        sys.exit(scan_catalog(target))

    if args.all:
        if not target.is_dir():
            die("--all needs a directory")
        skills = find_skill_dirs(target)
        if not skills:
            die(f"no SKILL.md found under {target}")
        worst = 0
        for d in skills:
            print(f"\n== {d} ==")
            worst = max(worst, run_skillspector(d))
        print("\n" + "=" * 60)
        print(f"Scanned {len(skills)} skill(s). Worst verdict -> exit {worst} "
              f"({'BLOCK' if worst else 'all SAFE'}).")
        sys.exit(worst)

    sys.exit(run_skillspector(target))


if __name__ == "__main__":
    main()
