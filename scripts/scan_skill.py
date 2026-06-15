#!/usr/bin/env python3
"""
Skill security scanner -- scan first, install after (for skills / plugins).

Wraps NVIDIA SkillSpector so skill scans get the same provider-aware, clean,
cross-platform handling as the MCP wrapper:
  - UTF-8 is forced (SkillSpector's terminal report crashes on a legacy Windows
    cp1252 console otherwise),
  - the LLM layer is used only with a provider SkillSpector supports
    (OpenAI / NVIDIA); with Anthropic it runs static-only -- the static layer
    (patterns, taint, YARA, OSV.dev) is unaffected,
  - a fail-closed [SAFE] / [BLOCK] verdict is parsed from JSON.

A skill is only *read*, never executed, so this never runs the scanned code.

Usage:
  python scan_skill.py <path>        # scan one skill (dir / .zip / .md / repo subdir)
  python scan_skill.py --all <dir>   # scan each skill (SKILL.md dir) under <dir>

After a SAFE verdict, install with:
  python install_skill.py skill <path>
"""

import argparse
import sys
from pathlib import Path

from _skillspector import die, run_skillspector


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


def main():
    ap = argparse.ArgumentParser(
        description="Scan a skill for malicious code before installing it.")
    ap.add_argument("path", help="skill path: a directory, .zip, .md, or repo subdir")
    ap.add_argument("--all", action="store_true",
                    help="treat <path> as a tree and scan each skill (every "
                         "SKILL.md directory) under it separately")
    args = ap.parse_args()

    target = Path(args.path)
    if not target.exists():
        die(f"path not found: {target}")

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
