"""Benign holdout: official skills drawn at random that no rule was tuned on.

An entry is `fresh` until a triage rule changes because of its result; it is
then `retired` and a new draw is made. Only fresh entries count as evidence.
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

import _corpus
import _staging

ROOT = Path(__file__).resolve().parents[1]
HOLDOUT = ROOT / "tests" / "eval" / "benign_holdout.toml"
LIBRARY = Path.home() / "skills-library"
REPOS = ("anthropics/skills", "vercel-labs/agent-skills", "cloudflare/skills",
         "supabase/agent-skills", "microsoft/skills", "openai/skills", "stripe/ai",
         "huggingface/skills", "getsentry/skills", "google-gemini/gemini-skills",
         "hashicorp/agent-skills", "firebase/agent-skills", "mongodb/agent-skills",
         "neondatabase/agent-skills", "expo/skills")


def draw(listing: dict, seen: set, per_repo: int, seed: int) -> list:
    rng = random.Random(seed)
    picked = []
    for source in sorted(listing):
        names = sorted(n for n in set(listing[source]) if n not in seen)
        picked += [(source, n) for n in rng.sample(names, min(per_repo, len(names)))]
    return picked


def seen_names() -> set:
    names = {d.name for d in LIBRARY.iterdir() if d.is_dir()} if LIBRARY.is_dir() else set()
    names |= {s.id for s in _corpus.load_manifest()}
    return names


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
LISTED_NAME = re.compile(r"^│ {4}(\S+)\s*$")


def parse_cli_list(text: str) -> list:
    """Skill names from `skills add <source> --list`: the names the CLI installs
    (SKILL.md `name`), which need not match the directory names."""
    lines = ANSI.sub("", text).splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if "Available Skills" in line)
    except StopIteration:
        return []
    return sorted({m.group(1) for line in lines[start + 1:] if (m := LISTED_NAME.match(line))})


def listing_at(source: str) -> tuple:
    """(commit sha of HEAD, [skill names the pinned skills CLI lists at that commit])."""
    sha = subprocess.run(["gh", "api", f"repos/{source}/commits/HEAD", "-q", ".sha"],
                         capture_output=True, text=True, check=True).stdout.strip()
    argv = _staging.stage_argv(source, sha, [])[:5] + ["--list"]
    with tempfile.TemporaryDirectory() as tmp:
        done = subprocess.run(argv, cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=300)
    return sha, parse_cli_list(done.stdout)


def load(path: Path = HOLDOUT) -> tuple:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return tuple(_corpus.Sample(e["name"], "benign", "safe", e["tree_hash"], e["source"], e["ref"])
                 for e in data.get("benign", []) if e.get("status") == "fresh")


def main(per_repo: int = 2, seed: int = 20261005) -> None:
    refs, listing = {}, {}
    for source in REPOS:
        refs[source], listing[source] = listing_at(source)
    picked = draw(listing, seen_names(), per_repo, seed)
    lines = ["# Benign holdout, drawn by tests/_eval.py. Do not edit by hand.",
             "version = 1", f"seed = {seed}", ""]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for n, source in enumerate(sorted({s for s, _ in picked})):
            names = [name for s, name in picked if s == source]
            target = Path(tmp) / f"r{n}"
            target.mkdir()
            try:
                staged = _staging.stage(source, refs[source], names, target)
            except Exception as exc:  # whole repo unusable: note it, draw nothing in its place
                staged, why = {}, f"{type(exc).__name__}: {exc}"[:200]
            else:
                why = "the skills CLI does not know this name"
            for name in names:
                if name in staged:
                    lines += ["[[benign]]", f'name = "{name}"', f'source = "{source}"',
                              f'ref = "{refs[source]}"',
                              f'tree_hash = "{_staging.tree_digest(staged[name].path)}"',
                              'status = "fresh"', ""]
                else:
                    lines += ["[[skipped]]", f'name = "{name}"', f'source = "{source}"',
                              f"why = {json.dumps(why)}", ""]
    HOLDOUT.parent.mkdir(parents=True, exist_ok=True)
    HOLDOUT.write_text("\n".join(lines), encoding="utf-8")
    kept = sum(1 for line in lines if line == "[[benign]]")
    print(f"{kept} of {len(picked)} skills written to {HOLDOUT}")


if __name__ == "__main__":
    main()
