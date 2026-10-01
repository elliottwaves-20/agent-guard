"""Stage skills through the pinned `skills` CLI without touching any agent.

The CLI's project mode writes only below its working directory: the skill to
`<cwd>/.agents/skills/<name>` and the lock to `<cwd>/skills-lock.json`. Run in a
throw-away directory, it fetches a skill exactly as a normal install would --
same source formats, same selection by name -- but nothing reaches an agent
until agent-guard has scanned the staged files and promoted them.

A commit is pinned with `owner/repo#<sha>`; the CLI records it as `ref` in the
lock, which is checked below, so the verdict belongs to one immutable commit.

The only parts of the CLI this module relies on are `add` in project mode and
the project lock format (version 1). An unknown lock version stops with an
error instead of guessing, so a pin bump that changes the format fails loudly.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple

import _skills_cli
from _skillspector import run_bounded

LOCK_FILE = "skills-lock.json"
LOCK_VERSION = 1
GLOBAL_LOCK_VERSION = 3
ORIGINS_VERSION = 1
STAGE_TIMEOUT = float(os.environ.get("AGENT_GUARD_STAGE_TIMEOUT", "600"))

# `codex` is one of the CLI's "universal" agents: in project mode its skills
# directory IS the canonical `.agents/skills`, so the CLI writes the staged copy
# once and links nothing else.
STAGE_AGENT = "codex"

GITHUB_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+")
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class StageError(Exception):
    """Staging or promotion could not complete; nothing was changed."""


class Staged(NamedTuple):
    name: str
    path: Path
    entry: dict


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# -- sources ------------------------------------------------------------------

def check_source(source: str) -> str:
    source = (source or "").strip()
    if not GITHUB_SOURCE.fullmatch(source) or source.endswith((".", ".git")):
        raise StageError(f"unsupported source {source!r}: expected owner/repo on GitHub")
    return source


def check_name(name: str) -> str:
    if not SAFE_NAME.fullmatch(name or "") or name.endswith("."):
        raise StageError(f"unsafe skill name {name!r}")
    return name


def resolve_ref(source: str) -> str:
    """The current default-branch commit of a GitHub source."""
    import _url_resolver
    owner, repo = check_source(source).split("/", 1)
    try:
        return _url_resolver.github_default_sha(owner, repo)
    except _url_resolver.FetchError as exc:
        raise StageError(str(exc)) from exc


# -- staging ------------------------------------------------------------------

def stage_argv(source: str, ref: str, names: list) -> list:
    argv = [_skills_cli.npx_path() or "npx", "-y",
            f"{_skills_cli.SKILLS_PACKAGE}@{_skills_cli.SKILLS_VERSION}",
            "add", f"{check_source(source)}#{ref}"]
    for name in names:
        argv += ["-s", check_name(name)]
    argv += ["-a", STAGE_AGENT, "-y"]
    return argv


def read_stage_lock(workdir: Path) -> dict:
    path = workdir / LOCK_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageError(f"skills CLI wrote no readable {LOCK_FILE} ({exc})") from exc
    if data.get("version") != LOCK_VERSION or not isinstance(data.get("skills"), dict):
        raise StageError(f"unknown {LOCK_FILE} format (version {data.get('version')!r}, "
                         f"expected {LOCK_VERSION}) -- re-verify the skills CLI pin")
    return data["skills"]


def stage(source: str, ref: str, names: list, workdir: Path,
          timeout: float = STAGE_TIMEOUT) -> dict:
    """Fetch `names` from `source` at commit `ref` into `workdir`.

    Returns {name: Staged} for every requested skill the source still has;
    a missing name is simply absent from the result."""
    if not SHA.fullmatch(ref or ""):
        raise StageError(f"ref must be a full commit SHA, got {ref!r}")
    if _skills_cli.npx_path() is None:
        raise StageError("npx not found on PATH")
    if not _skills_cli.verify_pinned_package():
        raise StageError("the pinned skills CLI did not pass verification")
    argv = stage_argv(source, ref, names)
    try:
        result = run_bounded(argv, env=_skills_cli.hardened_env(), timeout=timeout,
                             cwd=str(workdir))
    except subprocess.TimeoutExpired as exc:
        raise StageError(f"skills CLI timed out after {timeout:.0f}s") from exc
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-5:]
        raise StageError("skills CLI failed: " + " | ".join(tail))
    lock = read_stage_lock(workdir)
    staged = {}
    for name in names:
        entry = lock.get(name)
        path = workdir / ".agents" / "skills" / name
        if entry is None or not (path / "SKILL.md").is_file():
            continue
        if entry.get("source") != source or entry.get("ref") != ref:
            raise StageError(f"{name}: lock records {entry.get('source')}#{entry.get('ref')}, "
                             f"expected {source}#{ref}")
        staged[name] = Staged(name, path, entry)
    return staged


# -- content identity ---------------------------------------------------------

def tree_digest(root: Path) -> str:
    """One hash over every file below `root`; links anywhere are rejected."""
    root = Path(root)
    if root.is_symlink() or root.resolve() != root.absolute():
        raise StageError(f"{root} is a link, not a directory")
    base = root.resolve()
    h = hashlib.sha256()
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or path.resolve() != path.absolute():
            raise StageError(f"indirect filesystem entry: {path}")
        key = path.relative_to(base).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "dir"
        h.update(f"{key}\0{digest}\n".encode("utf-8"))
    return h.hexdigest()


# -- origins file -------------------------------------------------------------

def load_origins(path: Path) -> dict:
    if not path.exists():
        return {"version": ORIGINS_VERSION, "skills": {}, "sources": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != ORIGINS_VERSION:
        raise StageError(f"{path}: unknown origins format {data.get('version')!r}")
    data.setdefault("skills", {})
    data.setdefault("sources", {})
    return data


def save_origins(path: Path, data: dict):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def import_global_lock(lock_path: Path, origins: dict, inbox: Path) -> tuple:
    """Adopt GitHub entries of the CLI's global lock for skills in `inbox`.

    Returns (added, skipped) name lists. Nothing is fetched here."""
    data = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    if data.get("version") != GLOBAL_LOCK_VERSION:
        raise StageError(f"{lock_path}: unknown global lock format {data.get('version')!r}")
    added, skipped = [], []
    for name, entry in sorted((data.get("skills") or {}).items()):
        try:
            check_name(name)
            source = check_source(entry.get("source", ""))
        except StageError:
            skipped.append(name)
            continue
        if (entry.get("sourceType") != "github" or name in origins["skills"]
                or not (inbox / name / "SKILL.md").is_file()):
            skipped.append(name)
            continue
        origins["skills"][name] = {"source": source, "imported": now()}
        added.append(name)
    return added, skipped


# -- promotion ----------------------------------------------------------------

def copy_verified(src: Path, dest: Path, digest: str):
    shutil.copytree(src, dest, symlinks=False)
    if tree_digest(dest) != digest:
        shutil.rmtree(dest, ignore_errors=True)
        raise StageError(f"copy of {src.name} does not match the scanned files")


def promote(src: Path, target: Path, digest: str, backup: Path | None) -> Path | None:
    """Replace `target` by the scanned `src`. Returns where the old version went.

    The new copy is prepared next to the target under a `_` name, which the
    distribution ignores, and swapped in by rename; the old version is moved
    to `backup`, never deleted."""
    target = Path(target)
    if target.is_symlink() or (target.exists() and target.resolve() != target.absolute()):
        raise StageError(f"{target} is a link -- managed elsewhere, not replaced")
    if target.exists() and backup is None:
        raise StageError("replacing a skill needs [distribution] backup")
    fresh = target.with_name(f"_guard-new-{target.name}")
    if fresh.exists():
        raise StageError(f"leftover {fresh} -- remove it after review")
    moved = None
    if target.exists():
        backup.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        moved = backup / f"{target.name}-{stamp}"
        n = 1
        while moved.exists():
            n += 1
            moved = backup / f"{target.name}-{stamp}-{n}"
    copy_verified(src, fresh, digest)
    try:
        if moved is not None:
            target.rename(moved)
        fresh.rename(target)
    except OSError as exc:
        if moved is not None and moved.exists() and not target.exists():
            moved.rename(target)
        shutil.rmtree(fresh, ignore_errors=True)
        raise StageError(f"could not swap in {target.name}: {exc}") from exc
    return moved


def quarantine_copy(src: Path, quarantine: Path | None, name: str, digest: str) -> Path | None:
    if quarantine is None:
        return None
    dest = quarantine / f"{name}-{digest[:12]}"
    if dest.exists():
        return dest
    quarantine.mkdir(parents=True, exist_ok=True)
    copy_verified(src, dest, digest)
    return dest
