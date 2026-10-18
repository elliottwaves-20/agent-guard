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

import _dossier
import _skills_cli
from _skillspector import run_bounded

LOCK_FILE = "skills-lock.json"
LOCK_VERSION = 1
GLOBAL_LOCK_VERSION = 3
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


def remote_head(source: str, run=subprocess.run) -> tuple:
    """(default branch, head commit) of a GitHub source, by `git ls-remote`:
    no API call, so no rate limit for the check that runs every time."""
    url = f"https://github.com/{check_source(source)}.git"
    argv = ["git", "ls-remote", "--symref", url, "HEAD"]
    try:
        done = run(argv, capture_output=True, text=True, timeout=60,
                   env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StageError(f"git ls-remote {source} failed: {exc}") from exc
    if done.returncode != 0:
        raise StageError(f"git ls-remote {source} failed: {(done.stderr or '').strip()[:200]}")
    branch = sha = None
    for line in (done.stdout or "").splitlines():
        if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
            branch = line[len("ref: refs/heads/"):-len("\tHEAD")]
        elif line.endswith("\tHEAD") and SHA.fullmatch(line[:40]):
            sha = line[:40]
    if not branch or not sha:
        raise StageError(f"git ls-remote {source}: no default branch and commit in the answer")
    return branch, sha


# -- the 7-day rule -----------------------------------------------------------

# A commit is staged only once it has been on the branch this long: a hijacked
# repository is usually noticed and cleaned up within days, and a version that
# is never staged costs no download and no scan.
COOLDOWN_DAYS = 7
ACTIVITY_PAGE = 100
ACTIVITY_MAX_PAGES = 20
NULL_SHA = "0" * 40
_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _timestamp(value) -> _dt.datetime:
    try:
        stamp = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise StageError(f"invalid activity timestamp {value!r}") from exc
    if stamp.tzinfo is None:
        raise StageError(f"activity timestamp without time zone: {value!r}")
    return stamp


def _next_after_cursor(link_header: str) -> str | None:
    import urllib.parse
    match = _NEXT_LINK_RE.search(link_header or "")
    if not match:
        return None
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(match.group(1)).query)
    values = query.get("after") or []
    return values[0] if values and values[0] else None


def _fetch_activity_page(url: str) -> tuple:
    import urllib.error
    import urllib.request
    import _url_resolver
    req = urllib.request.Request(url, headers={**_url_resolver.DEFAULT_HEADERS, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            link = resp.headers.get("Link") or ""
            return json.load(resp), _next_after_cursor(link)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise _url_resolver.FetchError(_url_resolver.format_fetch_error(url, exc.code, body)) from exc
    except urllib.error.URLError as exc:
        raise _url_resolver.FetchError(f"could not fetch {url}: {exc.reason}") from exc


def settled_ref(source: str, branch: str, head: str, *, now=None,
                days: int = COOLDOWN_DAYS, fetch=None) -> tuple:
    """(commit, time) of the newest state of `branch` that is at least `days` old.

    The times come from GitHub's repository activity (push, merge, force push):
    GitHub sets them when the branch moves, so unlike a commit's own date they
    cannot be backdated by whoever writes the commit. No activity at all means
    the head itself is old (time None). Any doubt stops with StageError."""
    import urllib.parse
    import _url_resolver
    fetch = fetch or _fetch_activity_page
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cutoff = now - _dt.timedelta(days=days)
    ref = urllib.parse.quote(f"refs/heads/{branch}", safe="")
    base = f"https://api.github.com/repos/{check_source(source)}/activity?ref={ref}&per_page={ACTIVITY_PAGE}"
    oldest = None
    after_cursor = None
    for page in range(1, ACTIVITY_MAX_PAGES + 1):
        url = f"{base}&after={urllib.parse.quote(after_cursor, safe='')}" if after_cursor else (
            base if page == 1 else f"{base}&page={page}"
        )
        try:
            raw = fetch(url)
        except _url_resolver.FetchError as exc:
            raise StageError(f"{source}: branch activity unavailable ({exc})") from exc
        if isinstance(raw, tuple) and len(raw) == 2:
            items, next_cursor = raw
            has_cursor = True
        else:
            items, next_cursor, has_cursor = raw, None, False
        if not isinstance(items, list):
            raise StageError(f"{source}: unexpected branch activity answer")
        entries = []
        for item in items:
            if not isinstance(item, dict) or item.get("ref", f"refs/heads/{branch}") != f"refs/heads/{branch}":
                continue
            after = str(item.get("after") or "")
            if not SHA.fullmatch(after):
                raise StageError(f"{source}: invalid commit in branch activity")
            entries.append((_timestamp(item.get("timestamp")), after, str(item.get("before") or "")))
        for stamp, after, before in sorted(entries, reverse=True):
            if stamp <= cutoff:
                return after, stamp.isoformat()
            if oldest is None or stamp < oldest[0]:
                oldest = (stamp, after, before)
        if len(items) < ACTIVITY_PAGE or (has_cursor and not next_cursor):
            break
        after_cursor = next_cursor
    else:
        raise StageError(f"{source}: more than {ACTIVITY_PAGE * ACTIVITY_MAX_PAGES} branch changes "
                         f"in {days} days; not choosing a version")
    if oldest is None:
        return head, None
    before = oldest[2]
    if not SHA.fullmatch(before) or before == NULL_SHA:
        raise StageError(f"{source}: the branch is younger than {days} days")
    return before, None


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
    """The review file (see _dossier.py); version 1 is migrated on load."""
    try:
        return _dossier.load(path)
    except _dossier.DossierError as exc:
        raise StageError(str(exc)) from exc


def save_origins(path: Path, data: dict):
    _dossier.save(path, data)


def import_global_lock(lock_path: Path, origins: dict, inbox: Path) -> tuple:
    """Adopt GitHub entries of the CLI's global lock for skills in `inbox`.

    Returns (added, skipped) name lists. Nothing is fetched here."""
    try:
        data = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageError(f"cannot read {lock_path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != GLOBAL_LOCK_VERSION:
        raise StageError(f"{lock_path}: unknown global lock format {data.get('version') if isinstance(data, dict) else data!r}")
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
        origins["skills"][name] = {"kind": "skill", "source": source, "imported": now()}
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
