"""The review file (Prüfakte): one record per managed artifact.

It is the origins file of update_skills.py, grown into the single source of
truth for what agent-guard knows about each artifact:

  kind        "skill" (mcp and cli follow in 0.6)
  source/ref  where it comes from and the commit it was taken at
  tree_hash   identity of the installed version (_staging.tree_digest)
  files       {relative path: SHA-256} of the installed version
  verdict     SAFE or ACCEPTED, plus `triage`: the summary of the last scan
  approved    {SHA-256: {file, version, reason, at}} -- file contents a person
              approved with --accept. A finding in a file with exactly this
              content counts as reviewed; a changed or new file is judged anew.
              Hard evidence is never cleared by an approval (see _triage).
  decisions   accept/reject history; a rejected version never alerts again
  blocked     the version waiting for a decision, with the open findings

Version 1 files are migrated on load and the original is kept once as
`<name>.v1.bak` on the first save. v1's `accepted_findings` (rule + file) are
not carried over: they did not say which content was reviewed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections import Counter
from pathlib import Path

import _triage

VERSION = 2


class DossierError(Exception):
    """The review file cannot be read safely."""


# -- format -------------------------------------------------------------------------

def empty() -> dict:
    return {"version": VERSION, "skills": {}, "sources": {}}


def migrate(data: dict) -> dict:
    """A version 1 origins file as version 2; anything else is returned as is."""
    if data.get("version") != 1:
        return data
    for entry in (data.get("skills") or {}).values():
        entry.setdefault("kind", "skill")
        decisions = entry.setdefault("decisions", [])
        for a in entry.pop("accepted", []):
            decisions.append({"action": "accept", "hash": a.get("hash"),
                              "reason": a.get("reason", ""), "at": a.get("at")})
        for digest in entry.pop("rejected", []):
            decisions.append({"action": "reject", "hash": digest})
        entry.pop("accepted_findings", None)
        if not decisions:
            entry.pop("decisions")
    data["version"] = VERSION
    return data


def load(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return empty()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DossierError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") not in (1, VERSION):
        raise DossierError(f"{path}: unknown origins format "
                           f"{data.get('version') if isinstance(data, dict) else data!r}")
    data = migrate(data)
    data.setdefault("skills", {})
    data.setdefault("sources", {})
    return data


def save(path: Path, data: dict):
    path = Path(path)
    backup = path.with_name(path.name + ".v1.bak")
    if path.exists() and not backup.exists():
        try:
            on_disk = json.loads(path.read_text(encoding="utf-8")).get("version")
        except (OSError, json.JSONDecodeError, AttributeError):
            on_disk = None
        if on_disk == 1:
            shutil.copy2(path, backup)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# -- files and approvals ------------------------------------------------------------

def file_hashes(root: Path) -> dict:
    """{relative posix path: SHA-256} of every file below `root`."""
    base = Path(root).resolve()
    return {p.relative_to(base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(base.rglob("*")) if p.is_file() and not p.is_symlink()}


def approved(entry: dict) -> frozenset:
    return frozenset(entry.get("approved") or {})


def record(entry: dict, action: str, digest: str, reason: str = "", *, at: str):
    item = {"action": action, "hash": digest}
    if reason or action == "accept":
        item["reason"] = reason
    item["at"] = at
    entry.setdefault("decisions", []).append(item)


def approve(entry: dict, root: Path, digest: str, reason: str, *, at: str):
    """Approve every file of the version `digest` stored at `root`. The caller
    has verified that `root` is exactly that version."""
    store = entry.setdefault("approved", {})
    for rel, sha in file_hashes(root).items():
        store.setdefault(sha, {"file": rel, "version": digest, "reason": reason, "at": at})
    record(entry, "accept", digest, reason, at=at)


def rejected(entry: dict, digest: str) -> bool:
    return any(d.get("action") == "reject" and d.get("hash") == digest
               for d in entry.get("decisions") or [])


# -- triage summary -----------------------------------------------------------------

def summary(result: "_triage.Result") -> dict:
    """What the review file keeps of a triage: counts, which checks cleared what,
    and every finding that was not cleared."""
    return {
        "verdict": result.verdict,
        "counts": dict(Counter(d.status for d in result.dispositions)),
        "cleared_by": dict(Counter(d.check for d in result.dispositions
                                   if d.status == _triage.CLEARED)),
        "findings": [{"rule": d.finding.rule, "severity": d.finding.severity,
                      "file": d.finding.evidence_file or d.finding.file,
                      "line": d.finding.line, "status": d.status, "reason": d.reason}
                     for d in result.dispositions if d.status != _triage.CLEARED],
    }
