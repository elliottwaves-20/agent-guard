"""Receipts: the scan verdict a locked MCP install requires (#48, K1).

scan_url.py writes one receipt per judged package version into
`<install_dir>/.receipts/`. The locked installers refuse to run without a
matching SAFE receipt; a BLOCK receipt counts only with an explicit reason
(`--accept`), which holds for exactly that version. A scan without a verdict
writes no receipt, so it can never be accepted.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from _mcp_locked import NeedsScan, Refused, normalize_pypi, registry_scan_command

KINDS = {"npm", "pypi", "git"}
VERDICTS = {"SAFE", "BLOCK"}
_KEY_RE = re.compile(r"[A-Za-z0-9._-]+")


@dataclass(frozen=True)
class Receipt:
    kind: str
    package: str
    version: str
    archive_sha256: str
    integrity: str
    verdict: str
    at: str
    agent_guard: str


def identity(kind: str, package: str) -> str:
    """The package as receipts compare it: PyPI PEP 503, Git owner/repo in lower case."""
    if kind == "pypi":
        return normalize_pypi(package)
    if kind == "git":
        repo, sep, subdir = package.partition("#")
        return repo.lower() + (f"#{subdir}" if sep else "")
    return package


def _key(kind: str, package: str) -> str:
    ident = identity(kind, package)
    if kind == "npm":
        ident = ident.lstrip("@")
    key = ident.replace("#", "/").replace("/", "__")
    if not _KEY_RE.fullmatch(key):
        raise Refused(2, f"cannot file a receipt for the package name {package!r}")
    return key


def receipt_path(root: Path, kind: str, package: str, version: str) -> Path:
    if kind not in KINDS:
        raise Refused(2, f"unknown package kind {kind!r}")
    if not _KEY_RE.fullmatch(version):
        raise Refused(2, f"cannot file a receipt for the version {version!r}")
    return root / ".receipts" / f"{kind}-{_key(kind, package)}-{version}.json"


def write_receipt(root: Path, receipt: Receipt) -> Path:
    """Write (or replace) the receipt atomically."""
    path = receipt_path(root, receipt.kind, receipt.package, receipt.version)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(asdict(receipt), indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def _scan_hint(kind: str, package: str, version: str) -> str:
    if kind in ("npm", "pypi"):
        return registry_scan_command(kind, package, version)
    # A Git receipt covers the whole repository (F1). Its root alone may be
    # detected as a skill collection, which writes no receipt, so name the kind.
    return f"python scripts/scan_url.py https://github.com/{package}/tree/{version} --kind mcp-source"


def _load(path: Path) -> Receipt:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {f.name for f in fields(Receipt)}:
            raise ValueError("unexpected fields")
        if not all(isinstance(v, str) for v in data.values()):
            raise ValueError("non-text field")
        return Receipt(**data)
    except (OSError, ValueError, TypeError) as exc:
        raise Refused(2, f"unreadable receipt {path}: {exc}; scan again") from exc


def require_receipt(root: Path, kind: str, package: str, version: str,
                    accept: str | None) -> tuple:
    """(receipt, accepted) for exactly this package version, or Refused."""
    path = receipt_path(root, kind, package, version)
    if not path.is_file():
        prefix = f"no scan verdict for {package} {version}; scan first: "
        if kind in ("npm", "pypi"):
            raise NeedsScan([{"kind": kind, "package": package, "version": version}],
                            prefix=prefix)
        raise Refused(2, prefix + _scan_hint(kind, package, version))
    receipt = _load(path)
    if (receipt.kind != kind or identity(kind, receipt.package) != identity(kind, package)
            or receipt.version != version or receipt.verdict not in VERDICTS):
        raise Refused(2, f"receipt {path} does not match {package} {version}; scan again: "
                         f"{_scan_hint(kind, package, version)}")
    if receipt.verdict == "SAFE":
        if accept is not None:
            print("  note: --accept is ignored, the scan verdict is SAFE")
        return receipt, None
    if accept is None:
        raise Refused(1, f"the scan verdict for {package} {version} is BLOCK; install it only "
                         "after reviewing the findings, with --accept \"<reason>\"")
    if not accept.strip():
        raise Refused(2, "--accept needs a reason")
    accepted = {"version": version, "at": dt.date.today().isoformat(), "grund": accept.strip()}
    return receipt, accepted
