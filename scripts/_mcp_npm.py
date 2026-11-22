"""Locked npm MCP installs (#48, A2).

The server gets its own directory with an exact top-level pin in package.json.
npm resolves the lockfile without running scripts and without versions younger
than seven days; the lockfile is checked as a whole (advisories, age, the
scanned tarball as top-level package) before `npm ci` builds the tree. Only
then is the tree swapped in. The agent starts `node <bin>` from that tree,
never npx.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import _lockcheck
from _mcp_locked import (Installed, Refused, Runner, check_name, check_secrets, replace_tree,
                         staged, stale_leftovers, write_metadata)

REGISTRY = "https://registry.npmjs.org/"
MIN_NPM = (11, 10)  # first npm with --min-release-age (npm/cli#8965, v11.10.0)
PACKAGE_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
BIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
YOUNG_CODES = ("ETARGET", "ENOVERSIONS")
LOCKFILE = "package-lock.json"


def check_package(package: str) -> str:
    if not isinstance(package, str) or len(package) > 214 or not PACKAGE_RE.fullmatch(package):
        raise Refused(2, f"invalid npm package name {package!r}")
    return package


def check_version(version: str, what: str = "version") -> str:
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise Refused(2, f"invalid {what} {version!r}: an exact version like 1.2.3 is required")
    return version


def _validate(name, package, version, overrides, override_reason, bin_name, secrets):
    check_name(name)
    check_package(package)
    check_version(version)
    for dep, wanted in overrides.items():
        check_package(dep)
        check_version(wanted, f"override version for {dep}")
    if overrides and not (override_reason or "").strip():
        raise Refused(2, "--override needs --override-reason (why the pinned tree is changed)")
    if bin_name is not None and not BIN_RE.fullmatch(bin_name):
        raise Refused(2, f"invalid --bin {bin_name!r}")
    check_secrets(secrets)


def _npm_version(run: Runner, npm: str, cwd: Path) -> None:
    code, out = run([npm, "--version"], cwd)
    match = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", out or "")
    if code != 0 or not match:
        raise Refused(2, f"cannot read the npm version ({(out or '').strip()[:200]!r})")
    found = tuple(int(part) for part in match.groups()[:2])
    if found < MIN_NPM:
        raise Refused(2, f"npm {match.group(0).strip()} is too old: locked MCP installs need npm "
                         f"{MIN_NPM[0]}.{MIN_NPM[1]} or newer (--min-release-age)")


def _tail(text: str, lines: int = 12) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _manifest(name: str, package: str, version: str, overrides: dict,
              override_reason: str | None) -> dict:
    data = {"name": f"mcp-{name.lower()}", "private": True,
            "description": f"Locked tree for the MCP server {name} (agent-guard)",
            "dependencies": {package: version}}
    if overrides:
        data["overrides"] = dict(overrides)
        data["_overrides"] = override_reason.strip()
    return data


def _inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return path != base


def _bin_path(stage: Path, package: str, version: str, bin_name: str | None) -> Path:
    pkg_dir = stage.joinpath("node_modules", *package.split("/"))
    try:
        meta = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(2, f"npm ci did not install {package}: {exc}")
    if meta.get("name") != package or meta.get("version") != version:
        raise Refused(2, f"npm ci installed {meta.get('name')!r} {meta.get('version')!r}, "
                         f"not the pinned {package} {version}")
    bins = meta.get("bin")
    short = package.rsplit("/", 1)[-1]
    if isinstance(bins, str):
        bins = {short: bins}
    if not isinstance(bins, dict) or not bins:
        raise Refused(2, f"{package} declares no executable (bin) to start")
    if bin_name is not None:
        if bin_name not in bins:
            raise Refused(2, f"{package} has no bin {bin_name!r}; it has {', '.join(sorted(bins))}")
        rel = bins[bin_name]
    elif short in bins:
        rel = bins[short]
    elif len(bins) == 1:
        rel = next(iter(bins.values()))
    else:
        raise Refused(2, f"{package} has several bins ({', '.join(sorted(bins))}); "
                         "choose one with --bin")
    if not isinstance(rel, str) or not rel.strip():
        raise Refused(2, f"{package}: bin entry is not a path")
    base = pkg_dir.resolve()
    path = (pkg_dir / rel).resolve()
    if not _inside(path, base) or not path.is_file():
        raise Refused(2, f"{package}: bin {rel!r} is not a file inside the package")
    return path


def npm_install(*, name: str, package: str, version: str, overrides: dict,
                override_reason: str | None, bin_name: str | None, secrets: tuple,
                root: Path, receipt, accepted: dict | None, run: Runner,
                check=_lockcheck.check, which=shutil.which, dry: bool = False) -> Installed:
    """Build, check and swap in the locked tree of one npm MCP server."""
    overrides = dict(overrides or {})
    _validate(name, package, version, overrides, override_reason, bin_name, secrets)
    if (receipt.kind, receipt.package, receipt.version) != ("npm", package, version):
        raise Refused(2, f"the scan receipt is for {receipt.package} {receipt.version}, "
                         f"not {package} {version}")
    npm, node = which("npm"), which("node")
    if not npm or not node:
        raise Refused(2, "npm and node must be on PATH for a locked npm MCP install")
    root = Path(root)
    if dry:
        target = Path(root).absolute() / name
        print(f"  [DRY] would build {target} from {package}@{version} "
              f"(npm install --package-lock-only --ignore-scripts --min-release-age=7, "
              f"lockfile check, npm ci --ignore-scripts)")
        return Installed(name=name, kind="npm", package=package, requested=version,
                         command=node, args=[str(target / "node_modules" / package / "<bin>")],
                         tree=target, lockfile_sha256="", overrides=overrides,
                         override_reason=override_reason, secrets=tuple(secrets),
                         accepted=accepted)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    with staged(root, name) as stage:
        _npm_version(run, npm, stage)
        manifest = _manifest(name, package, version, overrides, override_reason)
        (stage / "package.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                            encoding="utf-8")
        (stage / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        code, out = run([npm, "install", "--package-lock-only", "--ignore-scripts",
                         "--min-release-age=7", f"--registry={REGISTRY}", "--no-audit",
                         "--no-fund"], stage)
        if code != 0:
            if any(c in (out or "") for c in YOUNG_CODES):
                raise Refused(2, f"npm finds no {package}@{version} (or a dependency) older "
                                 f"than 7 days: it is younger than 7 days; try again later\n"
                                 f"{_tail(out)}")
            raise Refused(2, f"npm could not resolve the lockfile:\n{_tail(out)}")
        lock_path = stage / LOCKFILE
        try:
            lock_bytes = lock_path.read_bytes()
            lock = json.loads(lock_bytes)
            entries = _lockcheck.npm_lock_entries(lock)
            integrity = _lockcheck.npm_top_level(lock, package, version, overrides)
        except (OSError, ValueError) as exc:
            raise Refused(2, f"cannot read {LOCKFILE}: {exc}")
        except _lockcheck.NoVerdict as exc:
            raise Refused(2, f"NO VERDICT -- {exc}")
        if integrity != receipt.integrity:
            raise Refused(2, f"the lockfile resolves {package}@{version} to a tarball other than "
                             f"the scanned one ({integrity} vs {receipt.integrity}); scan again")
        result = check(entries)
        for line in result.lines:
            print(f"  {line}")
        if result.code:
            raise Refused(result.code, f"lockfile check for {package}@{version} failed "
                                       "(see above); the installed tree is unchanged")
        code, out = run([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                         f"--registry={REGISTRY}"], stage)
        if code != 0:
            raise Refused(2, f"npm ci failed:\n{_tail(out)}")
        if lock_path.read_bytes() != lock_bytes:
            raise Refused(2, f"npm ci changed {LOCKFILE}; the checked tree is not what was built")
        bin_path = _bin_path(stage, package, version, bin_name)
        installed = Installed(
            name=name, kind="npm", package=package, requested=version, command=node,
            args=[str(target / bin_path.relative_to(stage.resolve()))], tree=target,
            lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides=overrides,
            override_reason=override_reason.strip() if overrides else None,
            secrets=tuple(secrets), accepted=accepted)
        write_metadata(stage, installed)
        replace_tree(stage, target)
    return installed
