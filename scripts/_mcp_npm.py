"""Locked npm MCP installs (#48, A2).

The server gets its own directory with an exact top-level pin in package.json.
npm resolves the lockfile without running scripts and enforces the configured
minimum age. The lockfile is checked as a whole (advisories, age, the
scanned tarball as top-level package) before `npm ci` builds the tree. Only
then is the tree swapped in. The agent starts `node <bin>` from that tree,
never npx.

Two rules let a package be younger than the waiting period, both judged by
_fastlane: the trusted period for the top package (S1, same source repository
as the installed version) and a scanned smallest security fix for any entry
(fast lane). The age limit is never lifted for the whole tree: npm gets an
exemption only for the named packages.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sys
import urllib.parse
from pathlib import Path

import _exe
import _fastlane
import _lockcheck
from _mcp_locked import (METADATA, Installed, NeedsScan, Refused, Runner, check_name,
                         check_secrets, print_dry_outcome, replace_tree, staged, stale_leftovers,
                         work_stage, write_metadata)

REGISTRY = "https://registry.npmjs.org/"
MIN_NPM = (11, 10)  # first npm with --min-release-age (npm/cli#8965, v11.10.0)
MIN_NPM_FAST_LANE = (11, 17)  # first npm with --min-release-age-exclude (npm/cli#9534, v11.17.0)
FAST_LANE_UNAVAILABLE = "fast lane not available for npm trees on this npm"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
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


def validate_overrides(overrides: dict, override_reason: str | None) -> None:
    for dep, wanted in overrides.items():
        check_package(dep)
        check_version(wanted, f"override version for {dep}")
    if overrides and not (override_reason or "").strip():
        raise Refused(2, "--override needs --override-reason (why the pinned tree is changed)")


def _validate(name, package, version, overrides, override_reason, bin_name, secrets):
    check_name(name)
    check_package(package)
    check_version(version)
    validate_overrides(overrides, override_reason)
    if bin_name is not None and not BIN_RE.fullmatch(bin_name):
        raise Refused(2, f"invalid --bin {bin_name!r}")
    check_secrets(secrets)


def _npm_version(run: Runner, npm: str, cwd: Path) -> tuple:
    """(major, minor) of npm; refuses an npm without --min-release-age."""
    code, out = run([npm, "--version"], cwd)
    match = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", out or "")
    if code != 0 or not match:
        raise Refused(2, f"cannot read the npm version ({(out or '').strip()[:200]!r})")
    found = tuple(int(part) for part in match.groups()[:2])
    if found < MIN_NPM:
        raise Refused(2, f"npm {match.group(0).strip()} is too old: locked MCP installs need npm "
                         f"{MIN_NPM[0]}.{MIN_NPM[1]} or newer (--min-release-age)")
    return found


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


# ── Registry facts for the waiting periods ───────────────────────────────────

def _published(name: str, version: str, fetch) -> dt.datetime:
    """Publish time of one version from the registry document; anything odd fails the lookup."""
    try:
        body, _ = fetch(_lockcheck.NPM_REGISTRY_URL + urllib.parse.quote(name, safe="@"))
        stamp = dt.datetime.fromisoformat(body["time"][version].replace("Z", "+00:00"))
    except _lockcheck.LookupFailed:
        raise
    except Exception as exc:
        raise _lockcheck.LookupFailed(
            f"cannot read the publish time of {name}@{version}: {type(exc).__name__}") from exc
    if stamp.tzinfo is None:
        raise _lockcheck.LookupFailed(f"publish time of {name}@{version} has no timezone")
    return stamp


def _pending_overrides(overrides: dict, policy, fetch, now) -> dict:
    """User overrides younger than the waiting period: name to (version, day it is old enough).

    They are not resolved into the tree; they count only as the chosen fix of an advisory."""
    pending = {}
    for dep, wanted in overrides.items():
        try:
            published = _published(dep, wanted, fetch)
        except _lockcheck.LookupFailed as exc:
            raise Refused(2, f"NO VERDICT -- {exc}")
        if published > now - dt.timedelta(days=policy.min_age_days):
            ready = (published + dt.timedelta(days=policy.min_age_days)).date().isoformat()
            pending[dep] = (wanted, ready)
    return pending


def _predecessor(target: Path, package: str, version: str):
    """(version, lockfile bytes) of the installed tree of this package, else (None, None).

    Only a tree this tool wrote counts: metadata of the current format for the same
    package and a lockfile that is still the one recorded."""
    try:
        meta = json.loads((target / METADATA).read_text(encoding="utf-8"))
        lock_bytes = (target / LOCKFILE).read_bytes()
    except (OSError, ValueError):
        return None, None
    if (not isinstance(meta, dict) or meta.get("kind") != "npm" or meta.get("package") != package
            or "tier" not in meta or not isinstance(meta.get("version"), str)
            or not VERSION_RE.fullmatch(meta["version"]) or meta["version"] == version
            or meta.get("lockfile_sha256") != hashlib.sha256(lock_bytes).hexdigest()):
        return None, None
    return meta["version"], lock_bytes


def _trusted_period_applies(package, version, old_version, policy, fetch, now) -> bool:
    """S1: the top package is younger than the waiting period and comes from the same repo."""
    try:
        published = _published(package, version, fetch)
        if published <= now - dt.timedelta(days=policy.min_age_days):
            return False
        return _fastlane.continuity("npm", package, old_version, version, fetch) == "same"
    except Exception:  # any doubt falls back to the ordinary waiting period
        return False


# ── Resolution and verification ──────────────────────────────────────────────

def _resolve(run, npm, stage, *, name, package, version, overrides, reason, seed, excludes,
             min_age_days):
    """Write the manifest, let npm resolve the lockfile and read it back."""
    for dep in (*overrides, *excludes):
        check_package(dep)
    manifest = _manifest(name, package, version, overrides, reason)
    (stage / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (stage / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    if seed is not None:
        (stage / LOCKFILE).write_bytes(seed)
    flags = [f"--min-release-age={min_age_days}",
             *[f"--min-release-age-exclude={dep}" for dep in excludes]]
    code, out = run([npm, "install", "--package-lock-only", "--ignore-scripts", *flags,
                     f"--registry={REGISTRY}", "--no-audit", "--no-fund"], stage)
    if code != 0:
        if any(c in (out or "") for c in YOUNG_CODES):
            raise Refused(2, f"npm finds no {package}@{version} (or a dependency) older "
                             f"than {min_age_days} days: it is younger than {min_age_days} "
                             f"days; try again later\n{_tail(out)}")
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
    return lock_path, lock_bytes, entries, integrity


def _require_scanned_top(integrity: str, receipt, package: str, version: str) -> None:
    if integrity != receipt.integrity:
        raise Refused(2, f"the lockfile resolves {package}@{version} to a tarball other than "
                         f"the scanned one ({integrity} vs {receipt.integrity}); scan again")


def _audit_signatures(run, npm, stage, required: list) -> None:
    """npm audit signatures after npm ci: nothing invalid or missing, and every required
    package@version carries a verified SLSA provenance attestation. Anything else is no verdict."""
    code, out = run([npm, "audit", "signatures", "--json", "--include-attestations",
                     f"--registry={REGISTRY}"], stage)
    if code != 0:
        raise Refused(2, f"npm audit signatures failed (exit {code}):\n{_tail(out)}")
    try:
        # The runner joins stdout and stderr: the JSON on stdout comes first, npm warnings after it.
        data, _ = json.JSONDecoder().raw_decode((out or "").lstrip())
    except ValueError:
        raise Refused(2, f"npm audit signatures gave unreadable output:\n{_tail(out)}")
    if not isinstance(data, dict) or any(
            not isinstance(data.get(key), list) for key in ("invalid", "missing", "verified")):
        raise Refused(2, "npm audit signatures gave an unexpected answer (no invalid, "
                         "missing and verified lists)")
    if data["invalid"] or data["missing"]:
        raise Refused(2, f"npm audit signatures reports {len(data['invalid'])} invalid and "
                         f"{len(data['missing'])} missing signature(s)")
    attested = set()
    for row in data["verified"]:
        try:
            if row["attestations"]["provenance"]["predicateType"] == SLSA_PROVENANCE:
                attested.add((row["name"], row["version"]))
        except (KeyError, TypeError):
            continue
    for package, version in required:
        if (package, version) not in attested:
            raise Refused(2, f"npm audit signatures verified no provenance attestation for "
                             f"{package}@{version}")


def _check_rebuilt(entries, fixes: dict, check, policy, fetch, now, extra_limits: dict) -> None:
    """The rebuilt tree passes the same check; only the fix entries skip the waiting period."""
    limits = {_lockcheck.entry_key(e): 0 for e in entries if e.name in fixes}
    limits.update(extra_limits)
    result = check(entries, now=now, fetch=fetch, min_age_days=policy.min_age_days,
                   age_limits=limits)
    for line in result.lines:
        print(f"  {line}")
    if result.code:
        raise Refused(result.code, "the rebuilt tree fails the lockfile check (see above); "
                                   "the installed tree is unchanged")
    if result.failures:
        raise Refused(2, "NO VERDICT -- a lookup of the rebuilt tree failed (see above)")


def _finish(run, npm, node, stage, target, *, name, package, version, bin_name, lock_path,
            lock_bytes, overrides, override_reason, secrets, accepted, tier, fast_lane,
            audit_required):  # audit_required None: no audit; a list: audit, these must be attested
    """npm ci, unchanged lockfile, signature audit when needed, then the swap."""
    code, out = run([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                     f"--registry={REGISTRY}"], stage)
    if code != 0:
        raise Refused(2, f"npm ci failed:\n{_tail(out)}")
    if lock_path.read_bytes() != lock_bytes:
        raise Refused(2, f"npm ci changed {LOCKFILE}; the checked tree is not what was built")
    if audit_required is not None:
        _audit_signatures(run, npm, stage, audit_required)
    bin_path = _bin_path(stage, package, version, bin_name)
    installed = Installed(
        name=name, kind="npm", package=package, requested=version, command=node,
        args=[str(target / bin_path.relative_to(stage.resolve()))], tree=target,
        lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides=overrides,
        override_reason=override_reason.strip() if overrides else None,
        secrets=tuple(secrets), accepted=accepted, tier=tier, fast_lane=fast_lane)
    write_metadata(stage, installed)
    replace_tree(stage, target)
    return installed


def _rebuild_with_fixes(run, npm, node, root, target, verdict, *, name, package, version, receipt,
                        applied, override_reason, bin_name, secrets, accepted, tier, seed, check,
                        policy, fetch, now):
    """Second tree: the checked lockfile as seed, the smallest scanned fixes pinned."""
    fixes = verdict.fixes
    top_fix = fixes.get(package)
    top_version = top_fix[0] if top_fix else version
    top_receipt = top_fix[1] if top_fix else receipt
    overrides = {**applied, **{dep: fix[0] for dep, fix in fixes.items() if dep != package}}
    ids = sorted({i for fix in fixes.values() for i in fix[2]["advisories"]})
    text = "agent-guard fast lane: " + ", ".join(ids)
    user_reason = (override_reason or "").strip()
    reason = f"{user_reason}; {text}" if user_reason else text
    excludes = list(dict.fromkeys([*fixes, *([package] if tier == "s1" else [])]))
    with staged(root, name) as stage:
        lock_path, lock_bytes, entries, integrity = _resolve(
            run, npm, stage, name=name, package=package, version=top_version,
            overrides=overrides, reason=reason, seed=seed, excludes=excludes,
            min_age_days=policy.min_age_days)
        _require_scanned_top(integrity, top_receipt, package, top_version)
        for dep, (fix_version, fix_receipt, _) in fixes.items():
            found = [e for e in entries if e.name == dep]
            if not found or any(e.version != fix_version or e.integrity != fix_receipt.integrity
                                for e in found):
                raise Refused(2, f"the rebuilt lockfile does not hold exactly the scanned "
                                 f"{dep}@{fix_version}; scan again")
        s1_top = tier == "s1" and package not in fixes
        extra = ({_lockcheck.entry_key(_lockcheck.Entry("npm", package, version)):
                  policy.trusted_days} if s1_top else {})
        _check_rebuilt(entries, fixes, check, policy, fetch, now, extra)
        fast_lane = [{"package": dep, "from": rec["installed"], "to": fix_version,
                      "advisories": rec["advisories"], "repo": rec["repo"],
                      "receipt_integrity": fix_receipt.integrity, "tier": rec["tier"]}
                     for dep, (fix_version, fix_receipt, rec) in fixes.items()]
        required = [(dep, fix[0]) for dep, fix in fixes.items() if fix[2]["tier"] == "fast_lane"]
        if s1_top:
            required.append((package, version))
        installed = _finish(
            run, npm, node, stage, target, name=name, package=package, version=top_version,
            bin_name=bin_name, lock_path=lock_path, lock_bytes=lock_bytes, overrides=overrides,
            override_reason=reason, secrets=secrets, accepted=accepted,
            tier="s1" if s1_top else "s2", fast_lane=fast_lane, audit_required=required)
    for item in fast_lane:
        print(f"fast lane: {item['package']} {item['from']} -> {item['to']} "
              f"({', '.join(item['advisories'])}, provenance {item['repo']}, "
              f"receipt {item['receipt_integrity']})", file=sys.stderr)
    return installed


def _dry_result(verdict, entries, node, target, *, name, package, version, lock_bytes, overrides,
                override_reason, secrets, accepted, tier) -> Installed:
    """End of a dry run after the lockfile check: say what the install would do next."""
    print_dry_outcome(verdict, entries)
    print(f"  [DRY] would run npm ci --ignore-scripts and swap the tree in at {target}")
    return Installed(name=name, kind="npm", package=package, requested=version, command=node,
                     args=[str(target / "node_modules" / package / "<bin>")], tree=target,
                     lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides=overrides,
                     override_reason=override_reason.strip() if overrides else None,
                     secrets=tuple(secrets), accepted=accepted, tier=tier)


def npm_install(*, name: str, package: str, version: str, overrides: dict,
                override_reason: str | None, bin_name: str | None, secrets: tuple,
                root: Path, receipt, accepted: dict | None, run: Runner,
                check=_lockcheck.check, which=_exe.which, dry: bool = False,
                policy: _fastlane.Policy = _fastlane.Policy(),
                fetch=_lockcheck.http_fetch, now: dt.datetime | None = None) -> Installed:
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
    min_age_days = policy.min_age_days
    if not dry:
        root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    now = now or dt.datetime.now(dt.timezone.utc)
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    with work_stage(root, name, dry) as stage:
        can_exclude = _npm_version(run, npm, stage) >= MIN_NPM_FAST_LANE
        pending = _pending_overrides(overrides, policy, fetch, now) if overrides else {}
        applied = {dep: wanted for dep, wanted in overrides.items() if dep not in pending}
        seed, tier, age_limits = None, "s2", None
        old_version, old_lock = _predecessor(root / name, package, version)
        if (old_version is not None and can_exclude and policy.trusted_days < min_age_days
                and _trusted_period_applies(package, version, old_version, policy, fetch, now)):
            seed, tier = old_lock, "s1"
            age_limits = {_lockcheck.entry_key(_lockcheck.Entry("npm", package, version)):
                          policy.trusted_days}
        lock_path, lock_bytes, entries, integrity = _resolve(
            run, npm, stage, name=name, package=package, version=version, overrides=applied,
            reason=override_reason, seed=seed, excludes=[package] if tier == "s1" else [],
            min_age_days=min_age_days)
        _require_scanned_top(integrity, receipt, package, version)
        verdict = _fastlane.judge_tree(
            entries, {}, receipts_root=root, kind="npm", user_overrides=overrides,
            policy=policy, fetch=fetch, now=now, age_limits=age_limits, check=check,
            unavailable=None if can_exclude else FAST_LANE_UNAVAILABLE)
        for line in verdict.lines:
            print(f"  {line}")
        if verdict.code:
            if verdict.needs_scan and verdict.code == 2:
                raise NeedsScan(verdict.needs_scan, prefix="fast lane needs scans first:\n")
            detail = "".join(f"\n{note}" for note in verdict.notes)
            raise Refused(verdict.code, f"lockfile check for {package}@{version} failed "
                                        f"(see above); the installed tree is unchanged{detail}")
        for dep, (wanted, ready) in pending.items():
            if verdict.fixes.get(dep, (None,))[0] != wanted:
                raise Refused(2, f"override {dep}@{wanted} is younger than {min_age_days} days "
                                 f"and fixes no advisory; wait until {ready}")
        if dry:
            return _dry_result(verdict, entries, node, target, name=name, package=package,
                               version=version, lock_bytes=lock_bytes, overrides=applied,
                               override_reason=override_reason, secrets=secrets,
                               accepted=accepted, tier=tier)
        if verdict.fixes:
            return _rebuild_with_fixes(
                run, npm, node, root, target, verdict, name=name, package=package,
                version=version, receipt=receipt, applied=applied,
                override_reason=override_reason, bin_name=bin_name, secrets=secrets,
                accepted=accepted, tier=tier, seed=lock_bytes, check=check, policy=policy,
                fetch=fetch, now=now)
        return _finish(
            run, npm, node, stage, target, name=name, package=package, version=version,
            bin_name=bin_name, lock_path=lock_path, lock_bytes=lock_bytes, overrides=applied,
            override_reason=override_reason, secrets=secrets, accepted=accepted, tier=tier,
            fast_lane=[], audit_required=[(package, version)] if tier == "s1" else None)
