"""Locked PyPI MCP installs through uv (#48, A3).

The server gets its own uv project with an exact top-level pin and a
configurable age window. `uv lock --no-build` resolves the whole tree without running
any build; the lockfile is checked as a whole, and the top-level package must
lock exactly one pure wheel -- the file scan_url.py scanned. The tree is swapped
in before `uv sync`, because the starters in .venv hold absolute paths; a
failing sync puts the previous tree back. The agent starts
`uv run --project <tree> --locked --no-dev <entry point>`, never uvx.
"""
from __future__ import annotations

import configparser
import datetime as dt
import hashlib
import re
import sys
import urllib.parse
from pathlib import Path

import _exe
import _fastlane
import _lockcheck
from _mcp_locked import (ENTRY_RE, Installed, NeedsScan, Refused, Runner, check_name,
                         check_secrets, normalize_pypi, print_dry_clean, print_dry_outcome,
                         replace_tree,
                         require_python_311, staged, stale_leftovers, work_stage, write_metadata)

INDEX = "https://pypi.org/simple"
PYPI_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?")
# PEP 440 public version, no range, no local part, no spaces.
PEP440_RE = re.compile(r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
                       r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?", re.IGNORECASE)
LOCKFILE = "uv.lock"


def check_package(package: str) -> str:
    if not isinstance(package, str) or not PYPI_NAME_RE.fullmatch(package):
        raise Refused(2, f"invalid PyPI package name {package!r}")
    return package


def check_version(version: str) -> str:
    if not isinstance(version, str) or not PEP440_RE.fullmatch(version):
        raise Refused(2, f"invalid version {version!r}: an exact PEP 440 version like 1.2.3 "
                         "is required")
    return version


def _tail(text: str, lines: int = 12) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def project_name(name: str) -> str:
    return normalize_pypi(f"mcp-{name}")


def _pyproject(name: str, dependency: str, min_age_days: int, extra: str = "") -> str:
    return (f'[project]\nname = "{project_name(name)}"\nversion = "0.0.0"\n'
            f'description = "Locked tree for the MCP server {name} (agent-guard)"\n'
            f'requires-python = ">=3.10"\ndependencies = ["{dependency}"]\n\n'
            f'[tool.uv]\npackage = false\nexclude-newer = "{min_age_days} days"\n{extra}')


def _site_packages(venv: Path) -> list:
    found = [venv / "Lib" / "site-packages"]
    found += sorted((venv / "lib").glob("python*/site-packages")) if (venv / "lib").is_dir() else []
    return [p for p in found if p.is_dir()]


def dist_info(venv: Path, package: str) -> tuple:
    """(dist-info directory, installed version) of `package` in the venv."""
    wanted = normalize_pypi(package)
    for site in _site_packages(venv):
        for info in site.glob("*.dist-info"):
            dist, sep, version = info.name[:-len(".dist-info")].partition("-")
            if sep and normalize_pypi(dist) == wanted:
                return info, version
    raise Refused(2, f"uv sync did not install {package}")


def console_scripts(venv: Path, package: str) -> dict:
    """console_scripts of the installed distribution of `package` (PEP 503 names)."""
    info, _version = dist_info(venv, package)
    parser = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    parser.optionxform = str
    path = info / "entry_points.txt"
    if path.is_file():
        try:
            parser.read_string(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, configparser.Error) as exc:
            raise Refused(2, f"cannot read {path}: {exc}")
    if not parser.has_section("console_scripts"):
        return {}
    return dict(parser.items("console_scripts"))


def entry_point(scripts: dict, package: str, executable: str | None) -> str:
    if executable is not None:
        if executable not in scripts:
            raise Refused(2, f"{package} has no executable {executable!r}; it has "
                             f"{', '.join(sorted(scripts)) or 'none'}")
        return executable
    same = [s for s in scripts if normalize_pypi(s) == normalize_pypi(package)]
    if len(same) == 1:
        return same[0]
    if len(scripts) == 1:
        return next(iter(scripts))
    if not scripts:
        raise Refused(2, f"{package} declares no executable (console_scripts); "
                         "use mcp-git --module or another source")
    raise Refused(2, f"{package} has several executables ({', '.join(sorted(scripts))}); "
                     "choose one with --executable")


def single_pure_wheel(entry: _lockcheck.Entry, sha256: str, what: str) -> None:
    """The entry must lock exactly one wheel, a pure one (*-none-any.whl), and it must be
    the file with this SHA-256 (the scanned one). Anything else is Refused(2)."""
    where = "" if what == "top-level package" else f" ({what})"
    wheels = [(f, h) for f, h in entry.files if f.endswith(".whl")]
    if len(wheels) != 1 or not wheels[0][0].endswith("-none-any.whl"):
        names = ", ".join(f for f, _ in wheels) or "no wheel"
        raise Refused(2, f"NO VERDICT -- {entry.name} {entry.version} must lock exactly one pure "
                         f"wheel (*-none-any.whl) to install the scanned file; it locks "
                         f"{names}{where}")
    if wheels[0][1] != sha256:
        raise Refused(2, f"the locked wheel {wheels[0][0]} is not the scanned file "
                         f"(sha256 {wheels[0][1]} vs {sha256}); scan again{where}")


def _top_level_wheel(entries: list, package: str, version: str, receipt) -> None:
    """The top-level package must lock exactly one pure wheel: the scanned file."""
    tops = [e for e in entries if normalize_pypi(e.name) == normalize_pypi(package)]
    if len(tops) != 1 or tops[0].version != version:
        found = ", ".join(e.version for e in tops) or "nothing"
        raise Refused(2, f"NO VERDICT -- uv.lock resolves {package} to {found}, "
                         f"not the pinned {version}")
    single_pure_wheel(tops[0], receipt.archive_sha256, "top-level package")


def validate_overrides(overrides, override_reason) -> dict:
    """User overrides by PEP 503 name: exact PEP 440 versions, each name once, a reason."""
    checked = {}
    for dep, wanted in (overrides or {}).items():
        check_package(dep)
        if not isinstance(wanted, str) or not PEP440_RE.fullmatch(wanted):
            raise Refused(2, f"invalid override version {wanted!r} for {dep}: an exact PEP 440 "
                             "version like 1.2.3 is required")
        key = normalize_pypi(dep)
        if key in checked:
            raise Refused(2, f"--override names {key} twice")
        checked[key] = wanted
    if checked and not (override_reason or "").strip():
        raise Refused(2, "--override needs --override-reason (why the pinned tree is changed)")
    return checked


def _uv_settings(overrides: dict, excludes: dict) -> str:
    """The [tool.uv] lines of a tree with pinned dependencies and per-package time limits."""
    for dep in (*overrides, *excludes):
        check_package(dep)
    text = ""
    if overrides:
        text += ("override-dependencies = ["
                 + ", ".join(f'"{dep}=={wanted}"' for dep, wanted in overrides.items()) + "]\n")
    if excludes:
        text += ("exclude-newer-package = { "
                 + ", ".join(f'"{dep}" = "{when}"' for dep, when in excludes.items()) + " }\n")
    return text


def _lock(run, uv, stage, *, name, package, version, overrides, excludes, min_age_days):
    """Write the project, let uv resolve without builds and read the lockfile back."""
    (stage / "pyproject.toml").write_text(
        _pyproject(name, f"{package}=={version}", min_age_days, _uv_settings(overrides, excludes)),
        encoding="utf-8")
    (stage / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    code, out = run([uv, "lock", "--no-build", "--default-index", INDEX], stage)
    if code != 0:
        raise Refused(2, f"uv could not lock {package}=={version} from {INDEX} without "
                         f"builds and without files younger than {min_age_days} days:\n"
                         f"{_tail(out)}")
    try:
        lock_bytes = (stage / LOCKFILE).read_bytes()
        entries = _lockcheck.uv_lock_entries(lock_bytes.decode("utf-8"), project_name(name))
    except (OSError, UnicodeDecodeError) as exc:
        raise Refused(2, f"cannot read {LOCKFILE}: {exc}")
    except _lockcheck.NoVerdict as exc:
        raise Refused(2, f"NO VERDICT -- {exc}")
    return lock_bytes, entries


# ── Registry facts for the waiting period of user overrides ──────────────────

def _published(name: str, version: str, fetch) -> dt.datetime:
    """Latest upload time of the files of one release; anything odd fails the lookup."""
    url = (f"{_lockcheck.PYPI_JSON_URL}{urllib.parse.quote(normalize_pypi(name), safe='')}/"
           f"{urllib.parse.quote(version, safe='')}/json")
    try:
        body, _ = fetch(url)
        stamps = [dt.datetime.fromisoformat(row["upload_time_iso_8601"].replace("Z", "+00:00"))
                  for row in body["urls"]]
    except _lockcheck.LookupFailed:
        raise
    except Exception as exc:
        raise _lockcheck.LookupFailed(
            f"cannot read the upload time of {name}=={version}: {type(exc).__name__}") from exc
    if not stamps or any(stamp.tzinfo is None for stamp in stamps):
        raise _lockcheck.LookupFailed(f"no usable upload time for {name}=={version}")
    return max(stamps)


def _pending_overrides(overrides: dict, policy, fetch, now) -> dict:
    """User overrides younger than the waiting period: name to (version, day it is old enough).

    They are not resolved into the first tree; they count only as the chosen fix of an advisory."""
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


def _check_rebuilt(entries, fixes: dict, check, policy, fetch, now) -> None:
    """The rebuilt tree passes the same check; only the fix entries skip the waiting period."""
    names = {normalize_pypi(dep) for dep in fixes}
    limits = {_lockcheck.entry_key(e): 0 for e in entries if normalize_pypi(e.name) in names}
    result = check(entries, now=now, fetch=fetch, min_age_days=policy.min_age_days,
                   age_limits=limits)
    for line in result.lines:
        print(f"  {line}")
    if result.code:
        raise Refused(result.code, "the rebuilt tree fails the lockfile check (see above); "
                                   "the installed tree is unchanged")
    if result.failures:
        raise Refused(2, "NO VERDICT -- a lookup of the rebuilt tree failed (see above)")


def _finish(run, uv, stage, target, *, name, package, version, executable, lock_bytes,
            overrides, override_reason, secrets, accepted, fast_lane) -> Installed:
    """Swap the checked tree in, then `uv sync --locked` it; a failing sync restores the old one."""
    chosen = {}

    def sync(tree: Path) -> None:
        code, out = run([uv, "sync", "--locked", "--no-dev", "--no-build"], tree)
        if code != 0:
            raise Refused(2, f"uv sync failed:\n{_tail(out)}")
        if (tree / LOCKFILE).read_bytes() != lock_bytes:
            raise Refused(2, "uv sync changed uv.lock; the checked tree is not what was built")
        _info, installed_version = dist_info(tree / ".venv", package)
        if installed_version != version:
            raise Refused(2, f"uv sync installed {package} {installed_version}, "
                             f"not the pinned {version}")
        chosen["entry"] = entry_point(console_scripts(tree / ".venv", package),
                                      package, executable)

    installed = Installed(
        name=name, kind="pypi", package=package, requested=version, command=uv, args=[],
        tree=target, lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides=overrides,
        override_reason=override_reason.strip() if overrides else None,
        secrets=tuple(secrets), accepted=accepted, fast_lane=fast_lane)
    write_metadata(stage, installed)
    replace_tree(stage, target, finish=sync)
    installed.args = ["run", "--project", str(target), "--locked", "--no-dev", chosen["entry"]]
    return installed


def _rebuild_with_fixes(run, uv, root, target, verdict, *, name, package, version, receipt,
                        applied, override_reason, executable, secrets, accepted, check, policy,
                        fetch, now) -> Installed:
    """Second tree: the smallest scanned fixes pinned, only they exempt from the waiting period."""
    fixes = verdict.fixes
    top_key = normalize_pypi(package)
    top_fix = next((fix for dep, fix in fixes.items() if normalize_pypi(dep) == top_key), None)
    top_version = top_fix[0] if top_fix else version
    top_receipt = top_fix[1] if top_fix else receipt
    overrides = {**applied, **{dep: fix[0] for dep, fix in fixes.items()
                               if normalize_pypi(dep) != top_key}}
    ids = sorted({i for fix in fixes.values() for i in fix[2]["advisories"]})
    text = "agent-guard fast lane: " + ", ".join(ids)
    user_reason = (override_reason or "").strip()
    reason = f"{user_reason}; {text}" if user_reason else text
    when = now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    excludes = {normalize_pypi(dep): when for dep in fixes}
    with staged(root, name) as stage:
        lock_bytes, entries = _lock(run, uv, stage, name=name, package=package,
                                    version=top_version, overrides=overrides, excludes=excludes,
                                    min_age_days=policy.min_age_days)
        _top_level_wheel(entries, package, top_version, top_receipt)
        for dep, (fix_version, fix_receipt, _) in fixes.items():
            found = [e for e in entries if normalize_pypi(e.name) == normalize_pypi(dep)]
            if len(found) != 1 or found[0].version != fix_version:
                raise Refused(2, f"the rebuilt lockfile does not hold exactly the scanned "
                                 f"{dep}=={fix_version}; the installed tree is unchanged")
            single_pure_wheel(found[0], fix_receipt.archive_sha256, "fast lane fix")
        _check_rebuilt(entries, fixes, check, policy, fetch, now)
        fast_lane = [{"package": dep, "from": rec["installed"], "to": fix_version,
                      "advisories": rec["advisories"], "repo": rec["repo"],
                      "receipt_sha256": fix_receipt.archive_sha256, "tier": rec["tier"]}
                     for dep, (fix_version, fix_receipt, rec) in fixes.items()]
        installed = _finish(
            run, uv, stage, target, name=name, package=package, version=top_version,
            executable=executable, lock_bytes=lock_bytes, overrides=overrides,
            override_reason=reason, secrets=secrets, accepted=accepted, fast_lane=fast_lane)
    for item in fast_lane:
        print(f"fast lane: {item['package']} {item['from']} -> {item['to']} "
              f"({', '.join(item['advisories'])}, provenance {item['repo']}, "
              f"receipt {item['receipt_sha256']})", file=sys.stderr)
    return installed


def pypi_install(*, name: str, package: str, version: str, executable: str | None,
                 secrets: tuple, root: Path, receipt, accepted: dict | None, run: Runner,
                 check=_lockcheck.check, which=_exe.which, dry: bool = False,
                 policy: _fastlane.Policy = _fastlane.Policy(), overrides: dict | None = None,
                 override_reason: str | None = None, fetch=_lockcheck.http_fetch,
                 now: dt.datetime | None = None) -> Installed:
    """Build, check and swap in the locked tree of one PyPI MCP server."""
    require_python_311()
    check_name(name)
    check_package(package)
    check_version(version)
    if executable is not None and not ENTRY_RE.fullmatch(executable):
        raise Refused(2, f"invalid --executable {executable!r}")
    check_secrets(secrets)
    overrides = validate_overrides(overrides, override_reason)
    if (receipt.kind != "pypi" or normalize_pypi(receipt.package) != normalize_pypi(package)
            or receipt.version != version):
        raise Refused(2, f"the scan receipt is for {receipt.package} {receipt.version}, "
                         f"not {package} {version}")
    uv = which("uv")
    if not uv:
        raise Refused(2, "uv must be on PATH for a locked PyPI MCP install")
    root = Path(root)
    if not dry:
        root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    now = now or dt.datetime.now(dt.timezone.utc)
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    min_age_days = policy.min_age_days
    with work_stage(root, name, dry) as stage:
        pending = _pending_overrides(overrides, policy, fetch, now) if overrides else {}
        applied = {dep: wanted for dep, wanted in overrides.items() if dep not in pending}
        lock_bytes, entries = _lock(run, uv, stage, name=name, package=package, version=version,
                                    overrides=applied, excludes={}, min_age_days=min_age_days)
        _top_level_wheel(entries, package, version, receipt)
        verdict = _fastlane.judge_tree(
            entries, {}, receipts_root=root, kind="pypi", user_overrides=overrides,
            policy=policy, fetch=fetch, now=now, check=check)
        for line in verdict.lines:
            print(f"  {line}")
        if verdict.code:
            if verdict.needs_scan and verdict.code == 2:
                raise NeedsScan(verdict.needs_scan, prefix="fast lane needs scans first:\n")
            detail = "".join(f"\n{note}" for note in verdict.notes)
            raise Refused(verdict.code, f"lockfile check for {package}=={version} failed "
                                        f"(see above); the installed tree is unchanged{detail}")
        for dep, (wanted, ready) in pending.items():
            if verdict.fixes.get(dep, (None,))[0] != wanted:
                raise Refused(2, f"override {dep}=={wanted} is younger than {min_age_days} days "
                                 f"and fixes no advisory; wait until {ready}")
        if dry:
            print_dry_outcome(verdict, entries)
            print(f"  [DRY] would swap the tree in at {target} and run "
                  "uv sync --locked --no-dev --no-build")
            return Installed(name=name, kind="pypi", package=package, requested=version,
                             command=uv, args=["run", "--project", str(target), "--locked",
                                               "--no-dev", executable or "<entry point>"],
                             tree=target, lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(),
                             overrides=applied,
                             override_reason=override_reason.strip() if applied else None,
                             secrets=tuple(secrets), accepted=accepted)
        if verdict.fixes:
            return _rebuild_with_fixes(
                run, uv, root, target, verdict, name=name, package=package, version=version,
                receipt=receipt, applied=applied, override_reason=override_reason,
                executable=executable, secrets=secrets, accepted=accepted, check=check,
                policy=policy, fetch=fetch, now=now)
        return _finish(
            run, uv, stage, target, name=name, package=package, version=version,
            executable=executable, lock_bytes=lock_bytes, overrides=applied,
            override_reason=override_reason, secrets=secrets, accepted=accepted, fast_lane=[])


# ── Git sources (A4) ─────────────────────────────────────────────────────────

GIT_URL_RE = re.compile(r"(?:git\+)?https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*)/"
                        r"([A-Za-z0-9_.-]+?)(?:\.git)?@([0-9a-fA-F]{40})"
                        r"(?:#subdirectory=([A-Za-z0-9_./-]+))?")
DEFAULT_BUILD_REQUIRES = ["setuptools>=40.8.0"]  # PEP 517 fallback without [build-system]
# A build requirement as PEP 508 name, extras, specifiers and markers -- no
# direct URL, no option line, nothing that changes where uv looks.
BUILD_REQ_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._, -]*\])?"
                          r"[ ]*(?:[<>=!~][<>=!~ ,.*A-Za-z0-9+-]*)?(?:;[ A-Za-z0-9_.<>=!~'\"()-]*)?")
BUILD_IN, BUILD_OUT = "build-requires.in", "build-constraints.txt"


def parse_git_url(url: str) -> tuple:
    """(owner, repo, sha, subdirectory) of a commit-pinned GitHub source, else Refused(2)."""
    match = GIT_URL_RE.fullmatch((url or "").strip())
    if not match:
        raise Refused(2, f"unsupported Git source {url!r}: only https://github.com/<owner>/<repo>"
                         "@<full 40-character commit SHA>[#subdirectory=...] is installed")
    owner, repo, sha, subdir = match.groups()
    subdir = subdir or ""
    if subdir and (subdir.startswith("/") or subdir.endswith("/")
                   or any(part in ("", ".", "..") for part in subdir.split("/"))):
        raise Refused(2, "the Git subdirectory must stay inside the scanned repository")
    return owner, repo, sha.lower(), subdir


def git_scan_id(owner: str, repo: str) -> str:
    """Receipt identity that covers a Git install: always the whole repository
    at the commit. uv builds from the whole checkout, and a build backend can
    pull files from outside the subdirectory (security review F1, #48)."""
    return f"{owner}/{repo}"


def build_requires(pyproject_text: str) -> list:
    """[build-system].requires of the scanned pyproject.toml, or the PEP 517 default."""
    import tomllib
    try:
        data = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError as exc:
        raise Refused(2, f"unreadable pyproject.toml of the scanned commit: {exc}")
    system = data.get("build-system")
    if system is None or "requires" not in system:
        return list(DEFAULT_BUILD_REQUIRES)
    requires = system["requires"]
    if not isinstance(requires, list) or not requires:
        raise Refused(2, "[build-system].requires of the scanned commit is not a list")
    for req in requires:
        if not isinstance(req, str) or not BUILD_REQ_RE.fullmatch(req.strip()):
            raise Refused(2, f"NO VERDICT -- build requirement {req!r} is not a plain PyPI "
                             "requirement (no URLs or options)")
    return [req.strip() for req in requires]


def build_constraints(requires: list, stage: Path, run: Runner, uv: str, check,
                      min_age_days: int) -> list:
    """Resolve the build tools exactly with their hashes, check them, return their entries.

    The check covers exactly the files whose hashes uv will accept for the build."""
    (stage / BUILD_IN).write_text("\n".join(requires) + "\n", encoding="utf-8")
    code, out = run([uv, "pip", "compile", BUILD_IN, "--no-build", "--generate-hashes",
                     "--exclude-newer", f"{min_age_days} days", "--default-index", INDEX,
                     "-o", BUILD_OUT], stage)
    if code != 0:
        raise Refused(2, f"uv could not resolve the build tools {', '.join(requires)}:\n{_tail(out)}")
    try:
        entries = _lockcheck.hashed_requirements(
            (stage / BUILD_OUT).read_text(encoding="utf-8"))
    except OSError as exc:
        raise Refused(2, f"cannot read the resolved build tools: {exc}")
    except _lockcheck.NoVerdict as exc:
        raise Refused(2, f"NO VERDICT -- {exc}")
    result = check(entries, min_age_days=min_age_days)
    for line in result.lines:
        print(f"  {line}")
    if result.code:
        raise Refused(result.code, "check of the build tools failed (see above); "
                                   "the installed tree is unchanged")
    for name in (BUILD_IN, BUILD_OUT):
        (stage / name).unlink()
    return entries


def git_uv_settings(build_tools: list) -> str:
    """[tool.uv] lines for the build of the Git package.

    With require-build-hashes uv installs into the build environment only
    files with a trusted hash; what the backend asks for at build time
    (get_requires_for_build_wheel) has none and is refused (uv 0.13.0, #21411,
    preview). The bundled uv_build backend needs no hash."""
    items = ", ".join(
        f'{{ requirement = "{e.name}=={e.version}", hashes = ['
        + ", ".join(f'"sha256:{h}"' for h in e.hashes) + "] }"
        for e in build_tools)
    return ("require-build-hashes = true\n"
            'preview-features = ["build-dependency-hashes"]\n'
            f"build-constraint-dependencies = [{items}]\n")


def git_sync_command(uv: str, entries: list) -> list:
    """`uv sync` of the swapped-in tree; registry packages are never built.

    --no-cache: uv does not check the build of a wheel it finds in its cache,
    and for a Git source only a fresh cache forces the checked rebuild
    (--refresh-package, --reinstall-package and --refresh do not; real uv 0.13.10)."""
    no_build = [arg for e in entries for arg in ("--no-build-package", e.name)]
    return [uv, "sync", "--locked", "--no-dev", "--no-cache", *no_build]


UNHASHED_BUILD_RE = re.compile(r"no trusted hash was provided for: (.+)")


def git_sync_failure(package: str, out: str) -> Refused:
    """The refusal for a failed `uv sync` of a Git tree."""
    match = UNHASHED_BUILD_RE.search(out or "")
    if match:
        names = match.group(1).strip().replace("`", "")
        return Refused(2, f"NO VERDICT -- the build backend of {package} asks for build tools "
                          f"that were not pinned and checked ({names}); uv refused them, so "
                          f"{package} is not installed")
    return Refused(2, f"uv sync failed:\n{_tail(out)}")


MIN_UV = (0, 13, 0)
UV_VERSION_RE = re.compile(r"uv (\d+)\.(\d+)\.(\d+)\b")


def require_build_hash_uv(run: Runner, uv: str, cwd: Path) -> None:
    """Refuse a uv without require-build-hashes (added in 0.13.0)."""
    code, out = run([uv, "--version"], cwd)
    match = UV_VERSION_RE.match((out or "").strip()) if code == 0 else None
    if match is None:
        raise Refused(2, f"cannot read the uv version:\n{_tail(out)}")
    if tuple(int(part) for part in match.groups()) < MIN_UV:
        raise Refused(2, f"{match.group(0)} cannot check the hashes of build tools; a locked "
                         "Git MCP install needs uv 0.13.0 or newer")


def _github_json(url: str):
    import _url_resolver
    try:
        return _url_resolver.http_json(url)
    except _url_resolver.FetchError as exc:
        raise Refused(2, f"GitHub lookup failed: {exc}")


def github_branch_head(source: str) -> tuple:
    """(default branch, its head commit) from the GitHub API."""
    repo = _github_json(f"https://api.github.com/repos/{source}")
    branch = repo.get("default_branch") if isinstance(repo, dict) else None
    if not isinstance(branch, str) or not branch:
        raise Refused(2, f"{source}: GitHub names no default branch")
    import urllib.parse
    data = _github_json(f"https://api.github.com/repos/{source}/branches/"
                        f"{urllib.parse.quote(branch, safe='')}")
    head = (data.get("commit") or {}).get("sha") if isinstance(data, dict) else None
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise Refused(2, f"{source}: GitHub names no head commit for {branch}")
    return branch, head


def github_compare(source: str, base: str, head: str) -> str:
    data = _github_json(f"https://api.github.com/repos/{source}/compare/{base}...{head}")
    status = data.get("status") if isinstance(data, dict) else None
    if not isinstance(status, str):
        raise Refused(2, f"{source}: GitHub compare gave no status")
    return status


def has_gitmodules(names) -> bool:
    """A .gitmodules entry in any letter case: Git on a case-insensitive
    filesystem reads it, and uv checks the submodules out for the build."""
    return any(str(n).lower() == ".gitmodules" for n in names)


def github_root_names(source: str, sha: str) -> list:
    """Names in the repository root at `sha` from the GitHub contents API."""
    data = _github_json(f"https://api.github.com/repos/{source}/contents?ref={sha}")
    # The contents API lists at most 1,000 entries; a full page may be cut off.
    if (not isinstance(data, list) or len(data) >= 1000
            or not all(isinstance(e, dict) and isinstance(e.get("name"), str) for e in data)):
        raise Refused(2, f"NO VERDICT -- GitHub gave no complete root listing for {source}@{sha}")
    return [e["name"] for e in data]


def raw_text(url: str) -> str:
    import _url_resolver
    try:
        return _url_resolver.http_bytes(url).decode("utf-8")
    except (_url_resolver.FetchError, UnicodeDecodeError) as exc:
        raise Refused(2, f"cannot read {url}: {exc}")


def _settled_commit(source: str, sha: str, settled, branch_head, compare,
                    min_age_days: int) -> None:
    """K4: the commit is in the newest default-branch state that meets the age limit."""
    import _staging
    branch, head = branch_head(source)
    age_options = {} if min_age_days == _staging.COOLDOWN_DAYS else {"days": min_age_days}
    try:
        base, _when = settled(source, branch, head, **age_options)
    except (_staging.StageError, OverflowError) as exc:
        raise Refused(2, f"NO VERDICT -- {exc}")
    status = compare(source, base, sha)
    if status not in ("identical", "behind"):
        raise Refused(2, f"commit {sha} is not in the state of {branch} from {min_age_days} days "
                         f"ago (GitHub compare: {status}); it is younger than {min_age_days} "
                         f"days or not on {branch} -- retry later")


def git_install(*, name: str, git_url: str, package: str, executable: str | None,
                module: str | None, secrets: tuple, root: Path, receipt, accepted: dict | None,
                scanned_dir: Path | None, run: Runner, check=_lockcheck.check,
                which=_exe.which, fetch_text=raw_text, settled=None,
                branch_head=github_branch_head, compare=github_compare,
                root_names=github_root_names,
                dry: bool = False, policy: _fastlane.Policy = _fastlane.Policy()) -> Installed:
    """Build, check and swap in the locked tree of one Git-backed Python MCP server."""
    require_python_311()
    check_name(name)
    owner, repo, sha, subdir = parse_git_url(git_url)
    check_package(package)
    if executable is not None and module is not None:
        raise Refused(2, "choose either --executable or --module, not both")
    for value, what in ((executable, "--executable"), (module, "--module")):
        if value is not None and not ENTRY_RE.fullmatch(value):
            raise Refused(2, f"invalid {what} {value!r}")
    check_secrets(secrets)
    source = f"{owner}/{repo}"
    repo_url = f"https://github.com/{source}"
    git_source = f"{repo_url}@{sha}" + (f"#subdirectory={subdir}" if subdir else "")
    scanned_id = git_scan_id(owner, repo)
    import _mcp_receipts
    if (receipt.kind != "git" or receipt.version != sha
            or _mcp_receipts.identity("git", receipt.package)
            != _mcp_receipts.identity("git", scanned_id)):
        raise Refused(2, f"the scan receipt is for {receipt.package}@{receipt.version}, "
                         f"not {scanned_id}@{sha}")
    if not which("git"):
        raise Refused(2, "git must be on PATH for a locked Git MCP install (uv builds the "
                         "package from the commit)")
    uv = which("uv")
    if not uv:
        raise Refused(2, "uv must be on PATH for a locked Git MCP install")
    root = Path(root)
    min_age_days = policy.min_age_days
    tail = ["python", "-m", module] if module else [executable or "<entry point>"]
    if settled is None:
        import _staging
        settled = _staging.settled_ref
    _settled_commit(source, sha, settled, branch_head, compare, min_age_days)
    # Also checked here, not only by the scan: a receipt from an older scan or
    # a manual call must not build a commit with unscanned submodules (F1).
    try:
        names = ([p.name for p in Path(scanned_dir).iterdir()] if scanned_dir is not None
                 else root_names(source, sha))
    except OSError as exc:
        raise Refused(2, f"cannot list the scanned source: {exc}")
    if has_gitmodules(names):
        raise Refused(2, f"NO VERDICT -- {source}@{sha} has Git submodules (.gitmodules); uv "
                         "would check them out unscanned, so it is not installed")
    if scanned_dir is not None:
        try:
            pyproject = (Path(scanned_dir) / subdir / "pyproject.toml").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise Refused(2, f"the scanned source has no readable pyproject.toml: {exc}")
    else:
        pyproject = fetch_text(f"https://raw.githubusercontent.com/{source}/{sha}/"
                               f"{subdir + '/' if subdir else ''}pyproject.toml")
    requires = build_requires(pyproject)
    if not dry:
        root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    chosen = {}
    with work_stage(root, name, dry) as stage:
        require_build_hash_uv(run, uv, stage)
        build_tools = build_constraints(requires, stage, run, uv, check, min_age_days)
        dependency = f"{package} @ git+{git_source}"
        (stage / "pyproject.toml").write_text(
            _pyproject(name, dependency, min_age_days, git_uv_settings(build_tools)),
            encoding="utf-8")
        (stage / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        code, out = run([uv, "lock", "--no-build", "--default-index", INDEX], stage)
        if code != 0:
            raise Refused(2, f"uv could not lock {package} from {source}@{sha} without builds "
                             "(dynamic metadata such as setuptools-scm needs a build and cannot "
                             f"be locked this way):\n{_tail(out)}")
        pin = _lockcheck.GitPin(normalize_pypi(package), repo_url, sha, subdir)
        try:
            lock_bytes = (stage / LOCKFILE).read_bytes()
            entries = _lockcheck.uv_lock_entries(lock_bytes.decode("utf-8"), project_name(name),
                                                 git=pin)
        except (OSError, UnicodeDecodeError) as exc:
            raise Refused(2, f"cannot read {LOCKFILE}: {exc}")
        except _lockcheck.NoVerdict as exc:
            raise Refused(2, f"NO VERDICT -- {exc}")
        if entries:
            result = check(entries, min_age_days=min_age_days)
            for line in result.lines:
                print(f"  {line}")
            if result.code:
                raise Refused(result.code, f"lockfile check for {package} failed (see above); "
                                           "the installed tree is unchanged")
        if dry:
            if entries:
                print_dry_clean(entries)
            else:
                print("  [DRY] the lockfile holds no registry package to check")
            print(f"  [DRY] would swap the tree in at {target} and run uv sync --locked "
                  "--no-dev --no-cache --no-build-package <each registry package>")
            return Installed(name=name, kind="git", package=package, requested=sha, command=uv,
                             args=["run", "--project", str(target), "--locked", "--no-dev",
                                   *tail],
                             tree=target, lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(),
                             overrides={}, override_reason=None, secrets=tuple(secrets),
                             accepted=accepted, source=git_source)

        def sync(tree: Path) -> None:
            code, out = run(git_sync_command(uv, entries), tree)
            if code != 0:
                raise git_sync_failure(package, out)
            if (tree / LOCKFILE).read_bytes() != lock_bytes:
                raise Refused(2, "uv sync changed uv.lock; the checked tree is not what was built")
            if module:
                dist_info(tree / ".venv", package)
                chosen["tail"] = ["python", "-m", module]
            else:
                chosen["tail"] = [entry_point(console_scripts(tree / ".venv", package),
                                              package, executable)]

        installed = Installed(
            name=name, kind="git", package=package, requested=sha, command=uv, args=[],
            tree=target, lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides={},
            override_reason=None, secrets=tuple(secrets), accepted=accepted, source=git_source)
        write_metadata(stage, installed)
        replace_tree(stage, target, finish=sync)
    installed.args = ["run", "--project", str(target), "--locked", "--no-dev", *chosen["tail"]]
    return installed
