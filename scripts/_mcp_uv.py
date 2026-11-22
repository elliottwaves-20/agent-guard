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
import hashlib
import re
import shutil
from pathlib import Path

import _fastlane
import _lockcheck
from _mcp_locked import (ENTRY_RE, Installed, Refused, Runner, check_name, check_secrets,
                         normalize_pypi, replace_tree, require_python_311, staged,
                         stale_leftovers, write_metadata)

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
        except (OSError, configparser.Error) as exc:
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


def _top_level_wheel(entries: list, package: str, version: str, receipt) -> None:
    """The top-level package must lock exactly one pure wheel: the scanned file."""
    tops = [e for e in entries if normalize_pypi(e.name) == normalize_pypi(package)]
    if len(tops) != 1 or tops[0].version != version:
        found = ", ".join(e.version for e in tops) or "nothing"
        raise Refused(2, f"NO VERDICT -- uv.lock resolves {package} to {found}, "
                         f"not the pinned {version}")
    wheels = [(f, h) for f, h in tops[0].files if f.endswith(".whl")]
    if len(wheels) != 1 or not wheels[0][0].endswith("-none-any.whl"):
        names = ", ".join(f for f, _ in wheels) or "no wheel"
        raise Refused(2, f"NO VERDICT -- {package} {version} must lock exactly one pure "
                         f"wheel (*-none-any.whl) to install the scanned file; it locks {names}")
    if wheels[0][1] != receipt.archive_sha256:
        raise Refused(2, f"the locked wheel {wheels[0][0]} is not the scanned file "
                         f"(sha256 {wheels[0][1]} vs {receipt.archive_sha256}); scan again")


def pypi_install(*, name: str, package: str, version: str, executable: str | None,
                 secrets: tuple, root: Path, receipt, accepted: dict | None, run: Runner,
                 check=_lockcheck.check, which=shutil.which, dry: bool = False,
                 policy: _fastlane.Policy = _fastlane.Policy()) -> Installed:
    """Build, check and swap in the locked tree of one PyPI MCP server."""
    require_python_311()
    check_name(name)
    check_package(package)
    check_version(version)
    if executable is not None and not ENTRY_RE.fullmatch(executable):
        raise Refused(2, f"invalid --executable {executable!r}")
    check_secrets(secrets)
    if (receipt.kind != "pypi" or normalize_pypi(receipt.package) != normalize_pypi(package)
            or receipt.version != version):
        raise Refused(2, f"the scan receipt is for {receipt.package} {receipt.version}, "
                         f"not {package} {version}")
    uv = which("uv")
    if not uv:
        raise Refused(2, "uv must be on PATH for a locked PyPI MCP install")
    root = Path(root)
    if dry:
        target = root.absolute() / name
        print(f"  [DRY] would build {target} from {package}=={version} (uv lock --no-build, "
              "lockfile check, swap, uv sync --locked --no-dev --no-build)")
        return Installed(name=name, kind="pypi", package=package, requested=version, command=uv,
                         args=["run", "--project", str(target), "--locked", "--no-dev",
                               executable or "<entry point>"],
                         tree=target, lockfile_sha256="", overrides={}, override_reason=None,
                         secrets=tuple(secrets), accepted=accepted)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    chosen = {}
    min_age_days = policy.min_age_days
    with staged(root, name) as stage:
        (stage / "pyproject.toml").write_text(
            _pyproject(name, f"{package}=={version}", min_age_days), encoding="utf-8")
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
        _top_level_wheel(entries, package, version, receipt)
        result = check(entries, min_age_days=min_age_days)
        for line in result.lines:
            print(f"  {line}")
        if result.code:
            raise Refused(result.code, f"lockfile check for {package}=={version} failed "
                                       "(see above); the installed tree is unchanged")

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
            tree=target, lockfile_sha256=hashlib.sha256(lock_bytes).hexdigest(), overrides={},
            override_reason=None, secrets=tuple(secrets), accepted=accepted)
        write_metadata(stage, installed)
        replace_tree(stage, target, finish=sync)
    installed.args = ["run", "--project", str(target), "--locked", "--no-dev", chosen["entry"]]
    return installed


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


def git_scan_ids(source: str, subdir: str) -> list:
    """Scanned parts that cover an install from `subdir`, narrowest first: the
    subdirectory itself, each parent, the whole repository."""
    parts = [p for p in subdir.split("/") if p]
    ids = [f"{source}#{'/'.join(parts[:n])}" for n in range(len(parts), 0, -1)]
    return ids + [source]


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
    """Resolve the build tools exactly, check them, return `name==version` pins."""
    (stage / BUILD_IN).write_text("\n".join(requires) + "\n", encoding="utf-8")
    code, out = run([uv, "pip", "compile", BUILD_IN, "--no-build", "--exclude-newer",
                     f"{min_age_days} days", "--default-index", INDEX, "-o", BUILD_OUT], stage)
    if code != 0:
        raise Refused(2, f"uv could not resolve the build tools {', '.join(requires)}:\n{_tail(out)}")
    try:
        entries = _lockcheck.pinned_entries((stage / BUILD_OUT).read_text(encoding="utf-8"))
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
    return [f"{e.name}=={e.version}" for e in entries]


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
                which=shutil.which, fetch_text=raw_text, settled=None,
                branch_head=github_branch_head, compare=github_compare,
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
    scanned_id = source + (f"#{subdir}" if subdir else "")
    import _mcp_receipts
    covering = {_mcp_receipts.identity("git", c) for c in git_scan_ids(source, subdir)}
    if (receipt.kind != "git" or receipt.version != sha
            or _mcp_receipts.identity("git", receipt.package) not in covering):
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
    if dry:
        target = root.absolute() / name
        print(f"  [DRY] would check that {sha} is at least {min_age_days} days on the default "
              f"branch, pin and check the build tools, lock and check {package} from {source}, "
              "swap, "
              "uv sync --locked --no-dev --no-build-package <each registry package>")
        return Installed(name=name, kind="git", package=package, requested=sha, command=uv,
                         args=["run", "--project", str(target), "--locked", "--no-dev", *tail],
                         tree=target, lockfile_sha256="", overrides={}, override_reason=None,
                         secrets=tuple(secrets), accepted=accepted, source=git_source)
    if settled is None:
        import _staging
        settled = _staging.settled_ref
    _settled_commit(source, sha, settled, branch_head, compare, min_age_days)
    if scanned_dir is not None:
        try:
            pyproject = (Path(scanned_dir) / subdir / "pyproject.toml").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise Refused(2, f"the scanned source has no readable pyproject.toml: {exc}")
    else:
        pyproject = fetch_text(f"https://raw.githubusercontent.com/{source}/{sha}/"
                               f"{subdir + '/' if subdir else ''}pyproject.toml")
    requires = build_requires(pyproject)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    target = root / name
    for leftover in stale_leftovers(root, name):
        print(f"  note: leftover of an aborted run, not used: {leftover}")
    chosen = {}
    with staged(root, name) as stage:
        constraints = build_constraints(requires, stage, run, uv, check, min_age_days)
        dependency = f"{package} @ git+{git_source}"
        extra = ("build-constraint-dependencies = ["
                 + ", ".join(f'"{c}"' for c in constraints) + "]\n")
        (stage / "pyproject.toml").write_text(
            _pyproject(name, dependency, min_age_days, extra), encoding="utf-8")
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
        no_build = [arg for e in entries for arg in ("--no-build-package", e.name)]

        def sync(tree: Path) -> None:
            code, out = run([uv, "sync", "--locked", "--no-dev", *no_build], tree)
            if code != 0:
                raise Refused(2, f"uv sync failed:\n{_tail(out)}")
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
