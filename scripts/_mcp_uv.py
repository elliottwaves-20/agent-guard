"""Locked PyPI MCP installs through uv (#48, A3).

The server gets its own uv project with an exact top-level pin and a
seven-day window. `uv lock --no-build` resolves the whole tree without running
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


def _pyproject(name: str, dependency: str, extra: str = "") -> str:
    return (f'[project]\nname = "{project_name(name)}"\nversion = "0.0.0"\n'
            f'description = "Locked tree for the MCP server {name} (agent-guard)"\n'
            f'requires-python = ">=3.10"\ndependencies = ["{dependency}"]\n\n'
            f'[tool.uv]\npackage = false\nexclude-newer = "7 days"\n{extra}')


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
                 check=_lockcheck.check, which=shutil.which, dry: bool = False) -> Installed:
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
    with staged(root, name) as stage:
        (stage / "pyproject.toml").write_text(_pyproject(name, f"{package}=={version}"),
                                              encoding="utf-8")
        (stage / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        code, out = run([uv, "lock", "--no-build", "--default-index", INDEX], stage)
        if code != 0:
            raise Refused(2, f"uv could not lock {package}=={version} from {INDEX} without "
                             f"builds and without files younger than 7 days:\n{_tail(out)}")
        try:
            lock_bytes = (stage / LOCKFILE).read_bytes()
            entries = _lockcheck.uv_lock_entries(lock_bytes.decode("utf-8"), project_name(name))
        except (OSError, UnicodeDecodeError) as exc:
            raise Refused(2, f"cannot read {LOCKFILE}: {exc}")
        except _lockcheck.NoVerdict as exc:
            raise Refused(2, f"NO VERDICT -- {exc}")
        _top_level_wheel(entries, package, version, receipt)
        result = check(entries)
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
