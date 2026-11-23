"""Shared core of the locked MCP installs (#48).

Each MCP server gets its own directory under the install directory with an
exact top-level pin and a lockfile over the whole tree. The tree is built in a
hidden staging sibling, checked, and only then swapped in; a failure at any
point leaves the previous tree where it was. This module holds what the npm,
PyPI and Git installers share: settings, names, the swap, metadata and the
subprocess runner. It writes no agent configuration itself.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

METADATA = "agent-guard-mcp.json"
REGISTER_FILE = "agent-guard-register.json"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SECRET_RE = re.compile(r"[A-Z][A-Z0-9_]*")
ENTRY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")  # executable / bin / module names
KEYS = {"install_dir", "register", "register_timeout"}
DEFAULT_REGISTER_TIMEOUT = 300
TOOL_TIMEOUT = 600
ONEDRIVE_VARS = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"

# Launchers that resolve a package tree at every start instead of running a fixed one.
ADHOC_RUNNERS = frozenset({"npx", "bunx", "uvx", "pnpx"})
ADHOC_SUBCOMMANDS = {"npm": ({"exec", "x"},), "bun": ({"x"},), "pnpm": ({"dlx"},),
                     "yarn": ({"dlx"},), "pipx": ({"run"},)}

Runner = Callable[[list, Path], tuple]


class Refused(Exception):
    """A locked install stops; `code` is the wrapper exit code (1 finding, 2 no verdict)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def registry_scan_command(kind: str, package: str, version: str) -> str:
    separator = {"npm": "@", "pypi": "=="}[kind]
    return f"python scripts/scan_url.py {kind}:{package}{separator}{version}"


class NeedsScan(Refused):
    """A locked install needs scan receipts for specific registry versions."""

    def __init__(self, items: list[dict], *, prefix: str = "scan first:\n"):
        self.items: list[dict] = items
        commands = "\n".join(registry_scan_command(**item) for item in items)
        super().__init__(2, prefix + commands)


@dataclass(frozen=True)
class Settings:
    install_dir: Path
    register: tuple | None
    register_timeout: float


@dataclass
class Installed:
    name: str
    kind: str
    package: str
    requested: str
    command: str
    args: list
    tree: Path
    lockfile_sha256: str
    overrides: dict
    override_reason: str | None
    secrets: tuple
    accepted: dict | None
    tier: str = "s2"
    fast_lane: list = field(default_factory=list)
    source: str = ""


# ── Settings ─────────────────────────────────────────────────────────────────

def _default_dir(env: Mapping, platform: str) -> Path:
    if platform == "win32":
        base = env.get("LOCALAPPDATA")
        if not base:
            raise Refused(2, "LOCALAPPDATA is not set; configure [mcp] install_dir")
        return Path(base) / "agent-guard" / "mcp"
    if env.get("XDG_DATA_HOME"):
        return Path(env["XDG_DATA_HOME"]) / "agent-guard" / "mcp"
    home = env.get("HOME") or str(Path.home())
    return Path(home) / ".local" / "share" / "agent-guard" / "mcp"


def _inside(path: Path, base: Path) -> bool:
    child = os.path.normcase(os.path.abspath(path))
    parent = os.path.normcase(os.path.abspath(base))
    return child == parent or child.startswith(parent.rstrip("\\/") + os.sep) \
        or child.startswith(parent.rstrip("\\/") + "/")


def settings(config: dict, env: Mapping, platform: str) -> Settings:
    """The [mcp] settings of the user config, with the platform defaults."""
    section = config.get("mcp", {})
    if not isinstance(section, dict):
        raise Refused(2, "[mcp] must be a table")
    unknown = sorted(set(section) - KEYS)
    if unknown:
        raise Refused(2, f"[mcp]: unknown key(s) {', '.join(unknown)}; "
                         f"expected {', '.join(sorted(KEYS))}")
    raw = section.get("install_dir")
    if raw is None:
        install_dir = _default_dir(env, platform)
    else:
        if not isinstance(raw, str) or not raw.strip():
            raise Refused(2, "[mcp] install_dir must be a path")
        install_dir = Path(raw.strip()).expanduser()
        if not install_dir.is_absolute():
            raise Refused(2, f"[mcp] install_dir must be an absolute path, got {raw!r}")
    for var in ONEDRIVE_VARS:
        if env.get(var) and _inside(install_dir, Path(env[var])):
            raise Refused(2, f"[mcp] install_dir {install_dir} lies inside OneDrive ({var}); "
                             "choose a local directory")
    register = section.get("register")
    if register is not None:
        if (not isinstance(register, list) or not register
                or not all(isinstance(a, str) for a in register) or not register[0].strip()):
            raise Refused(2, "[mcp] register must be a non-empty list of strings "
                             '(program and arguments, e.g. ["pwsh", "-File", "register.ps1"])')
        register = tuple(register)
    timeout = section.get("register_timeout", DEFAULT_REGISTER_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise Refused(2, "[mcp] register_timeout must be a positive number of seconds")
    return Settings(install_dir=install_dir, register=register, register_timeout=timeout)


# ── Names and checks ─────────────────────────────────────────────────────────

def parse_overrides(pairs: list) -> dict:
    overrides = {}
    for pair in pairs or []:
        dep, sep, version = pair.partition("=")
        if not sep or not dep:
            raise Refused(2, f"--override expects NAME=VERSION, got {pair!r}")
        if dep in overrides:
            raise Refused(2, f"--override names {dep} twice")
        overrides[dep] = version
    return overrides


def age_arg(value: str) -> int | str:
    """Leave invalid values for policy validation and the command result."""
    try:
        return int(value)
    except ValueError:
        return value


def normalize_pypi(name: str) -> str:
    """PEP 503 normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise Refused(2, f"invalid MCP server name {name!r}: letters, digits, '.', '_' "
                         "and '-', starting with a letter or digit, at most 64 characters")
    return name


def check_secrets(secrets: tuple) -> tuple:
    """Names of keys in the secret manager; a value never passes here (K2)."""
    for name in secrets:
        if not isinstance(name, str) or not SECRET_RE.fullmatch(name):
            raise Refused(2, f"invalid secret name {name!r}: --secret takes the name of a key "
                             "in your secret manager (A-Z, 0-9, _), never a value")
    return tuple(secrets)


def default_name(kind: str, package: str) -> str:
    """npm: last part without scope; PyPI and Git: the normalized package name."""
    if kind == "npm":
        return check_name(package.rsplit("/", 1)[-1])
    return check_name(normalize_pypi(package))


def require_python_311() -> None:
    if tuple(sys.version_info[:2]) < (3, 11):
        raise Refused(2, "locked PyPI and Git MCP installs need Python 3.11 or newer "
                         "(tomllib reads uv.lock)")


def _program(command: str) -> str:
    base = re.split(r"[\\/]", command)[-1].lower()
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(suffix):
            return base[:-len(suffix)]
    return base


def is_adhoc_launch(command: str, args: list) -> bool:
    """True for a launcher that resolves its package tree at every start."""
    program = _program(command)
    if program in ADHOC_RUNNERS:
        return True
    first = args[0] if args else ""
    if program in ADHOC_SUBCOMMANDS and first in ADHOC_SUBCOMMANDS[program][0]:
        return True
    if program == "uv":
        if args[:2] == ["tool", "run"]:
            return True
        if first == "run" and any(a == "--with" or a.startswith("--with=") for a in args):
            return True
    return False


# ── Tree swap ────────────────────────────────────────────────────────────────

def new_stage(root: Path, name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stage = root / f".{name}.staging-{secrets.token_hex(4)}"
    stage.mkdir()
    return stage


@contextlib.contextmanager
def staged(root: Path, name: str):
    """A fresh staging directory that is removed unless it was swapped in."""
    stage = new_stage(root, name)
    try:
        yield stage
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _is_leftover(path: Path, name_pattern: str) -> bool:
    return bool(re.match(rf"\.{name_pattern}\.(?:staging|old)-", path.name))


def stale_leftovers(root: Path, name: str) -> list:
    """Staging and old trees an aborted earlier run left behind (reported, never removed)."""
    if not root.is_dir():
        return []
    return [p for p in root.iterdir() if _is_leftover(p, re.escape(name))]


def replace_tree(stage: Path, target: Path,
                 finish: Callable[[Path], None] | None = None) -> None:
    """Swap the checked `stage` in for `target`; on any failure the old tree stays."""
    old = None
    if target.exists():
        old = target.with_name(f".{target.name}.old-{secrets.token_hex(4)}")
        try:
            os.replace(target, old)
        except OSError as exc:
            raise Refused(2, f"cannot replace {target} ({exc}); close the apps that run "
                             f"{target.name} and try again -- the installed tree is unchanged")
    try:
        os.replace(stage, target)
    except OSError as exc:
        if old is not None:
            os.replace(old, target)
        raise Refused(2, f"cannot move the new tree into {target} ({exc}); "
                         "the installed tree is unchanged")
    if finish is not None:
        try:
            finish(target)
        except (Refused, OSError, subprocess.SubprocessError) as exc:
            shutil.rmtree(target, ignore_errors=True)
            if old is not None:
                if target.exists():
                    raise Refused(2, f"{exc}; the new tree could not be removed, the previous "
                                     f"one is kept at {old}") from exc
                os.replace(old, target)
            raise Refused(getattr(exc, "code", 2),
                          f"{exc}; the previous tree is back in place") from exc
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)
        if old.exists():
            print(f"  note: could not remove the previous tree {old}; remove it later")


# ── Metadata and runner ──────────────────────────────────────────────────────

def agent_guard_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_metadata(directory: Path, installed: Installed) -> None:
    data = {"kind": installed.kind, "package": installed.package,
            "version": installed.requested, "overrides": installed.overrides,
            "override_reason": installed.override_reason,
            "lockfile_sha256": installed.lockfile_sha256, "at": now_iso(),
            "agent_guard": agent_guard_version(), "tier": installed.tier,
            "fast_lane": installed.fast_lane, "source": installed.source}
    (directory / METADATA).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _audit_stat(path: Path) -> os.stat_result:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise Refused(2, f"{path} is a link or reparse point (including junctions)")
    return info


def _audit_stamp(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns


def _audit_verify(snapshot: dict) -> None:
    for path, stamp in snapshot.items():
        if _audit_stamp(_audit_stat(path)) != stamp:
            raise Refused(2, f"{path} changed during the audit")


def _audit_open(path, flags):
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))


def _audit_read(path: Path, snapshot: dict) -> bytes:
    _audit_verify(snapshot)
    info = _audit_stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise Refused(2, f"{path} is not a regular file")
    snapshot[path] = _audit_stamp(info)
    with open(path, "rb", opener=_audit_open) as stream:
        if _audit_stamp(os.fstat(stream.fileno())) != snapshot[path]:
            raise Refused(2, f"{path} changed before it could be read")
        _audit_verify(snapshot)
        return stream.read()


def _audit_entries(path: Path, metadata: dict, snapshot: dict):
    import _lockcheck
    import _mcp_npm
    import _mcp_uv

    kind, package = metadata["kind"], metadata["package"]
    lock = path / (_mcp_npm.LOCKFILE if kind == "npm" else _mcp_uv.LOCKFILE)
    content = _audit_read(lock, snapshot)
    if metadata.get("lockfile_sha256") != hashlib.sha256(content).hexdigest():
        raise Refused(2, f"{lock.name} SHA-256 does not match installed metadata")
    text = content.decode("utf-8")
    if kind == "npm":
        return _lockcheck.npm_lock_entries(json.loads(text))
    pin = None
    if kind == "git":
        source = metadata.get("source")
        if not isinstance(source, str) or not source.strip():
            raise Refused(2, "Git metadata is missing a source")
        owner, repo, sha, subdirectory = _mcp_uv.parse_git_url(source)
        pin = _lockcheck.GitPin(normalize_pypi(package), f"https://github.com/{owner}/{repo}",
                                sha, subdirectory)
    return _lockcheck.uv_lock_entries(text, _mcp_uv.project_name(path.name), pin)


def _audit_findings(advisories: list, decisions: list) -> list:
    from _lockcheck import entry_key

    records = {(record["package"], record["installed"]): record for record in decisions}
    groups = {}
    for advisory in advisories:
        entry = advisory.entry
        key = entry_key(entry) if entry is not None else None
        if key not in groups:
            package, version = (entry.name, entry.version) if entry is not None else (None, None)
            groups[key] = {"package": package, "version": version, "advisories": [],
                           "decision": records.get((package, version))}
        ids = groups[key]["advisories"]
        if advisory.id not in ids:
            ids.append(advisory.id)
    return list(groups.values())


def _audit_tree(path: Path, snapshot: dict, *, policy, fetch, now) -> dict | None:
    import _fastlane
    import _lockcheck

    tree = {"name": path.name, "kind": None, "path": str(path), "status": "no_verdict",
            "scope": "all locked entries", "findings": [], "error": None}
    try:
        _audit_verify(snapshot)
        info = _audit_stat(path)
        if not stat.S_ISDIR(info.st_mode):
            return None
        snapshot[path] = _audit_stamp(info)
        check_name(path.name)
        metadata = json.loads(_audit_read(path / METADATA, snapshot))
        if not isinstance(metadata, dict):
            raise Refused(2, f"{METADATA} must contain a JSON object")
        kind, package = metadata.get("kind"), metadata.get("package")
        if kind not in ("npm", "pypi", "git"):
            raise Refused(2, f"{METADATA} has an invalid kind")
        tree["kind"] = kind
        if kind == "git":
            tree["scope"] = "registry entries; the git commit itself has no advisory source"
        if not isinstance(package, str) or not package.strip():
            raise Refused(2, f"{METADATA} has no package")
        entries = _audit_entries(path, metadata, snapshot)
        verdict = _fastlane.judge_tree(
            entries, {}, receipts_root=path.parent, kind=kind, user_overrides={},
            policy=policy, fetch=fetch, now=now, check=partial(_lockcheck.check, ages=False),
            check_receipts=False)
        checked = verdict.check_result
        if checked is None:
            tree["error"] = " | ".join(verdict.lines) or "lockfile check gave no verdict"
            return tree

        tree["findings"] = _audit_findings(checked.advisories, verdict.decisions)
        errors = list(checked.failures)
        if verdict.kev_unavailable:
            errors.append("KEV feed unavailable")
        errors.extend(f"{record['package']}@{record['installed']}: {record['reason']}"
                      for record in verdict.decisions if record["action"] == "no_verdict")
        if checked.advisories or checked.blocking or checked.code == 1:
            tree["status"] = "finding"
            if not checked.advisories:
                errors.extend(checked.blocking or checked.lines)
        elif checked.code != 0 or errors:
            if not errors:
                errors.extend(checked.lines or ["lockfile check gave no verdict"])
        else:
            tree["status"] = "clean"
        tree["error"] = " | ".join(errors) or None
    except (Refused, _lockcheck.NoVerdict) as exc:
        tree["error"] = str(exc)
    except Exception as exc:
        tree["error"] = f"{type(exc).__name__}: {exc}"
    return tree


def audit_trees(root: Path, *, policy, fetch, now=None) -> dict:
    """Check installed lockfiles and report findings without changing the trees."""
    audit = {"code": 0, "trees": [], "leftovers": []}
    try:
        root = Path(root)
        try:
            info = _audit_stat(root)
        except FileNotFoundError:
            return audit
        if not stat.S_ISDIR(info.st_mode):
            raise Refused(2, f"{root} is not a directory")
        children = sorted(root.iterdir(), key=lambda child: child.name)
    except Exception as exc:
        return {**audit, "code": 2, "error": str(exc)}

    root_snapshot = {root: _audit_stamp(info)}
    checked_trees = []
    for child in children:
        if child.name.startswith("."):
            if _is_leftover(child, NAME_RE.pattern):
                try:
                    if stat.S_ISDIR(child.lstat().st_mode):
                        audit["leftovers"].append(child.name)
                except OSError as exc:
                    audit["error"] = str(exc)
            continue
        snapshot = dict(root_snapshot)
        tree = _audit_tree(child, snapshot, policy=policy, fetch=fetch, now=now)
        if tree is not None:
            audit["trees"].append(tree)
            if tree["status"] != "no_verdict":
                checked_trees.append((tree, snapshot))

    for tree, snapshot in checked_trees:
        try:
            _audit_verify(snapshot)
        except (OSError, Refused) as exc:
            tree["error"] = " | ".join(filter(None, (tree["error"], str(exc))))
            if tree["status"] == "clean":
                tree["status"] = "no_verdict"
    try:
        _audit_verify(root_snapshot)
    except (OSError, Refused) as exc:
        audit["error"] = str(exc)

    statuses = {tree["status"] for tree in audit["trees"]}
    if "finding" in statuses:
        audit["code"] = 1
    elif "no_verdict" in statuses or "error" in audit:
        audit["code"] = 2
    return audit


# ── Handoff (A5) ─────────────────────────────────────────────────────────────

def register_payload(installed: Installed) -> dict:
    """What a configured register command receives: the start command and its provenance."""
    payload = {"version": 1, "name": installed.name, "kind": installed.kind,
               "package": installed.package, "requested": installed.requested,
               "command": installed.command, "args": list(installed.args),
               "tree": str(installed.tree), "lockfile_sha256": installed.lockfile_sha256,
               "overrides": dict(installed.overrides),
               "override_reason": installed.override_reason,
               "scan": {"verdict": "BLOCK" if installed.accepted else "SAFE",
                        "agent_guard": agent_guard_version()},
               "secrets": list(installed.secrets)}
    if installed.accepted is not None:
        payload["accepted"] = dict(installed.accepted)
    return payload


def _retry_hint(tree: Path) -> str:
    return f"python scripts/install_skill.py mcp-register {tree}"


def _call_register(register: tuple, path: Path, timeout: float, tree: Path, run) -> None:
    from _skills_cli import hardened_env
    if run is None:
        from _skillspector import run_bounded as run
    cmd = list(register) + [str(path)]
    try:
        result = run(cmd, env=hardened_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Refused(2, f"installed but not registered: the register command did not finish "
                         f"within {timeout}s; retry: {_retry_hint(tree)}")
    except OSError as exc:
        raise Refused(2, f"installed but not registered: the register command could not start "
                         f"({exc}); retry: {_retry_hint(tree)}")
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        print("\n".join(f"   {line}" for line in output.splitlines()[-20:]))
    if result.returncode != 0:
        raise Refused(2, f"installed but not registered: the register command exited with "
                         f"{result.returncode}; retry: {_retry_hint(tree)}")


def deliver(installed: Installed, settings: Settings, *, dry: bool, selected, install,
            run=None) -> int:
    """Hand the start command to the agents: install(...) by default, the register command
    when [mcp] register is set (then no agent config is written here)."""
    if settings.register is None:
        if installed.secrets:
            print(f"   This server needs {', '.join(installed.secrets)}; start it through your "
                  "secret manager (agent-guard stores no key values).")
        install(installed.name, {"command": installed.command, "args": list(installed.args)},
                dry, selected=selected)
        return 0
    path = Path(installed.tree) / REGISTER_FILE
    payload = register_payload(installed)
    if dry:
        print(f"  [DRY] would write {path}:\n{json.dumps(payload, indent=2)}")
        print(f"  [DRY] would run: {' '.join(list(settings.register) + [str(path)])}")
        return 0
    tmp = path.with_name(f".{REGISTER_FILE}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    _call_register(settings.register, path, settings.register_timeout, Path(installed.tree), run)
    print(f"[OK] MCP '{installed.name}' handed to the register command.")
    return 0


def rerun_register(tree: Path, settings: Settings, run=None) -> int:
    """Repeat the handoff of an installed tree (after a failed register command)."""
    if settings.register is None:
        raise Refused(2, "[mcp] register is not set; nothing to repeat")
    tree = Path(tree)
    path = tree / REGISTER_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(2, f"cannot read {path}: {exc}")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise Refused(2, f"{path} is not a version 1 handoff file")
    recorded = payload.get("tree")
    if (not isinstance(recorded, str)
            or os.path.normcase(str(Path(recorded).resolve())) != os.path.normcase(str(tree.resolve()))):
        raise Refused(2, f"{path} belongs to {recorded!r}, not {tree}")
    _call_register(settings.register, path, settings.register_timeout, tree, run)
    print(f"[OK] MCP '{payload.get('name')}' handed to the register command again.")
    return 0


def run_tool(cmd: list, cwd: Path) -> tuple:
    """Run npm or uv without credentials and without lifecycle scripts."""
    from _skillspector import run_bounded
    from _skills_cli import hardened_env
    try:
        result = run_bounded(list(cmd), env=hardened_env(), timeout=TOOL_TIMEOUT, cwd=str(cwd))
    except subprocess.TimeoutExpired:
        raise Refused(2, f"{Path(cmd[0]).name} timed out after {TOOL_TIMEOUT}s")
    except OSError as exc:
        raise Refused(2, f"{Path(cmd[0]).name} could not start: {exc}")
    return result.returncode, (result.stdout or "") + (result.stderr or "")
