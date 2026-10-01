"""Local skill distribution configured in the user config.

Some machines already run their own skill distribution: one store, links into
every agent, profiles that decide what each agent loads. Asking for target
agents would bypass it. With

    [distribution]
    mode = "sync"
    inbox = "<a directory the sync collects new skills from>"
    sync = ["<program>", "<arg>", ...]     # optional
    sync_timeout = 600                     # optional, seconds
    origins = "<file>.json"                # optional: enables update_skills.py
    backup = "<directory>"                 # optional: replaced versions go here
    quarantine = "<directory>"             # optional: blocked versions are kept here

the installer publishes a SAFE skill into `inbox` and runs `sync` once. What
the sync does -- store, links, profile assignment -- is the machine's business;
agent-guard only checks that it did not change the scanned files and prints
the sync's lines that mention the skill. Without the section nothing changes.
`origins`, `backup` and `quarantine` are used only by update_skills.py.
A missing, failing or slow sync is a warning: the skill is already installed
in the inbox and the next regular sync picks it up.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import NamedTuple

import _skills_cli
from _skillspector import run_bounded
from _user_config import ConfigError

MODES = {"sync"}
KEYS = {"mode", "inbox", "sync", "sync_timeout", "origins", "backup", "quarantine"}
DEFAULT_SYNC_TIMEOUT = 600.0


class Distribution(NamedTuple):
    inbox: Path
    sync: tuple | None
    timeout: float
    origins: Path | None = None
    backup: Path | None = None
    quarantine: Path | None = None


def _optional_path(section: dict, key: str, *, must_exist: bool) -> Path | None:
    raw = section.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ConfigError(f"[distribution] {key} must be a path")
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        raise ConfigError(f"[distribution] {key} must be an absolute path, got {raw!r}")
    if must_exist and not path.parent.is_dir():
        raise ConfigError(f"[distribution] {key}: parent directory does not exist: {path.parent}")
    return path


def from_config(config: dict) -> Distribution | None:
    """The configured distribution, None without a [distribution] section."""
    section = config.get("distribution")
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ConfigError("[distribution] must be a table")
    unknown = sorted(set(section) - KEYS)
    if unknown:
        raise ConfigError(f"[distribution]: unknown key(s) {', '.join(unknown)}; "
                          f"expected {', '.join(sorted(KEYS))}")
    mode = section.get("mode")
    if mode not in MODES:
        raise ConfigError(f"[distribution] mode must be one of {', '.join(sorted(MODES))}, "
                          f"got {mode!r}")

    raw = section.get("inbox")
    if not isinstance(raw, str) or not raw.strip():
        raise ConfigError("[distribution] inbox is required (a directory path)")
    inbox = Path(raw.strip()).expanduser()
    if not inbox.is_absolute():
        raise ConfigError(f"[distribution] inbox must be an absolute path, got {raw!r}")
    if not inbox.is_dir():
        raise ConfigError(f"[distribution] inbox does not exist: {inbox}")

    sync = section.get("sync")
    if sync is not None:
        if (not isinstance(sync, list) or not sync
                or not all(isinstance(a, str) for a in sync) or not sync[0].strip()):
            raise ConfigError("[distribution] sync must be a non-empty list of strings "
                              '(program and arguments, e.g. ["pwsh", "-File", "sync.ps1"])')
        sync = tuple(sync)

    timeout = section.get("sync_timeout", DEFAULT_SYNC_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ConfigError("[distribution] sync_timeout must be a positive number of seconds")

    return Distribution(inbox=inbox.resolve(), sync=sync, timeout=timeout,
                        origins=_optional_path(section, "origins", must_exist=True),
                        backup=_optional_path(section, "backup", must_exist=False),
                        quarantine=_optional_path(section, "quarantine", must_exist=False))


def run_sync(distribution: Distribution, name: str) -> bool:
    """Run the sync command once. Returns True when it exited cleanly.

    The command comes from the user's own config, but it still runs without
    credentials: a skill sync has no business with provider keys."""
    if distribution.sync is None:
        print("  distribution: no sync command configured -- the skill waits in "
              f"{distribution.inbox} until your next sync run")
        return False
    print(f"  distribution: running sync ({Path(distribution.sync[0]).name})")
    try:
        result = run_bounded(list(distribution.sync), env=_skills_cli.hardened_env(),
                             timeout=distribution.timeout)
    except subprocess.TimeoutExpired:
        print(f"  distribution: sync timed out after {distribution.timeout:.0f}s -- "
              f"the skill stays in {distribution.inbox}")
        return False
    except OSError as exc:
        print(f"  distribution: sync command could not start ({exc}) -- "
              f"the skill stays in {distribution.inbox}")
        return False
    if result.returncode != 0:
        print(f"  distribution: sync command failed (exit {result.returncode}) -- "
              f"the skill stays in {distribution.inbox}")
        for stream in (result.stdout, result.stderr):
            if stream and stream.strip():
                _skills_cli.echo(stream.rstrip())
        return False
    own = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])")
    mentions = [line.strip() for line in (result.stdout or "").splitlines()
                if own.search(line)]
    if mentions:
        for line in mentions:
            _skills_cli.echo(f"  sync: {line}")
    else:
        print(f"  distribution: sync finished; its output does not mention '{name}'")
    return True
