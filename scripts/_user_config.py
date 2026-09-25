"""User-level agent-guard configuration (outside the repository).

One TOML file holds everything that is personal to a machine: LLM profiles
and the local skill distribution. The repository ships only the mechanism and
`config.example.toml`; without a config file every wrapper behaves exactly as
before.

Lookup order (first hit wins):
  1. AGENT_GUARD_CONFIG=<path>             (must exist; AGENT_GUARD_NO_USER_CONFIG=1
                                            disables the defaults below)
  2. Windows: %APPDATA%\\agent-guard\\config.toml
  3. Otherwise: $XDG_CONFIG_HOME/agent-guard/config.toml,
     then ~/.config/agent-guard/config.toml

Secrets never live in this file. A profile names the environment variable
that holds its key (`key_env`); anything that looks like a credential is
refused so a key cannot end up in a synced or shared config.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: only an existing config needs TOML.
    tomllib = None

SECTIONS = {"llm", "distribution"}

# Credential prefixes of common providers. A match refuses the whole file.
SECRET_PREFIXES = ("sk-", "sk_", "csk-", "gsk_", "nvapi-", "xai-", "AIza",
                   "ghp_", "gho_", "github_pat_", "hf_", "pplx-", "fc-", "tvly-")
SECRET_FIELD = re.compile(r"(^|_)(api_?key|key|token|secret|password|passwd)$",
                          re.IGNORECASE)


class ConfigError(RuntimeError):
    """The user config exists but cannot be used safely."""


def find_config(env=None, platform=None, home=None) -> Path | None:
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    explicit = env.get("AGENT_GUARD_CONFIG", "").strip()
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"AGENT_GUARD_CONFIG points to a missing file: {path}")
        return path
    # Opt-out for isolated runs (test suites, budget campaigns): only an
    # explicitly named file is read, never the machine's personal config.
    if env.get("AGENT_GUARD_NO_USER_CONFIG", "").strip():
        return None
    if home is None:
        try:
            home = Path.home()
        except RuntimeError:  # no HOME/USERPROFILE (services, stripped envs)
            home = None
    candidates = []
    if platform == "win32":
        if env.get("APPDATA", "").strip():
            candidates.append(Path(env["APPDATA"]) / "agent-guard" / "config.toml")
    else:
        if env.get("XDG_CONFIG_HOME", "").strip():
            candidates.append(Path(env["XDG_CONFIG_HOME"]) / "agent-guard" / "config.toml")
        if home is not None:
            candidates.append(Path(home) / ".config" / "agent-guard" / "config.toml")
    return next((path for path in candidates if path.is_file()), None)


def _refuse_secrets(node, where: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{where}.{key}" if where else key
            if SECRET_FIELD.search(key) and key != "key_env":
                raise ConfigError(f"{path}: credentials do not belong in the config; "
                                  "name the environment variable with key_env instead")
            _refuse_secrets(value, path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _refuse_secrets(value, f"{where}[{index}]")
    elif isinstance(node, str) and node.strip().startswith(SECRET_PREFIXES):
        raise ConfigError(f"{where}: value looks like a credential; keep keys in the "
                          "environment and reference them with key_env")


def load_config(env=None, platform=None, home=None) -> dict:
    path = find_config(env, platform, home)
    if path is None:
        return {}
    if tomllib is None:
        raise ConfigError(f"{path} needs Python 3.11+ (tomllib) to be read")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read config ({exc})") from None
    unknown = sorted(set(data) - SECTIONS)
    if unknown:
        raise ConfigError(f"{path}: unknown section(s) {', '.join(unknown)}; "
                          f"expected {', '.join(sorted(SECTIONS))}")
    _refuse_secrets(data, "")
    return data
