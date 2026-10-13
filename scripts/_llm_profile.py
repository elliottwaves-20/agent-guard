"""LLM profiles: one switch for every scanner's semantic analysis.

A profile in the user config describes *how* to reach a model; the wrapper
knows only three kinds of connection, never individual models:

  kind = "cli"                       a coding-agent CLI login (no key)
  kind = "api", protocol = "openai"  any OpenAI-compatible endpoint
  kind = "api", protocol = "native"  a scanner-native provider (anthropic, ...)

`[llm.use]` names the profile per scanner ("skills" = SkillSpector, "mcp" =
Cisco runtime check). AGENT_GUARD_LLM overrides it for one run,
AGENT_GUARD_LLM_SKILLS / AGENT_GUARD_LLM_MCP for one scanner. A scanner
without a profile keeps the legacy env-based resolution.

The translators below are pure: they return a new environment and never read
or write files, so a model switch is a config edit, not a code change.
"""
from __future__ import annotations

import re
import shutil
from urllib.parse import urlsplit

import _providers

# "campaign" = budgeted scans via llm_scan.py (dollar ledger over HTTP).
SCANNERS = {"skills": "AGENT_GUARD_LLM_SKILLS", "mcp": "AGENT_GUARD_LLM_MCP",
            "campaign": "AGENT_GUARD_LLM_CAMPAIGN"}

_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _safe_url(value: str) -> bool:
    """https with a host, or plain http only to the local machine (parsed, not prefix-matched)."""
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    if not host:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and host in _LOCAL_HOSTS)

# Settings a profile owns. Stale values (e.g. from an old .env) are removed
# before the profile is applied, so an explicit profile is never mixed with a
# leftover model or endpoint.
_SKILLSPECTOR_OWNED = ("SKILLSPECTOR_PROVIDER", "SKILLSPECTOR_MODEL",
                       "SKILLSPECTOR_MODEL_REGISTRY", "SKILLSPECTOR_COMPAT_BASE_URL",
                       "SKILLSPECTOR_COMPAT_API_KEY")
_CISCO_OWNED_PREFIXES = ("MCP_SCANNER_LLM_", "MCP_SCANNER_DEFAULT_LLM_",
                         "AGENT_GUARD_CISCO_REASONING")


class ProfileError(ValueError):
    """A selected profile is missing or malformed."""


def _positive_int(name, profile, field, minimum=1):
    if field not in profile:
        return
    value = profile[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProfileError(f"profile {name}: {field} must be an integer >= {minimum}")


def _number(name, profile, field, low, high):
    if field not in profile:
        return
    value = profile[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ProfileError(f"profile {name}: {field} must be a number in [{low}, {high}]")


def _text(name, profile, field, pattern=None):
    value = profile.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ProfileError(f"profile {name}: {field} is required")
    if pattern is not None and not pattern.match(value):
        raise ProfileError(f"profile {name}: {field}={value!r} is not a valid name")
    return value


def _enabled(name, provider_id):
    try:
        _providers.check_enabled(provider_id)
    except _providers.DisabledProvider as exc:
        raise ProfileError(f"profile {name}: {exc}") from None


def _provider_of(profile):
    if profile["kind"] == "cli":
        return _providers.cli_for_binary(profile["cli"])
    if profile.get("protocol") == "openai":
        return _providers.get("openai_compatible")
    return _providers.get(profile["provider"])


def _settings(name, profile):
    settings = profile.get("settings", {})
    if not isinstance(settings, dict):
        raise ProfileError(f"profile {name}: settings must be a table")
    provider = _provider_of(profile)
    allowed = set(provider.settings)
    for var, value in settings.items():
        if var not in allowed:
            raise ProfileError(f"profile {name}: settings.{var} is not a setting of "
                               f"{provider.id}; allowed: {', '.join(sorted(allowed)) or 'none'}")
        if not isinstance(value, str) or not value.strip():
            raise ProfileError(f"profile {name}: settings.{var} must be a non-empty string")
        if var.endswith(("_URL", "_ENDPOINT")) and not _safe_url(value):
            raise ProfileError(f"profile {name}: settings.{var} must be https:// "
                               "(plain http only for localhost)")
        if var == "SKILLSPECTOR_COMPAT_BASE_URL" and profile.get("protocol") == "openai":
            raise ProfileError(f"profile {name}: settings.{var} is set by base_url")


def validate_profile(name: str, profile) -> dict:
    if not isinstance(profile, dict):
        raise ProfileError(f"profile {name} must be a table")
    kind = profile.get("kind")
    if kind == "cli":
        binary = _text(name, profile, "cli", _NAME)
        provider = _providers.cli_for_binary(binary)
        if provider is None or provider.kind != "cli":
            raise ProfileError(f"profile {name}: no SkillSpector CLI provider for {binary!r}")
        _enabled(name, provider.id)
    elif kind == "api":
        protocol = profile.get("protocol")
        _text(name, profile, "model")
        if protocol == "openai":
            url = _text(name, profile, "base_url")
            if not _safe_url(url):
                raise ProfileError(f"profile {name}: base_url must be https:// "
                                   "(plain http only for localhost)")
            _text(name, profile, "key_env", _ENV_NAME)
        elif protocol == "native":
            pid = _text(name, profile, "provider", _NAME)
            provider = _providers.get(pid)
            if provider is None or provider.kind != "api":
                raise ProfileError(f"profile {name}: unknown SkillSpector API provider {pid!r}")
            _enabled(name, pid)
            if provider.secrets or "key_env" in profile:
                _text(name, profile, "key_env", _ENV_NAME)
        else:
            raise ProfileError(f"profile {name}: protocol must be 'openai' or 'native'")
    else:
        raise ProfileError(f"profile {name}: kind must be 'cli' or 'api'")
    _settings(name, profile)
    if "model" in profile:
        _text(name, profile, "model")
    for field in ("context", "max_output", "timeout", "concurrency"):
        _positive_int(name, profile, field)
    _positive_int(name, profile, "retries", minimum=0)
    _number(name, profile, "retry_delay", 0, 600)
    _number(name, profile, "temperature", 0, 2)
    if "litellm_model" in profile:
        _text(name, profile, "litellm_model")
    if "reasoning" in profile and not isinstance(profile["reasoning"], bool):
        raise ProfileError(f"profile {name}: reasoning must be true or false")
    return profile


def select_profile(config: dict, scanner: str, env) -> tuple[str, dict] | None:
    """Return (name, profile) for `scanner`, or None for legacy resolution."""
    llm = config.get("llm")
    if not isinstance(llm, dict):
        return None
    name = (env.get(SCANNERS[scanner], "").strip()
            or env.get("AGENT_GUARD_LLM", "").strip()
            or str((llm.get("use") or {}).get(scanner, "")).strip())
    if not name:
        return None
    profiles = llm.get("profiles") or {}
    if name not in profiles:
        raise ProfileError(f"LLM profile {name!r} is not defined in [llm.profiles]")
    profile = validate_profile(name, profiles[name])
    if scanner == "mcp" and profile["kind"] != "api":
        raise ProfileError(f"profile {name}: the Cisco runtime check has no CLI path; "
                           "use a kind = \"api\" profile for [llm.use] mcp")
    if scanner == "campaign" and (profile["kind"], profile.get("protocol")) != ("api", "openai"):
        raise ProfileError(f"profile {name}: budgeted campaigns speak the OpenAI "
                           "protocol directly; use kind = \"api\", protocol = \"openai\"")
    return name, profile


def _key(profile, env):
    var = profile.get("key_env")
    return var, (env.get(var, "").strip() if var else "")


def skillspector_env(name: str, profile: dict, env, which=shutil.which):
    """Return (env, ready, reason, registry) for a SkillSpector run."""
    provider = _provider_of(profile)
    out = {k: v for k, v in env.items()
           if k not in _SKILLSPECTOR_OWNED and k not in provider.settings}
    ready, reason = True, f"profile {name}"
    model = profile.get("model", "").strip()
    out["SKILLSPECTOR_PROVIDER"] = provider.id
    # A provider setting in the environment that the profile does not set would
    # be dropped silently (SkillSpector then falls back to its own region or
    # endpoint, possibly another account). Fail closed and say where to move it.
    profile_sets = set(profile.get("settings", {}))
    if profile.get("protocol") == "openai":
        profile_sets.add("SKILLSPECTOR_COMPAT_BASE_URL")
    stray = next((v for v in provider.settings
                  if env.get(v, "").strip() and v not in profile_sets), None)
    if stray:
        ready, reason = False, (f"profile {name}: {stray} is set in the environment "
                                "but not in the profile's settings; move it into settings")
    elif profile["kind"] == "cli":
        if which(provider.binary):
            reason = f"profile {name}: {provider.binary} CLI (local login)"
        else:
            ready, reason = False, f"profile {name}: '{provider.binary}' is not on PATH"
    else:
        var, key = _key(profile, env)
        if profile["protocol"] == "openai":
            out["SKILLSPECTOR_COMPAT_BASE_URL"] = profile["base_url"]
        target = provider.secrets[0] if provider.secrets else None
        # A provider that takes no key ignores key_env altogether.
        if var and target:
            if key:
                out[target] = key
                reason = f"profile {name}: {provider.id} (API key)"
            else:
                ready, reason = False, f"profile {name}: {var} is not set"
    out.update(profile.get("settings", {}))
    if ready:
        for var in provider.required:
            if not out.get(var, "").strip():
                ready, reason = False, f"profile {name}: {var} is not set"
                break
    if model:
        out["SKILLSPECTOR_MODEL"] = model
    if "concurrency" in profile:
        out["SKILLSPECTOR_MAX_LLM_CONCURRENCY"] = str(profile["concurrency"])
    registry = None
    if model and ("context" in profile or "max_output" in profile):
        entry = {}
        if "context" in profile:
            entry["context_length"] = profile["context"]
        if "max_output" in profile:
            entry["max_output_tokens"] = profile["max_output"]
        registry = {"models": {model: entry}}
    return out, ready, reason, registry


def cisco_env(name: str, profile: dict, env):
    """Return (env, problem) for the Cisco runtime scan; problem is None when usable."""
    out = {k: v for k, v in env.items() if not k.startswith(_CISCO_OWNED_PREFIXES)}
    if profile["protocol"] == "openai":
        model = f"openai/{profile['model']}"
        out["MCP_SCANNER_LLM_BASE_URL"] = profile["base_url"]
    else:
        model = f"{profile['provider']}/{profile['model']}"
    out["MCP_SCANNER_LLM_MODEL"] = profile.get("litellm_model", model)
    mapping = {"max_output": "MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS",
               "timeout": "MCP_SCANNER_LLM_TIMEOUT",
               "retries": "MCP_SCANNER_LLM_MAX_RETRIES",
               "retry_delay": "MCP_SCANNER_LLM_RETRY_BASE_DELAY",
               "temperature": "MCP_SCANNER_DEFAULT_LLM_TEMPERATURE"}
    for field, var in mapping.items():
        if field in profile:
            out[var] = str(profile[field])
    if profile.get("reasoning"):
        # Cisco only recognises reasoning models by name; _cisco_boot.py applies
        # its reasoning request rule to this profile's model as well.
        out["AGENT_GUARD_CISCO_REASONING"] = "1"
    var, key = _key(profile, env)
    # Only the requirement is dropped for a native provider without secrets; a
    # key that is present is still forwarded. A litellm_model override may name
    # a keyed backend, so it keeps the requirement.
    keyless = (profile["protocol"] != "openai" and "litellm_model" not in profile
               and not _provider_of(profile).secrets)
    if var and not key and not keyless:
        return out, f"profile {name}: {var} is not set"
    if key:
        out["MCP_SCANNER_LLM_API_KEY"] = key
    return out, None
