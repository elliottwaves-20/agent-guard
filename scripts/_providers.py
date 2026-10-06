"""Which SkillSpector LLM providers exist, what each one needs, and which are refused.

The single source for the profile layer (_llm_profile) and the legacy resolution
(_skillspector). Taken from SkillSpector's provider code at the pinned commit
(providers/*/provider.py, providers/_agent_cli.py), never from its README.
Re-check it on every pin change (MAINTENANCE.md).
"""
from __future__ import annotations

from dataclasses import dataclass

CODEX_DISABLED = (
    "codex_cli is disabled: Codex's read-only sandbox still lets model-driven commands "
    "read files on this machine, and scanned content could steer it there "
    "(NVIDIA/SkillSpector#737). Use claude or opencode, or an API provider.")
ANTIGRAVITY_DISABLED = (
    "antigravity_cli is disabled: agy prints nothing to a pipe, so SkillSpector "
    "cannot read its answer. Use claude or opencode, or an API provider.")


class DisabledProvider(ValueError):
    """A provider SkillSpector registers but agent-guard refuses to run."""


@dataclass(frozen=True)
class Provider:
    id: str
    kind: str                 # "cli" or "api"
    binary: str = ""          # cli only
    secrets: tuple = ()       # credential variables; the first receives key_env
    settings: tuple = ()      # non-secret variables a profile may set
    required: tuple = ()      # must be non-empty for the provider to run
    markers: tuple = ()       # model-name markers for leftover legacy settings
    disabled: str = ""        # non-empty: refused everywhere, with this reason


_ALL = (
    Provider("claude_cli", "cli", binary="claude", markers=("claude",)),
    Provider("gemini_cli", "cli", binary="gemini", markers=("gemini",)),
    Provider("opencode_cli", "cli", binary="opencode"),
    Provider("codex_cli", "cli", binary="codex", disabled=CODEX_DISABLED),
    Provider("antigravity_cli", "cli", binary="agy", disabled=ANTIGRAVITY_DISABLED),
    Provider("anthropic", "api", secrets=("ANTHROPIC_API_KEY",),
             settings=("ANTHROPIC_BASE_URL",), required=("ANTHROPIC_API_KEY",),
             markers=("claude",)),
    Provider("openai", "api", secrets=("OPENAI_API_KEY",),
             settings=("OPENAI_BASE_URL", "OPENAI_PROJECT_ID"), required=("OPENAI_API_KEY",)),
    Provider("nv_build", "api", secrets=("NVIDIA_INFERENCE_KEY",),
             required=("NVIDIA_INFERENCE_KEY",)),
    Provider("nv_inference", "api", secrets=("NVIDIA_INFERENCE_KEY",),
             required=("NVIDIA_INFERENCE_KEY",)),
    Provider("anthropic_proxy", "api", secrets=("ANTHROPIC_PROXY_API_KEY",),
             settings=("ANTHROPIC_PROXY_ENDPOINT_URL", "ANTHROPIC_PROXY_API_VERSION"),
             required=("ANTHROPIC_PROXY_API_KEY", "ANTHROPIC_PROXY_ENDPOINT_URL")),
    Provider("azure_openai", "api", secrets=("AZURE_OPENAI_API_KEY",),
             settings=("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT",
                       "AZURE_OPENAI_API_VERSION"),
             required=("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT")),
    Provider("openai_compatible", "api", secrets=("SKILLSPECTOR_COMPAT_API_KEY",),
             settings=("SKILLSPECTOR_COMPAT_BASE_URL",),
             required=("SKILLSPECTOR_COMPAT_API_KEY", "SKILLSPECTOR_COMPAT_BASE_URL")),
    # Credentials resolved by the provider itself: boto3 chain, local service, Google ADC.
    Provider("bedrock", "api", settings=("AWS_PROFILE", "AWS_REGION")),
    Provider("ollama", "api", settings=("OLLAMA_BASE_URL",)),
    Provider("gemini", "api", settings=("GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION"),
             required=("GOOGLE_CLOUD_PROJECT",), markers=("gemini",)),
)
CATALOG = {p.id: p for p in _ALL}

AUTODETECT_KEYS = ("anthropic", "openai", "nv_build")
# gemini_cli stays usable when named explicitly, but is not auto-picked: Google no
# longer offers the CLI login to personal subscriptions (checked 2026-10-06).
AUTODETECT_CLIS = ("claude_cli", "opencode_cli")

ALIASES = {p.binary: p.id for p in _ALL if p.kind == "cli"}
ALIASES.update({"openai-compatible": "openai_compatible", "custom-openai": "openai_compatible"})


def get(provider_id: str) -> Provider | None:
    return CATALOG.get(provider_id)


def cli_for_binary(binary: str) -> Provider | None:
    return CATALOG.get(ALIASES.get(binary, ""))


def check_enabled(provider_id: str) -> Provider:
    provider = CATALOG[provider_id]
    if provider.disabled:
        raise DisabledProvider(provider.disabled)
    return provider
