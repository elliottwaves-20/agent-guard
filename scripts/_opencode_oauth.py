"""Keep OpenCode's internal OAuth plugins enabled for SkillSpector's opencode_cli.

SkillSpector 2.12 sets OPENCODE_DISABLE_DEFAULT_PLUGINS=1 for every
`opencode run`. That switch also turns off OpenCode's built-in auth plugins,
so a ChatGPT or Copilot login can no longer reach its provider
(NVIDIA/SkillSpector#809, fix proposed in #810). External plugins stay off
through OPENCODE_PURE and the isolated config, which this shim leaves alone.

Runs inside SkillSpector's tool environment. Once upstream stops setting the
switch, removing it here changes nothing.
"""

import dataclasses

_SWITCH = "OPENCODE_DISABLE_DEFAULT_PLUGINS"
_MARK = "_agent_guard_keeps_oauth_plugins"


def keep_oauth_plugins() -> bool:
    """Wrap SkillSpector's OpenCode env builder; return whether it is wrapped."""
    try:
        from skillspector.providers import _agent_cli
    except ImportError:
        return False
    prepare = getattr(_agent_cli, "_prepare_opencode_env", None)
    if prepare is None:
        return False
    if getattr(prepare, _MARK, False):
        return True

    def prepare_with_oauth_plugins(*args, **kwargs):
        env = prepare(*args, **kwargs)
        env.pop(_SWITCH, None)
        return env

    setattr(prepare_with_oauth_plugins, _MARK, True)
    _agent_cli._prepare_opencode_env = prepare_with_oauth_plugins
    # Inference reads the builder from the frozen registry entry that was
    # bound at import time, so that entry needs the wrapped builder too.
    registry = getattr(_agent_cli, "_REGISTRY", {})
    spec = registry.get("opencode")
    if spec is not None and getattr(spec, "prepare_env", None) is prepare:
        registry["opencode"] = dataclasses.replace(spec, prepare_env=prepare_with_oauth_plugins)
    return True
