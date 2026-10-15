"""Single source for the SkillSpector pin.

setup.sh / setup.ps1 install exactly this commit (a test keeps them in sync);
the budget adapter and the installed-scanner tests compare against it. Bump
deliberately: the adapter patches SkillSpector internals and must be
re-verified against every new release.

Until SkillSpector 2.13.0 ships, the pin is a reviewed commit on NVIDIA's main
branch (package version 2.12.0). It carries the merged fixes agent-guard relies
on: concurrent TP4 batches (#731), the --remove flag reading (#697) and fewer
false parser limits behind AE1 (#627, #634, #661, #686). Since 532f67c it also
carries #704, #709, #737 (codex_cli disabled) and #738, plus the gemini provider
that signs in through Application Default Credentials. Since 2404212 it also
carries #779 (a command wrapper with no command is complete) and #810
(OpenCode keeps its internal plugins, so the ChatGPT OAuth login works without
a local shim). tests/test_pins.py
checks on GitHub that main contains it. Move to the release tag with 2.13.0.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_REPO = "https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA = "240421219409dc0bafef9f618a10d80c2d7e83a3"
