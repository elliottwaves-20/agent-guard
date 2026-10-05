"""Single source for the SkillSpector pin.

setup.sh / setup.ps1 install exactly this commit (a test keeps them in sync);
the budget adapter and the installed-scanner tests compare against it. Bump
deliberately: the adapter patches SkillSpector internals and must be
re-verified against every new release.

Until SkillSpector 2.13.0 ships, the pin is a reviewed commit on NVIDIA's main
branch (package version 2.12.0). It carries the merged fixes agent-guard relies
on: concurrent TP4 batches (#731), the --remove flag reading (#697) and fewer
false parser limits behind AE1 (#627, #634, #661, #686). tests/test_pins.py
checks on GitHub that main contains it. Move to the release tag with 2.13.0.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_REPO = "https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA = "532f67c72f453b55ddff302c8e578e50336cf4f2"
