"""Single source for the SkillSpector pin.

setup.sh / setup.ps1 install exactly this commit (a test keeps them in sync);
the budget adapter and the installed-scanner tests compare against it. Bump
deliberately: the adapter patches SkillSpector internals and must be
re-verified against every new release.

Until SkillSpector 2.13.0 ships, the pin is v2.12.0 plus the merged upstream
fix NVIDIA/SkillSpector#697 (cherry-picked unchanged, files identical to the
merge 9ee7fbf), published on a branch of the agent-guard maintainer's fork.
It stops a CLI flag such as `--remove` in documentation from being read as
an obfuscated text-removal directive. Return to NVIDIA with the next release.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_REPO = "https://github.com/elliottwaves-20/SkillSpector"
SKILLSPECTOR_SHA = "92bb52130513e9482f8e59fb580965ff6f9430cb"

# What the fork pin must be, checked against GitHub by tests/test_pins.py:
# exactly the files of the upstream merge, on top of the v2.12.0 release commit.
# Drop this block when the pin returns to NVIDIA.
FORK_BASE_SHA = "c7958a3268d9498644b22edb75d0f051bbc8cbfc"      # NVIDIA v2.12.0
FORK_UPSTREAM_MERGE = "9ee7fbf36af68ec46465758e57b322ed0ca8a514"  # NVIDIA #697 merge
FORK_FILES = ("src/skillspector/security_reconstruction.py",
              "tests/nodes/analyzers/test_security_reconstruction.py")
