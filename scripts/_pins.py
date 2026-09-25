"""Single source for the SkillSpector pin.

setup.sh / setup.ps1 install exactly this commit (a test keeps them in sync);
the budget adapter and the installed-scanner tests compare against it. Bump
deliberately: the adapter patches SkillSpector internals and must be
re-verified against every new release.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_SHA = "c7958a3268d9498644b22edb75d0f051bbc8cbfc"
