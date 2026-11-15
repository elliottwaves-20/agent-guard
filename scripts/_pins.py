"""Single source for the scanner pins (SkillSpector, Cisco mcp-scanner, images).

setup.sh / setup.ps1 install exactly these commits (a test keeps them in sync);
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
a local shim). Since 54921c8 it also carries #855 (CLI prompts stay under the
input cap when large files are batched), #856 (security discovery shares the
LLM limiter) and #882 (code fence lines no longer merge shell lines). Since
9adb1a6 it also carries #872, #929 and #949 (a local matcher timeout no
longer stops later files). Since 6d0b7c8 it also carries #752 (info_stealer
needs a browser cookie-store path, so our corrected rule no longer applies),
#801 and #902 (fewer false parser limits from JavaScript template literals
and from backticks or apostrophes in prose), #947, #952 (locked npm
dependency contents), #955 and #957. Since e48d771 it also carries #814
(command lines inside a word that spans lines), #848 (PowerShell host syntax
no longer invents shell parse limits), #916 (locked dependencies past
published advisories), #1051 (one LLM batch admission shared across
analyzers) and #1048 (accounted refusals). Malformed LLM answers now get a
bounded field-by-field recovery; its calls go through the same patched
get_chat_model, and an unfinished recovery is reported as a partial
inspection, which still ends in no verdict. Since
#798 SkillSpector refuses --output on Windows, so reports are read from stdout.
tests/test_pins.py checks on GitHub that main contains it. The 2.13.x release
tags sit on a separate branch without #855/#856, so the pin stays on main.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_REPO = "https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA = "e48d771a26f7398b36256ceb8d8f94adce3d5c44"

# Cisco mcp-scanner (optional live MCP runtime check), pinned like SkillSpector
# to a commit on the official main branch. The newest PyPI release (4.8.7)
# still pins litellm==1.93.2, which carries published advisories
# (GHSA-7hp6-4w63-5g45, GHSA-g5ff-637f-6q2m). Main since #289 accepts any
# litellm>=1.93.2 (minus a few excluded versions) instead of pinning 1.93.2, so
# the setup adds litellm>=1.106.5 (past those advisories) and excludes the
# compromised 1.107.0 upload, independent of what the resolver would pick. A
# known vulnerability is the one case where we install ahead of an official
# release; move back to a PyPI release once one allows litellm>=1.106.5.
# 9ff8fc8 is main of 2026-11-06 (package version 4.8.7).
CISCO_MCP_SCANNER_VERSION = "4.8.7"
CISCO_MCP_SCANNER_REPO = "https://github.com/cisco-ai-defense/mcp-scanner"
CISCO_MCP_SCANNER_SHA = "9ff8fc84b792aae315a838cf4e37b40ef46a0293"
CISCO_LITELLM_REQUIREMENT = "litellm>=1.106.5,!=1.107.0"

# Dependency window for every `uv tool install` in the setup scripts. A pinned
# commit fixes the scanner code, not its dependencies: `uv tool install git+...`
# resolves them fresh and ignores the project's uv.lock. --exclude-newer limits
# registry packages to files uploaded before this instant, so a release from
# the days before a setup run cannot slip in (git sources are not affected,
# hence the commit pins). It is a fixed date rather than "now minus 7 days" so
# a setup run is reproducible; raise it with every scanner pin bump, to a
# moment at least 7 days back (a test checks the 7 days).
UV_EXCLUDE_NEWER = "2026-11-08T09:00:00Z"

# Scanner images, pinned by digest. Docker runs the
# digest; the tag only keeps the line readable. GuardDog and malcontent carry
# their rules inside the image and fetch no signatures at run time, so a newer
# rule set only arrives with a new release. Never fall back to a moving tag:
# an unavailable digest ends in no verdict. Bump by hand once a newer release
# is at least 7 days old and the offline suite is green;
# scripts/check_image_pins.py reports newer releases and finds candidates.
#
# GuardDog 3.2.0 (released 2026-08-12): ghcr.io/datadog/guarddog:3.2.0, the
# build of DataDog's tag-release.yml that also carries :v3 and :latest.
GUARDDOG_VERSION = "3.2.0"
GUARDDOG_IMAGE = ("ghcr.io/datadog/guarddog:3.2.0@sha256:"
                  "3dbc783f65f508b95222101cb2cd84d1d5f3e3675e42d6f1329bb9b8a99c8998")
# malcontent 1.28.1 (released 2026-11-08): Chainguard's free registry only
# serves the daily rebuilt :latest, so the pin is one build of it (2026-11-08
# 20:26 UTC, the minimal variant without a shell), picked with the selection
# of `check_image_pins.py --malcontent-candidate 1.28.1` on 2026-11-15, about
# ten hours before the build turned 7 days old (bundled with the SkillSpector
# and Cisco environment bumps by the user's decision).
MALCONTENT_VERSION = "1.28.1"
MALCONTENT_IMAGE = ("cgr.dev/chainguard/malcontent:latest@sha256:"
                    "98734fbb8de4510ac4f5b6e820b74e38d5bd528884e579a2c44afa57aeba0fcf")
