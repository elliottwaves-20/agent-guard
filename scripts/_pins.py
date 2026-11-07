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
a local shim). Since 54921c8 it also carries #855 (CLI prompts stay under the
input cap when large files are batched), #856 (security discovery shares the
LLM limiter) and #882 (code fence lines no longer merge shell lines). Since
9adb1a6 it also carries #872, #929 and #949 (a local matcher timeout no
longer stops later files). Since 6d0b7c8 it also carries #752 (info_stealer
needs a browser cookie-store path, so our corrected rule no longer applies),
#801 and #902 (fewer false parser limits from JavaScript template literals
and from backticks or apostrophes in prose), #947, #952 (locked npm
dependency contents), #955 and #957. Since
#798 SkillSpector refuses --output on Windows, so reports are read from stdout.
tests/test_pins.py checks on GitHub that main contains it. The 2.13.x release
tags sit on a separate branch without #855/#856, so the pin stays on main.
"""
SKILLSPECTOR_VERSION = "2.12.0"
SKILLSPECTOR_REPO = "https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA = "6d0b7c849949cab9181e57798247f89e48ce5d6a"

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
# malcontent 1.28.0-r0 (released 2026-10-27): Chainguard's free registry only
# serves the daily rebuilt :latest, so the pin is one build of it (2026-10-28
# 20:49 UTC, the minimal variant without a shell), as picked by
# `check_image_pins.py --malcontent-candidate 1.28.0` on 2026-11-07.
MALCONTENT_VERSION = "1.28.0"
MALCONTENT_IMAGE = ("cgr.dev/chainguard/malcontent:latest@sha256:"
                    "e78ef39008129f3211dc21bf40fd0add5955ff3f045ee671e62dc3a250bf3855")
