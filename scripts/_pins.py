"""Single source for the scanner pins (SkillSpector, Cisco mcp-scanner, images).

setup.sh / setup.ps1 install exactly these commits (a test keeps them in sync);
the budget adapter and the installed-scanner tests compare against it. Bump
deliberately: the adapter patches SkillSpector internals and must be
re-verified against every new release.

The SkillSpector pin is the commit of the newest NVIDIA release tag that is at
least 7 days old; a main commit only for a fix no such release carries yet.
Since v2.13.2 the releases are cut from main (tag v2.13.7 = c323ad4, an
ancestor of main), so a release carries every earlier main fix.
tests/test_pins.py checks on GitHub that the pin is the tag's commit and that
main contains it. It is installed from Git, never from the PyPI package
`skillspector`: OSV lists that name as malware campaign MAL-2026-6561.

v2.13.7 (c323ad4) carries every fix of the earlier main pins listed below and
adds #1148 (locked pyasn1, cryptography and pyjwt past published advisories),
#1127, #1118, #1130, #1161 (host Git templates stay out of URL scans), #1180,
#1183 and a large batch of parser corrections. The earlier main pins carried,
in order: concurrent TP4 batches (#731), the --remove flag reading (#697) and fewer
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
inspection, which still ends in no verdict. Since c816150 it also carries
#1077 (bounded token-gap compaction for mixed scripts), #1092 (an unforced
tool-call binding when a gateway rejects json_schema; it reuses the same
patched model, and a second rejection still ends the batch), #1027
(--exclude globs on Windows), #1087, #1095 (langgraph past
GHSA-3fx2-cqw9-xr3c), #980 (prompt token counting that never downloads a
vocabulary) and #1123. Since
#798 SkillSpector refuses --output on Windows, so reports are read from stdout.
"""
SKILLSPECTOR_VERSION = "2.13.7"
SKILLSPECTOR_REPO = "https://github.com/NVIDIA/SkillSpector"
SKILLSPECTOR_SHA = "c323ad4c43e3c8f2de051572cc25b2711d11e648"

# Cisco mcp-scanner (optional live MCP runtime check), pinned like SkillSpector
# to a commit on the official main branch. The newest PyPI release (4.8.7)
# still pins litellm==1.93.2, which carries published advisories
# (GHSA-7hp6-4w63-5g45, GHSA-g5ff-637f-6q2m). Main since #289 accepts any
# litellm>=1.93.2 (minus a few excluded versions) instead of pinning 1.93.2, so
# the setup adds litellm>=1.106.5 (past those advisories) and excludes the
# compromised 1.107.0 upload, independent of what the resolver would pick. A
# known vulnerability is the one case where we install ahead of an official
# release; move back to a PyPI release once one allows litellm>=1.106.5.
# 8c3cae1 is main of 2026-11-19 (package version 4.8.7).
CISCO_MCP_SCANNER_VERSION = "4.8.7"
CISCO_MCP_SCANNER_REPO = "https://github.com/cisco-ai-defense/mcp-scanner"
CISCO_MCP_SCANNER_SHA = "8c3cae130a12afb7b3abfe9c8a4e2a5e2b103735"
CISCO_LITELLM_REQUIREMENT = "litellm>=1.106.5,!=1.107.0"

# Dependency window for every `uv tool install` in the setup scripts. A pinned
# commit fixes the scanner code, not its dependencies: `uv tool install git+...`
# resolves them fresh and ignores the project's uv.lock. --exclude-newer limits
# registry packages to files uploaded before this instant, so a release from
# the days before a setup run cannot slip in (git sources are not affected,
# hence the commit pins). It is a fixed date rather than "now minus 7 days" so
# a setup run is reproducible; raise it with every scanner pin bump, to a
# moment at least 7 days back (a test checks the 7 days).
UV_EXCLUDE_NEWER = "2026-11-20T00:00:00Z"

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

# Runtimes of the MCP sandbox image (scan_mcp.py), from official images pinned
# by digest. Pick a maintained line that MCP packages support and its latest
# patch, not the newest line (Python 3.14 over 3.15: same security fixes, wider
# package support; user, 2026-11-24). Docker Library rebuilds its tags daily, so
# a digest is the newest build of the version that is at least 2 days old
# (history: github.com/docker-library/repo-info, repos/<image>/remote/<tag>.md).
# check_image_pins.py reports new patches, uv releases and end of life;
# tests/test_sandbox_image.py checks the built image.
SANDBOX_NODE = "26.13.1"     # LTS, released 2026-11-10 (security release)
SANDBOX_NODE_IMAGE = ("node:26.13.1-trixie-slim@sha256:"
                      "e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc")
SANDBOX_PYTHON = "3.14.10"   # released 2026-10-25
SANDBOX_PYTHON_IMAGE = ("python:3.14.10-slim-trixie@sha256:"
                        "9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f")
SANDBOX_UV = "0.13.9"        # released 2026-11-17, image attested by astral-sh/uv
SANDBOX_UV_IMAGE = ("ghcr.io/astral-sh/uv:0.13.9@sha256:"
                    "d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d")
