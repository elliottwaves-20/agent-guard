# Changelog

## 0.3.0 - 2026-09-04

Scanner upgrades plus a rework of how the wrapper drives SkillSpector's LLM
layer. Existing `.env` files keep working, except the removed legacy variables
noted below.

### SkillSpector LLM layer: CLI subscription instead of API keys

- Bump the pinned SkillSpector build from v2.1.4 to the commit behind release
  **v2.11.0**. Upstream now ships tagged releases; the pin stays on the exact
  commit so "scan = install" still applies to the scanner itself.
- `SKILLSPECTOR_PROVIDER` now accepts every upstream provider, including the
  coding-agent CLIs `claude_cli`, `codex_cli`, `gemini_cli` (the user's existing
  login, no API key) and the native `anthropic` provider. The 0.2.0 rule
  "Anthropic runs static-only" is gone — the upstream limitation it worked
  around no longer exists.
- Provider auto-detection when `SKILLSPECTOR_PROVIDER` is unset: a hosted key
  in the environment wins, then the first of `claude`, `codex`, `gemini` found
  on PATH. `.env.example` now recommends `claude_cli` as the default.
- New `AGENT_GUARD_STATIC_ONLY=1` forces static-only regardless of providers.
- The scan banner and the verdict line state which provider ran, or why the
  scan was static-only.
- A `SKILLSPECTOR_MODEL` from another vendor (e.g. a leftover `gpt-*` with
  `claude_cli`) is dropped with a note instead of failing every LLM call.
- New `scripts/_skillspector_boot.py`: SkillSpector is started inside its own
  tool environment with its aggregate scan deadline raised from the hard-coded
  60 s to `SKILLSPECTOR_MAX_WORKFLOW_SECONDS` (default: scan timeout minus
  60 s). CLI providers exhausted the upstream budget on medium-sized skills
  ("shared runtime limit reached", partial report, NO VERDICT). Upstream
  issue NVIDIA/SkillSpector#460 / PR #468 adopt the same variable; the shim is
  a no-op once the pinned build honours it natively.

### Fail-closed verdict updated to the SkillSpector 2.5–2.11 report contract

- `execution_successful: false` (top-level or in `analysis_completeness`) is a
  blocking validation failure (exit 2) and prints the `ledger_exceptions`.
- LLM completeness is judged from report metadata (`llm_requested`,
  `llm_available`, `llm_error`, `llm_calls_attempted/succeeded`) instead of
  stderr string matching. A partial LLM run is retried and, if still partial,
  blocks with NO VERDICT.
- `risk_assessment.max_issue_severity` feeds the HIGH/CRITICAL gate.
- Coverage caveats (`entirely_uninspected_files`, `partially_inspected_files`,
  `limitations`, `scope_exclusions`) are printed as `LIMIT:` lines with the
  verdict.
- Removed the wrapper-side "LLM source tree" filter that scanned a *copy* of the
  skill with binaries, archives, lockfiles and large files stripped out. It hid
  those files from the static/YARA layer too; SkillSpector's own resource bounds
  and its new hidden/nested-archive inspection now see the full tree.

### CLI-tool scans

- `scan_cli.py cargo` now runs Datadog GuardDog's `crates` scan (GuardDog 3.2.0)
  in addition to the SkillSpector static scan of the crate source; the worse
  verdict wins.

### Other

- `install_skill.py`: the default workspace probe no longer hardcodes a
  German-locale OneDrive folder; it globs `~/OneDrive/*/Github`, and
  `AGENT_GUARD_WORKSPACE` overrides the choice.
- `.env` loader strips inline `# comments` after a value.
- Cisco `cisco-ai-mcp-scanner` upgraded to 4.8.4 (dynamic tool-registration
  detection, transient-error retry).
- Docs: README, SKILL.md and `.env.example` rewritten for the provider model
  above, including why the scan uses its own isolated LLM process rather than
  the installing agent's judgment.

### Removed

- The legacy `SKILL_SCANNER_LLM_*` variables (0.1.x) are no longer read.

## 0.2.0 - 2026-06-15

- Add provider-aware `scan_skill.py` wrapper for skill scans.
- Share SkillSpector static-scan verdict logic between skill scans and MCP Stage 1.
- Require OpenAI or NVIDIA credentials for full SkillSpector LLM coverage.
- Separate Cisco runtime MCP LLM configuration via `MCP_SCANNER_LLM_*`; Cisco can use any LiteLLM-supported provider.
- Document that Anthropic under SkillSpector runs static-only in this pinned integration, while Cisco runtime provider choice is independent.
