#!/usr/bin/env python3
"""
Shared SkillSpector integration for agent-guard.

NVIDIA SkillSpector is the static scanner behind both wrappers:
  - scan_skill.py  -- skills / plugins
  - scan_mcp.py    -- the static MCP source scan (Stage 1)

This module centralises the provider-aware LLM resolution, the cross-platform
invocation (forcing UTF-8 so SkillSpector's report renders on legacy Windows
consoles), and the fail-closed verdict, so both wrappers share one source of
truth for how a scan is run and judged.

LLM providers: SkillSpector's semantic analyzers run against whatever
SKILLSPECTOR_PROVIDER names. The recommended default is a coding-agent CLI
(claude_cli / opencode_cli / gemini_cli): the scanner starts the CLI as a separate
tool-less process, feeds the untrusted content via stdin, and validates the
answer against a JSON schema -- so the scanning LLM stays isolated from the
agent that later installs the skill, and no API key is needed. Hosted API
providers (anthropic, openai, nv_build, ...) remain fully supported.
"""

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _console_text(value) -> str:
    text = str(value)
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def _console_err_text(value) -> str:
    text = str(value)
    encoding = getattr(sys.stderr, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        # Strip an inline "# comment" (only when separated by whitespace) and quotes.
        value = value.split(" #", 1)[0].split("\t#", 1)[0]
        value = value.strip().strip('"').strip("'")
        os.environ[key] = value


def load_agent_guard_env() -> None:
    if os.environ.get("AGENT_GUARD_NO_DOTENV"):
        return
    script_root = Path(__file__).resolve().parents[1]
    candidates: list[Path] = []
    explicit = os.environ.get("AGENT_GUARD_ENV_FILE", "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    # Only the trusted installation config is implicit. A target checkout
    # must never configure the scanner through its working/parent directory.
    candidates.append(script_root / ".env")
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_env_file(resolved)


load_agent_guard_env()

# The personal config (LLM profiles, local distribution) is read once, right
# after the env files. A config that exists but is unsafe or unreadable stops
# every wrapper before anything is scanned -- ignoring it silently would run
# the scan with settings the user did not choose.
import _llm_profile
import _providers
from _parse_spans import PARSE_SPAN_ANALYZERS
import _user_config
try:
    USER_CONFIG = _user_config.load_config()
    # (name, profile) for SkillSpector, or None for the legacy env resolution.
    LLM_PROFILE = _llm_profile.select_profile(USER_CONFIG, "skills", os.environ)
except (_user_config.ConfigError, _llm_profile.ProfileError) as exc:
    print(f"ERROR: agent-guard config: {exc}", file=sys.stderr)
    sys.exit(2)

SKILLSPECTOR = shutil.which("skillspector")
BOOT = Path(__file__).with_name("_skillspector_boot.py")
SKILLSPECTOR_CMD: list | None = None   # resolved lazily by skillspector_command()

# Hard cap on a single scan, so a hanging scan never blocks forever.
# (SCAN_MCP_TIMEOUT kept for backwards compatibility with the old MCP-only knob.)
SCAN_TIMEOUT = int(os.environ.get("AGENT_GUARD_SCAN_TIMEOUT")
                   or os.environ.get("SCAN_MCP_TIMEOUT", "600"))

# SkillSpector >= 2.11.1 reads this deadline natively. Leave time for
# reporting before the parent subprocess timeout.
WORKFLOW_BUDGET = int(os.environ.get("SKILLSPECTOR_MAX_WORKFLOW_SECONDS")
                      or str(max(60, SCAN_TIMEOUT - 60)))

# stderr markers of a provider failure that a whole-scan repeat can actually fix:
# the provider was briefly unreachable or busy, not refusing us on quota.
LLM_TRANSIENT_FAILURE_MARKERS = (
    "APIConnectionError",
    "overloaded",
)

# Quota refusals. These are deliberately NOT retried. SkillSpector does not retry
# a 429 either -- `_is_retryable_api_connection_error` only accepts
# APIConnectionError -- it drops the batch and reports a degraded LLM stage. Re-running
# the whole scan would re-issue every prompt, including the ones that already
# succeeded, so on a rate-limited provider our retry multiplies exactly the requests
# the provider just refused. The fix is fewer requests in flight
# (SKILLSPECTOR_MAX_LLM_CONCURRENCY), not more attempts.
LLM_RATE_LIMIT_MARKERS = (
    "rate_limit_exceeded",
    "Rate limit reached",
    "HTTP 429",
    "429",
    "tokens per min",
    "requests per min",
    "quota_exceeded",
    # Bedrock speaks SigV4, not HTTP status codes, and boto3 has already spent
    # its own retry budget by the time this reaches us.
    "ThrottlingException",
    "Too many requests",
)
LLM_RETRIES = int(os.environ.get("AGENT_GUARD_LLM_RETRIES", "0"))

# Mirror of SkillSpector's own --fail-on-incomplete, which is opt-in upstream:
# by default the scanner does not fail a scan just because
# analysis_completeness.is_complete is false. Set to 1 to demand a fully
# complete inspection before any verdict is given.
FAIL_ON_INCOMPLETE = os.environ.get("AGENT_GUARD_FAIL_ON_INCOMPLETE", "").strip() == "1"
LLM_RETRY_BASE_DELAY = int(os.environ.get("AGENT_GUARD_LLM_RETRY_BASE_DELAY", "20"))


def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# -- bounded subprocess execution ---------------------------------------------
# A scan child spawns further processes: SkillSpector starts the coding-agent
# CLI, and on Windows that CLI is usually an npm .cmd shim (cmd.exe -> node ->
# the real worker). Killing only the direct child -- what
# subprocess.run(timeout=...) does -- leaves those workers running, still
# talking to the provider and still spending the user's subscription long after
# the wrapper gave up. Every long-running scan child therefore goes through
# run_bounded(), which terminates the whole tree.

TREE_KILL_GRACE = 30  # seconds to reap the tree after the kill signal


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Kill `proc` and every process it started. Best effort, never raises."""
    if os.name == "nt":
        # taskkill /T walks the parent-PID tree, which the .cmd shim chain
        # preserves; /F skips the graceful close no console-less child answers.
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=TREE_KILL_GRACE)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    # Backstop: the direct child, in case the tree kill missed it.
    try:
        proc.kill()
    except OSError:
        pass


def combine_verdicts(*codes: int) -> int:
    """Fail-closed merge of several stage exit codes: any BLOCK (1) wins, so its
    findings are not hidden behind a no-verdict stage; any other non-zero code
    (2, or anything unexpected) is NO VERDICT; only all-zero is SAFE."""
    if 1 in codes:
        return 1
    if any(code != 0 for code in codes):
        return 2
    return 0


def run_bounded(cmd: list, *, env: dict | None = None, timeout: float,
                cwd: str | None = None) -> subprocess.CompletedProcess:
    """subprocess.run(capture_output, text) with a process-TREE deadline.

    On timeout the whole tree is killed and subprocess.TimeoutExpired is
    raised, carrying whatever output was captured. A KeyboardInterrupt (the
    user pressing Ctrl-C) kills the tree too, so an aborted scan leaves no
    orphaned CLI workers behind.
    """
    popen_kwargs = {}
    if os.name != "nt":
        # Own process group so killpg reaches the descendants.
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace",
                            env=env, cwd=cwd, **popen_kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_tree(proc)
        try:
            out, err = proc.communicate(timeout=TREE_KILL_GRACE)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
    except BaseException:
        # Ctrl-C and anything else unwinding through here: no orphans.
        _terminate_tree(proc)
        try:
            proc.communicate(timeout=TREE_KILL_GRACE)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def need_skillspector():
    if SKILLSPECTOR is None:
        die("skillspector not found on PATH. Run setup.sh / setup.ps1 first.")


def skillspector_python() -> str | None:
    """Python interpreter of SkillSpector's uv tool environment, or None."""
    uv = shutil.which("uv")
    if uv is None:
        return None
    try:
        tool_dir = subprocess.run([uv, "tool", "dir"], capture_output=True,
                                  text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if tool_dir.returncode != 0 or not tool_dir.stdout.strip():
        return None
    root = Path(tool_dir.stdout.strip()) / "skillspector"
    for candidate in (root / "Scripts" / "python.exe", root / "bin" / "python"):
        if candidate.exists():
            return str(candidate)
    return None


def skillspector_command() -> list:
    """Command prefix that runs SkillSpector: the bootstrap inside its own
    tool environment when available, otherwise
    the plain `skillspector` executable."""
    global SKILLSPECTOR_CMD
    if SKILLSPECTOR_CMD is not None:
        return list(SKILLSPECTOR_CMD)
    py = skillspector_python() if BOOT.is_file() else None
    if py:
        SKILLSPECTOR_CMD = [py, str(BOOT)]
    else:
        print("  NOTE: SkillSpector tool environment not found; running the plain "
              "`skillspector` binary with its native environment configuration.")
        SKILLSPECTOR_CMD = [SKILLSPECTOR]
    return list(SKILLSPECTOR_CMD)


# -- provider-aware LLM resolution --------------------------------------------
# This provider config is for SkillSpector only. scan_mcp.py has a separate
# Cisco runtime LLM config based on MCP_SCANNER_LLM_* (LiteLLM; no CLI path).

# Coding-agent CLIs SkillSpector can drive with the user's existing login, in
# auto-detection order. Refused providers (Codex, Antigravity) are not listed.
CLI_PROVIDERS = {pid: _providers.CATALOG[pid].binary for pid in _providers.AUTODETECT_CLIS}
# Hosted providers and the env vars they need (shared with the profile layer).
KEY_PROVIDERS = {p.id: p.required for p in _providers.CATALOG.values()
                 if p.kind == "api" and not p.disabled}
# Auto-detection only considers the unambiguous key providers, in this order.
KEY_AUTODETECT_ORDER = _providers.AUTODETECT_KEYS
PROVIDER_ALIASES = _providers.ALIASES

# A SKILLSPECTOR_MODEL is forwarded verbatim to the provider. For the vendor
# CLIs and the native Anthropic provider a model from a different vendor can
# only fail (e.g. a leftover model id from an old OpenAI setup makes `claude
# --model ...` exit 1 on every call). If the model does not carry the
# vendor's marker it is dropped and the provider default is used instead.
PROVIDER_MODEL_MARKERS = {p.id: p.markers for p in _providers.CATALOG.values() if p.markers}


def model_matches_provider(provider: str, model: str) -> bool:
    markers = PROVIDER_MODEL_MARKERS.get(provider)
    if not markers or not model:
        return True
    lowered = model.lower()
    return any(marker in lowered for marker in markers)


# SkillSpector warns once per analyzer slot that the empty model id (= "use the
# CLI's own default") has no token-limit entry in its registry. That is
# expected for CLI providers and says nothing about the scan; it is the one
# stderr line the wrapper filters. Real errors and every other warning pass.
_EMPTY_MODEL_NOISE = (
    "No token-limit info for model ''",
    "Model '' (slot:",
)


def _static_only_forced() -> bool:
    return os.environ.get("AGENT_GUARD_STATIC_ONLY", "").strip().lower() in (
        "1", "true", "yes", "on")


def skipped_dynamic_verdict() -> int:
    """Verdict of a dynamic stage skipped by --no-dynamic: only an explicit
    static-only choice keeps it at 0, otherwise the scan has no verdict."""
    if _static_only_forced():
        print("[WARN] Dynamic install analysis skipped by --no-dynamic.")
        return 0
    print("[BLOCK] NO VERDICT -- dynamic analysis skipped by --no-dynamic "
          "(set AGENT_GUARD_STATIC_ONLY=1 for an explicit static-only policy)")
    return 2


def resolve_llm() -> tuple[str, bool, str]:
    """Return (provider, ready, reason).

    `provider` is the SkillSpector provider id that will be used ("" when
    nothing is configured); `ready` says whether SkillSpector's LLM layer can
    run with it; `reason` is a short human-readable note for the scan banner.

    Resolution order:
      1. AGENT_GUARD_STATIC_ONLY=1 disables only LLM semantic analysis; other
         configured static analyzers may still perform their own network lookups.
      2. An active LLM profile from the user config decides alone; stale
         SKILLSPECTOR_* settings are ignored.
      3. An explicit SKILLSPECTOR_PROVIDER is honoured and validated: a CLI
         provider needs its binary on PATH, a hosted one its credential(s).
      4. Otherwise auto-detect: a hosted credential in the environment wins
         (explicit intent), then the first of claude, opencode found on PATH;
         Codex and Antigravity are never used, gemini only when named.
    """
    if _static_only_forced():
        return "", False, "AGENT_GUARD_STATIC_ONLY is set"

    if LLM_PROFILE:
        env, ready, reason, _registry = _llm_profile.skillspector_env(
            *LLM_PROFILE, os.environ, which=shutil.which)
        return env["SKILLSPECTOR_PROVIDER"], ready, reason

    explicit = os.environ.get("SKILLSPECTOR_PROVIDER", "").strip().lower()
    # A catalog id wins over a binary alias, so "gemini" stays the Google ADC provider.
    if explicit and explicit not in _providers.CATALOG:
        explicit = _providers.ALIASES.get(explicit, explicit)

    if explicit:
        provider = _providers.get(explicit)
        if provider is None:
            return explicit, False, f"unknown SKILLSPECTOR_PROVIDER={explicit}"
        if provider.disabled:
            return explicit, False, provider.disabled
        if provider.kind == "cli":
            if shutil.which(provider.binary):
                return explicit, True, f"{provider.binary} CLI (local login)"
            return explicit, False, (f"SKILLSPECTOR_PROVIDER={explicit} but "
                                     f"'{provider.binary}' is not on PATH")
        missing = [v for v in provider.required if not os.environ.get(v, "").strip()]
        if missing:
            return explicit, False, (f"SKILLSPECTOR_PROVIDER={explicit} but "
                                     f"{', '.join(missing)} is not set")
        how = "API key" if provider.secrets else "provider-managed credentials"
        return explicit, True, f"{explicit} ({how})"

    for provider in KEY_AUTODETECT_ORDER:
        if all(os.environ.get(v, "").strip() for v in KEY_PROVIDERS[provider]):
            return provider, True, f"{provider} (API key, auto-detected)"
    for provider, binary in CLI_PROVIDERS.items():
        if shutil.which(binary):
            return provider, True, f"{binary} CLI (local login, auto-detected)"
    return "", False, "no LLM provider configured"


PROVIDER, LLM_READY, LLM_REASON = resolve_llm()


def _llm_explicit() -> bool:
    """True when the user named a provider (SKILLSPECTOR_PROVIDER or an active
    LLM profile) and did not opt out with AGENT_GUARD_STATIC_ONLY."""
    if _static_only_forced():
        return False
    return bool(LLM_PROFILE) or bool(
        os.environ.get("SKILLSPECTOR_PROVIDER", "").strip())


# One rule for every path: a named provider that is refused, unknown or not
# ready never degrades silently to a static-only SAFE.
LLM_EXPLICIT = _llm_explicit()


def explicit_llm_gap() -> str | None:
    """The NO VERDICT message when the user chose a provider that cannot run,
    else None. A static-only SAFE needs AGENT_GUARD_STATIC_ONLY=1; with nothing
    named and nothing found, verdict_skillspector withholds SAFE as well."""
    if LLM_EXPLICIT and not LLM_READY:
        return ("[BLOCK] NO VERDICT -- the chosen LLM provider cannot run: "
                f"{LLM_REASON}. A static-only scan is not a substitute for the "
                "analysis you configured. Fix the provider (see .env.example) or "
                "set AGENT_GUARD_STATIC_ONLY=1 for an explicit static-only policy.")
    return None


def skillspector_llm_usable() -> bool:
    """Whether SkillSpector's LLM layer will run for this scan."""
    return LLM_READY


_REGISTRY_FILE: str | None = None


def _profile_registry_file(registry: dict) -> str:
    """Write the profile's single-model registry once per process.

    SkillSpector reads SKILLSPECTOR_MODEL_REGISTRY as YAML; JSON is valid YAML,
    so no extra dependency is needed. The file replaces the bundled registry,
    which is fine because a profile run uses exactly this one model."""
    global _REGISTRY_FILE
    if _REGISTRY_FILE is None:
        import atexit
        fd, path = tempfile.mkstemp(prefix="agent-guard-registry-", suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(registry, handle)
        atexit.register(lambda: Path(path).unlink(missing_ok=True))
        _REGISTRY_FILE = path
    return _REGISTRY_FILE


def skillspector_env() -> dict:
    """Environment for SkillSpector: force UTF-8 (its rich terminal renderer
    crashes on a legacy Windows cp1252 console) and pin the resolved provider
    under SkillSpector's native variable name. When the LLM layer is not
    usable the provider variable is dropped so SkillSpector does not try (and
    fail) on its own default; the scan is run with --no-llm."""
    e = dict(os.environ)
    profile_active = bool(LLM_PROFILE) and LLM_READY
    if profile_active:
        e, _ready, _reason, registry = _llm_profile.skillspector_env(
            *LLM_PROFILE, e, which=shutil.which)
        if registry:
            e["SKILLSPECTOR_MODEL_REGISTRY"] = _profile_registry_file(registry)
    e["PYTHONUTF8"] = "1"
    e["PYTHONIOENCODING"] = "utf-8"
    e["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"] = str(WORKFLOW_BUDGET)
    if LLM_READY:
        e["SKILLSPECTOR_PROVIDER"] = PROVIDER
        is_cli = getattr(_providers.get(PROVIDER), "kind", "") == "cli"
        # SkillSpector's own default fan-out is 10 parallel LLM calls, which suits a
        # normal API quota -- we leave it alone for key providers. A CLI provider is
        # different, and the difference is ours: every call becomes a separate CLI
        # subprocess driving one interactive login, so a 10-wide burst spends a single
        # subscription's rate limit in seconds and SkillSpector drops the 429'd batches.
        # Serialize that case unless the user has chosen a value.
        if is_cli and not e.get("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "").strip():
            e["SKILLSPECTOR_MAX_LLM_CONCURRENCY"] = "1"
        model = e.get("SKILLSPECTOR_MODEL", "").strip()
        # A profile's model is the user's explicit choice; the marker check only
        # guards against leftovers in the legacy env configuration.
        if model and not profile_active and not model_matches_provider(PROVIDER, model):
            print(f"  NOTE: SKILLSPECTOR_MODEL={model} does not belong to provider "
                  f"{PROVIDER}; it is not used, the provider's default model applies.")
            e.pop("SKILLSPECTOR_MODEL", None)
    else:
        e.pop("SKILLSPECTOR_PROVIDER", None)
    return e


def _filter_stderr(stderr: str) -> str:
    kept = [line for line in stderr.splitlines()
            if not any(marker in line for marker in _EMPTY_MODEL_NOISE)]
    return "\n".join(kept)


def _has_transient_llm_failure(stderr: str) -> bool:
    return any(marker in stderr for marker in LLM_TRANSIENT_FAILURE_MARKERS)


def _has_rate_limit_failure(stderr: str) -> bool:
    return any(marker in stderr for marker in LLM_RATE_LIMIT_MARKERS)


def _load_report(report_path: Path):
    if not report_path.exists():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (ValueError, OSError):
        return None


def llm_run_incomplete(data, expected: bool = False) -> str:
    """Return a reason string when an LLM-requested scan did not get full LLM
    coverage (report metadata, SkillSpector >= 2.10), else ""."""
    if not isinstance(data, dict):
        return "invalid report metadata" if expected else ""
    meta = data.get("metadata", {})
    if not isinstance(meta, dict):
        return "invalid report metadata"
    if expected and meta.get("llm_requested") is not True:
        return "report does not confirm the requested LLM analysis"
    if not meta.get("llm_requested"):
        return ""
    if meta.get("llm_error"):
        return str(meta["llm_error"])
    if meta.get("llm_available") is not True:
        return "LLM provider unavailable"
    attempted = meta.get("llm_calls_attempted")
    succeeded = meta.get("llm_calls_succeeded")
    if (type(attempted) is not int or type(succeeded) is not int
            or attempted <= 0 or succeeded < 0 or succeeded > attempted):
        return "missing or invalid LLM call accounting"
    if isinstance(attempted, int) and isinstance(succeeded, int) and succeeded < attempted:
        return f"{attempted - succeeded} of {attempted} LLM calls failed"
    return ""


# -- static scan + verdict ----------------------------------------------------

def load_reviewed_baseline(path: Path) -> dict:
    """Accept only explicit SkillSpector v2 JSON fingerprints, never glob rules.

    SkillSpector binds each fingerprint to the complete component content,
    scanner version, finding location, severity and evidence. A baseline is
    trusted reviewer input; no file supplied by a scan target is auto-selected.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 2:
        raise ValueError("reviewed baseline must use SkillSpector JSON version 2")
    if data.get("rules") != []:
        raise ValueError("reviewed baseline must have rules: [] (no wildcard exclusions)")
    version = data.get("scanner_version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("reviewed baseline must name the scanner_version")
    entries = data.get("fingerprints")
    if not isinstance(entries, list) or not entries:
        raise ValueError("reviewed baseline must contain exact fingerprints")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid baseline fingerprint entry")
        digest = entry.get("hash")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("reviewed baseline requires full SHA-256 fingerprints")
        for key in ("rule_id", "file", "reason"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError(f"baseline fingerprint requires a non-empty {key}")
    return data


def run_skillspector(src: Path, runtime_hint: bool = False, *,
                     baseline: Path | None = None,
                     report_output: Path | None = None) -> int:
    """SkillSpector scan of `src` (a dir / zip / .md / file). Nothing from the
    scanned target is executed. Writes a JSON report to a temp file (robust
    across platforms; the terminal renderer is unreliable on legacy Windows
    consoles) and judges it.

    `runtime_hint=True` adds the MCP-specific note that a static scan cannot see
    tools a server registers only at runtime (set by the MCP wrapper, not for
    plain skills)."""
    need_skillspector()
    reviewed = None
    if baseline is not None:
        try:
            reviewed = load_reviewed_baseline(baseline)
        except (OSError, ValueError) as exc:
            print(f"[BLOCK] NO VERDICT -- invalid reviewed baseline: {_console_text(exc)}")
            return 2
    gap = explicit_llm_gap()
    if gap:
        print(_console_text(gap))
        return 2
    env = skillspector_env()
    use_llm = skillspector_llm_usable()
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "report.json"
        cmd = skillspector_command() + ["scan", str(src),
                                        "--format", "json", "--output", str(report)]
        if reviewed is not None:
            snapshot = Path(d) / "reviewed-baseline.json"
            snapshot.write_text(json.dumps(reviewed), encoding="utf-8")
            cmd += ["--baseline", str(snapshot), "--show-suppressed"]
        if not use_llm:
            cmd.append("--no-llm")
            suffix = f"  [static only -- {LLM_REASON}]"
        else:
            suffix = f"  [LLM: {LLM_REASON}]"
        print(f"  SkillSpector scan (no execution): {src}{suffix}")
        attempts = LLM_RETRIES + 1 if use_llm else 1
        r = None
        data = None
        for attempt in range(1, attempts + 1):
            if report.exists():
                report.unlink()
            try:
                r = run_bounded(cmd, timeout=SCAN_TIMEOUT, env=env)
            except subprocess.TimeoutExpired:
                print("\n" + "=" * 60)
                print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
                      "install. Raise AGENT_GUARD_SCAN_TIMEOUT or review manually.")
                return 2
            data = _load_report(report)
            if not use_llm or attempt >= attempts:
                break
            incomplete = llm_run_incomplete(data, expected=True) if data is not None else ""
            transient = _has_transient_llm_failure(r.stderr)
            if not incomplete and not transient:
                break
            if _has_rate_limit_failure(r.stderr):
                # Repeating the scan re-sends every prompt, so it asks the provider
                # for more of exactly what it just refused. Stop and say what helps.
                print("  SkillSpector LLM run hit a provider quota limit; not repeating "
                      "the scan (a repeat re-sends every prompt). Lower the fan-out with "
                      "SKILLSPECTOR_MAX_LLM_CONCURRENCY=1, or use a provider whose "
                      "quota fits the target size.")
                break
            delay = LLM_RETRY_BASE_DELAY * attempt
            print(f"  SkillSpector LLM run incomplete "
                  f"({incomplete or 'transient provider error'}); "
                  f"retrying in {delay}s ({attempt}/{attempts - 1})...")
            time.sleep(delay)
        # Never hide scanner errors (fail closed): surface stderr if present.
        stderr = _filter_stderr(r.stderr)
        if stderr.strip():
            print(_console_err_text(stderr), file=sys.stderr)
        if report_output is not None and report.is_file():
            try:
                # Refuse overwrite: a report must not replace source or policy files.
                with report_output.open("xb") as dest:
                    dest.write(report.read_bytes())
            except OSError as exc:
                print(f"[BLOCK] NO VERDICT -- could not save report: {_console_text(exc)}")
                return 2
            print(f"  Report saved: {_console_text(report_output)}")
        if reviewed is not None and data is not None:
            metadata = data.get("metadata")
            actual = metadata.get("skillspector_version") if isinstance(metadata, dict) else None
            if actual != reviewed["scanner_version"]:
                print("[BLOCK] NO VERDICT -- baseline scanner version does not match "
                      "the running scanner. Review again before using this baseline.")
                return 2
        if use_llm and data is not None:
            incomplete = llm_run_incomplete(data, expected=True)
            if incomplete:
                print("\n" + "=" * 60)
                print(f"[BLOCK] NO VERDICT -- SkillSpector LLM analysis incomplete "
                      f"({incomplete}). Do NOT install based on a partial LLM run; "
                      "fix the provider (see .env.example) or set "
                      "AGENT_GUARD_STATIC_ONLY=1 for an explicit static-only policy.")
                return 2
        return verdict_skillspector(report, r.returncode, runtime_hint,
                                    reviewed_baseline=reviewed is not None)


def parse_limit_only(completeness: dict) -> bool:
    """Every file was read; the only gap besides unresolved references is a bounded
    shell parser giving up on a passage (static_parse_limit). The triage locates
    those lines with the same parser and checks them, so this can be judged."""
    exceptions = completeness.get("ledger_exceptions")
    if completeness.get("entirely_uninspected_files") or not isinstance(exceptions, list):
        return False
    analyzers = set()
    for item in exceptions:
        if not isinstance(item, dict) or item.get("fatal") is not False:
            return False
        if (item.get("phase") == "reference_resolution"
                and item.get("reason_code") == "reference_missing"):
            continue
        names = item.get("analyzers")
        if (item.get("phase") != "static" or item.get("reason_code") != "static_parse_limit"
                or not item.get("path") or not isinstance(names, list) or not names
                or not set(map(str, names)) <= PARSE_SPAN_ANALYZERS):
            return False
        analyzers.update(str(n) for n in names)
    if not analyzers:
        return False
    allowed = {f"Analyzer {name} status: degraded." for name in analyzers}
    return (set(completeness.get("limitations") or []) <= allowed
            and not completeness.get("scope_exclusions"))


def verdict_skillspector(report_path: Path, code: int, runtime_hint: bool = False, *,
                        reviewed_baseline: bool = False, llm_confirmed: bool = False) -> int:
    """Turn a SkillSpector JSON report into a clear verdict. Fail closed.

    llm_confirmed: the caller already verified from the report that the requested
    LLM analysis ran (campaign scans), so the skills profile's readiness does not apply.
    """
    print("\n" + "=" * 60)
    data = _load_report(report_path)
    if data is None:
        print("[BLOCK] NO VERDICT -- SkillSpector produced no parsable report "
              f"(exit {code}). Do NOT install. Re-run the scan.")
        return 2

    ra = data.get("risk_assessment", {})
    issues = data.get("issues", [])
    meta = data.get("metadata", {})
    completeness = data.get("analysis_completeness", {})
    if (not isinstance(ra, dict) or not isinstance(meta, dict)
            or not isinstance(completeness, dict) or not isinstance(issues, list)
            or any(not isinstance(item, dict)
                   or not isinstance(item.get("location", {}), dict) for item in issues)):
        print("[BLOCK] NO VERDICT -- invalid SkillSpector report structure.")
        return 2
    score = ra.get("score")
    severity = str(ra.get("severity") or "").upper()
    rec = str(ra.get("recommendation") or "").upper()
    max_sev = str(ra.get("max_issue_severity") or "").upper()
    suppressed = data.get("suppressed", [])
    suppressed_count = data.get("suppressed_count", 0)

    if (not isinstance(suppressed, list) or type(suppressed_count) is not int
            or suppressed_count < 0):
        print("[BLOCK] NO VERDICT -- invalid suppression audit metadata.")
        return 2

    if suppressed or suppressed_count:
        if (not reviewed_baseline or not isinstance(suppressed, list)
                or not isinstance(suppressed_count, int)
                or suppressed_count != len(suppressed)
                or any(not isinstance(item, dict) or not item.get("suppression_reason")
                       or item.get("suppressed") is not True
                       or not isinstance(item.get("location"), dict)
                       for item in suppressed)):
            print("[BLOCK] NO VERDICT -- suppressed findings lack an explicit "
                  "reviewed baseline or a complete audit trail.")
            return 2
        print(f"REVIEW: {suppressed_count} finding(s) accepted by explicit baseline:")
        for item in suppressed:
            loc = item["location"]
            print(f"  ACCEPTED: {_console_text(item.get('id', '?'))} @ "
                  f"{_console_text(loc.get('file', '?'))}:{loc.get('start_line', '?')} "
                  f"-- {_console_text(item['suppression_reason'])}")

    # SkillSpector >= 2.5: a report with execution_successful=false is a
    # validation failure, not a clean result -- even if it carries a score.
    exec_ok = data.get("execution_successful")
    if exec_ok is None:
        exec_ok = completeness.get("execution_successful")
    if exec_ok is not True or completeness.get("execution_successful", True) is not True:
        print("[BLOCK] NO VERDICT -- SkillSpector did not confirm successful execution. "
              "Do NOT install. Analyzer exceptions:")
        for exc in completeness.get("ledger_exceptions") or []:
            print(f"  - {_console_text(exc)}")
        return 2

    if issues:
        print(f"Findings ({len(issues)}):")
        for it in issues:
            loc = it.get("location") or {}
            where = f"{loc.get('file')}:{loc.get('start_line')}" if loc.get("file") else "?"
            print(f"  {str(it.get('severity') or '?').upper()}: "
                  f"{it.get('id') or ''} {it.get('category') or ''} @ {where}")
            if it.get("explanation"):
                print(f"      {_console_text(it['explanation'])}")

    if (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 100):
        print("[BLOCK] NO VERDICT -- report has no valid risk score. Review manually "
              "before installing.")
        return 2

    # Coverage caveats travel with the verdict (fail-closed reporting).
    uninspected = completeness.get("entirely_uninspected_files")
    partial = completeness.get("partially_inspected_files")
    if any(type(count) is not int or count < 0 for count in (uninspected, partial)):
        print("[BLOCK] NO VERDICT -- missing or invalid inspection counts.")
        return 2
    if completeness and (uninspected or partial or completeness.get("is_complete") is False):
        cov = completeness.get("coverage_percent")
        print(f"  LIMIT: analysis coverage {cov}% -- {uninspected} file(s) not inspected, "
              f"{partial} partially. The verdict covers inspected files only.")
        for lim in completeness.get("limitations") or []:
            print(f"    - {_console_text(lim)}")
        for exc in completeness.get("scope_exclusions") or []:
            print(f"    - excluded: {_console_text(exc)}")

    sev_set = {str(it.get("severity") or "").upper() for it in issues}
    if max_sev:
        sev_set.add(max_sev)
    if meta.get("llm_available") is True:
        llm_note = ""
    else:
        llm_note = f"  (static only -- {LLM_REASON})"
    runtime_note = ("\n   Note: a static source scan cannot see MCP tools that are "
                    "registered only at runtime. Use --sandbox for a live check of "
                    "an unfamiliar server.") if runtime_hint else ""

    if (rec == "DO_NOT_INSTALL"
                   or (isinstance(score, (int, float)) and score > 50)
                   or (sev_set & {"HIGH", "CRITICAL"})):
        print(f"[BLOCK] risk {score}/100 ({severity}) -- {len(issues)} finding(s). "
              "Review the findings above before installing. Do not install on a whim.")
        return 1

    if code != 0:
        print(f"[BLOCK] NO VERDICT -- scanner exited {code}; a low risk score cannot override an error.")
        return 2
    if (uninspected or partial or completeness.get("is_complete") is not True):
        exceptions = completeness.get("ledger_exceptions") or []
        reviewed_paths = {item["location"].get("file") for item in suppressed
                          if item.get("id") == "AE1"}
        reviewed_references = (
            reviewed_baseline and not uninspected and not partial
            and completeness.get("coverage_percent") == 100
            and reviewed_paths and not any(item.get("id") == "AE1" for item in issues)
            and isinstance(exceptions, list) and exceptions and all(isinstance(item, dict)
                and item.get("phase") == "reference_resolution"
                and item.get("reason_code") in ("reference_missing", "reference_unresolved")
                and item.get("fatal") is False
                and item.get("path") in reviewed_paths for item in exceptions)
            and not completeness.get("limitations")
        )
        # Every file was inspected and the only thing SkillSpector could not
        # settle are references that match no bundled file. Upstream does not
        # fail a scan for this -- `--fail-on-incomplete` is opt-in -- and its own
        # resolver reports prose like "X/100" or "blog/article" as a path-like
        # reference, so blocking here would deny a verdict to essentially every
        # skill whose documentation contains a slash. Report it as a caveat and
        # judge. Since SkillSpector 2.12.0 `reference_unresolved` means a path
        # that matched several bundled files instead; upstream keeps that from
        # counting as safe, so it needs the reviewed baseline above.
        unresolved_only = (
            not uninspected and not partial
            and completeness.get("coverage_percent") == 100
            and isinstance(exceptions, list) and exceptions
            and all(isinstance(item, dict)
                    and item.get("phase") == "reference_resolution"
                    and item.get("reason_code") == "reference_missing"
                    and item.get("fatal") is False for item in exceptions))
        if not reviewed_references and not (unresolved_only and not FAIL_ON_INCOMPLETE):
            gaps = [item for item in exceptions if isinstance(item, dict)
                    and item.get("reason_code") != "reference_missing"]
            for item in gaps:
                print(f"    - not fully inspected: {_console_text(str(item.get('path')))}: "
                      f"{_console_text(str(item.get('reason_code')))}")
            if parse_limit_only(completeness) and not FAIL_ON_INCOMPLETE:
                print("[BLOCK] partial inspection -- the scanner's shell parser gave up on "
                      "passages of the files listed above. Do not install until those lines "
                      "are checked: update_skills.py checks them automatically; otherwise "
                      "review them by hand.")
                return 1
            print("[BLOCK] NO VERDICT -- incomplete inspection requires review; no clean verdict."
                  + (" Review the files listed above by hand." if gaps else ""))
            return 2
        if reviewed_references:
            print("  REVIEW: unresolved documentation references accepted with exact AE1 "
                  "fingerprints; all source files were inspected.")
        else:
            where = sorted({str(item.get("path")) for item in exceptions})
            print(f"  CAVEAT: {len(exceptions)} reference(s) in {', '.join(where)} could not be "
                  "resolved, so whatever they point at was not inspected. Every file present was. "
                  "Check that referenced files ship with the skill; set "
                  "AGENT_GUARD_FAIL_ON_INCOMPLETE=1 to require a complete inspection instead.")

    gap = None if llm_confirmed else explicit_llm_gap()
    if gap:
        print(_console_text(gap))
        return 2
    if (not llm_confirmed and meta.get("llm_available") is not True
            and not _static_only_forced()):
        print(_console_text(
            f"[BLOCK] NO VERDICT -- static only ({LLM_REASON}); no AI analysis ran. "
            "Set up an LLM provider or set AGENT_GUARD_STATIC_ONLY=1 for an explicit "
            "static-only policy."))
        return 2

    extra = f" with {len(issues)} low/medium note(s)" if issues else ""
    review_note = (f"  ({suppressed_count} finding(s) accepted by explicit review; "
                   "not an unqualified clean scan)") if suppressed_count else ""
    print(f"[SAFE] risk {score}/100 ({severity}){extra}. Installation reasonable."
          f"{review_note}{llm_note}{runtime_note}")
    return 0
