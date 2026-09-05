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
(claude_cli / codex_cli / gemini_cli): the scanner starts the CLI as a separate
tool-less process, feeds the untrusted content via stdin, and validates the
answer against a JSON schema -- so the scanning LLM stays isolated from the
agent that later installs the skill, and no API key is needed. Hosted API
providers (anthropic, openai, nv_build, ...) remain fully supported.
"""

import json
import os
import shutil
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
    candidates.extend([
        script_root / ".env",
        Path.cwd() / ".env",
        script_root.parent / ".env",
    ])
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_env_file(resolved)


load_agent_guard_env()

SKILLSPECTOR = shutil.which("skillspector")
BOOT = Path(__file__).with_name("_skillspector_boot.py")
SKILLSPECTOR_CMD: list | None = None   # resolved lazily by skillspector_command()

# Hard cap on a single scan, so a hanging scan never blocks forever.
# (SCAN_MCP_TIMEOUT kept for backwards compatibility with the old MCP-only knob.)
SCAN_TIMEOUT = int(os.environ.get("AGENT_GUARD_SCAN_TIMEOUT")
                   or os.environ.get("SCAN_MCP_TIMEOUT", "600"))

# SkillSpector's aggregate deadline for one scan (upstream default: 60 s, which
# CLI providers exhaust on medium-sized skills). Applied through
# _skillspector_boot.py; upstream PR #468 adopts the same variable name.
WORKFLOW_BUDGET = int(os.environ.get("SKILLSPECTOR_MAX_WORKFLOW_SECONDS")
                      or str(max(60, SCAN_TIMEOUT - 60)))

# stderr markers of a transient provider failure worth retrying (rate limits).
LLM_TRANSIENT_FAILURE_MARKERS = (
    "rate_limit_exceeded",
    "Rate limit reached",
    "HTTP 429",
    "429",
    "tokens per min",
    "overloaded",
)
LLM_RETRIES = int(os.environ.get("AGENT_GUARD_LLM_RETRIES", "3"))
LLM_RETRY_BASE_DELAY = int(os.environ.get("AGENT_GUARD_LLM_RETRY_BASE_DELAY", "20"))


def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


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
    tool environment when available (raises the workflow budget), otherwise
    the plain `skillspector` executable."""
    global SKILLSPECTOR_CMD
    if SKILLSPECTOR_CMD is not None:
        return list(SKILLSPECTOR_CMD)
    py = skillspector_python() if BOOT.is_file() else None
    if py:
        SKILLSPECTOR_CMD = [py, str(BOOT)]
    else:
        print("  NOTE: SkillSpector tool environment not found; running the plain "
              "`skillspector` binary with its built-in 60s workflow budget.")
        SKILLSPECTOR_CMD = [SKILLSPECTOR]
    return list(SKILLSPECTOR_CMD)


# -- provider-aware LLM resolution --------------------------------------------
# This provider config is for SkillSpector only. scan_mcp.py has a separate
# Cisco runtime LLM config based on MCP_SCANNER_LLM_* (LiteLLM; no CLI path).

# Coding-agent CLIs SkillSpector can drive with the user's existing login.
# Order = auto-detection preference.
CLI_PROVIDERS = {
    "claude_cli": "claude",
    "codex_cli": "codex",
    "gemini_cli": "gemini",
}

# Hosted providers and the env vars they need.
KEY_PROVIDERS = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "nv_build": ("NVIDIA_INFERENCE_KEY",),
    "nv_inference": ("NVIDIA_INFERENCE_KEY",),
    "anthropic_proxy": ("ANTHROPIC_PROXY_API_KEY", "ANTHROPIC_PROXY_ENDPOINT_URL"),
    "azure_openai": ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"),
    "openai_compatible": ("SKILLSPECTOR_COMPAT_API_KEY", "SKILLSPECTOR_COMPAT_BASE_URL"),
}
# Auto-detection only considers the unambiguous key providers, in this order.
KEY_AUTODETECT_ORDER = ("anthropic", "openai", "nv_build")

# Providers that resolve credentials on their own (boto3 chain / local service).
IMPLICIT_PROVIDERS = {"bedrock", "ollama"}

PROVIDER_ALIASES = {
    "claude": "claude_cli",
    "codex": "codex_cli",
    "gemini": "gemini_cli",
    "openai-compatible": "openai_compatible",
    "custom-openai": "openai_compatible",
}

# A SKILLSPECTOR_MODEL is forwarded verbatim to the provider. For the vendor
# CLIs and the native Anthropic provider a model from a different vendor can
# only fail (e.g. a leftover `gpt-*` from an old OpenAI setup makes `claude
# --model gpt-...` exit 1 on every call). If the model does not carry the
# vendor's marker it is dropped and the provider default is used instead.
PROVIDER_MODEL_MARKERS = {
    "claude_cli": ("claude",),
    "anthropic": ("claude",),
    "codex_cli": ("gpt", "codex", "o1", "o3", "o4"),
    "gemini_cli": ("gemini",),
}


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


def resolve_llm() -> tuple[str, bool, str]:
    """Return (provider, ready, reason).

    `provider` is the SkillSpector provider id that will be used ("" when
    nothing is configured); `ready` says whether SkillSpector's LLM layer can
    run with it; `reason` is a short human-readable note for the scan banner.

    Resolution order:
      1. AGENT_GUARD_STATIC_ONLY=1 forces static-only (nothing leaves the box).
      2. An explicit SKILLSPECTOR_PROVIDER is honoured and validated: a CLI
         provider needs its binary on PATH, a hosted one its credential(s).
      3. Otherwise auto-detect: a hosted credential in the environment wins
         (explicit intent), then the first coding-agent CLI on PATH.
    """
    if _static_only_forced():
        return "", False, "AGENT_GUARD_STATIC_ONLY is set"

    explicit = os.environ.get("SKILLSPECTOR_PROVIDER", "").strip().lower()
    explicit = PROVIDER_ALIASES.get(explicit, explicit)

    if explicit:
        if explicit in CLI_PROVIDERS:
            binary = CLI_PROVIDERS[explicit]
            if shutil.which(binary):
                return explicit, True, f"{binary} CLI (local login)"
            return explicit, False, (f"SKILLSPECTOR_PROVIDER={explicit} but "
                                     f"'{binary}' is not on PATH")
        if explicit in KEY_PROVIDERS:
            missing = [v for v in KEY_PROVIDERS[explicit]
                       if not os.environ.get(v, "").strip()]
            if not missing:
                return explicit, True, f"{explicit} (API key)"
            return explicit, False, (f"SKILLSPECTOR_PROVIDER={explicit} but "
                                     f"{', '.join(missing)} is not set")
        if explicit in IMPLICIT_PROVIDERS:
            return explicit, True, f"{explicit} (provider-managed credentials)"
        return explicit, False, f"unknown SKILLSPECTOR_PROVIDER={explicit}"

    for provider in KEY_AUTODETECT_ORDER:
        if all(os.environ.get(v, "").strip() for v in KEY_PROVIDERS[provider]):
            return provider, True, f"{provider} (API key, auto-detected)"
    for provider, binary in CLI_PROVIDERS.items():
        if shutil.which(binary):
            return provider, True, f"{binary} CLI (local login, auto-detected)"
    return "", False, "no LLM provider configured"


PROVIDER, LLM_READY, LLM_REASON = resolve_llm()


def skillspector_llm_usable() -> bool:
    """Whether SkillSpector's LLM layer will run for this scan."""
    return LLM_READY


def skillspector_env() -> dict:
    """Environment for SkillSpector: force UTF-8 (its rich terminal renderer
    crashes on a legacy Windows cp1252 console) and pin the resolved provider
    under SkillSpector's native variable name. When the LLM layer is not
    usable the provider variable is dropped so SkillSpector does not try (and
    fail) on its own default; the scan is run with --no-llm."""
    e = dict(os.environ)
    e["PYTHONUTF8"] = "1"
    e["PYTHONIOENCODING"] = "utf-8"
    e["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"] = str(WORKFLOW_BUDGET)
    if LLM_READY:
        e["SKILLSPECTOR_PROVIDER"] = PROVIDER
        model = e.get("SKILLSPECTOR_MODEL", "").strip()
        if model and not model_matches_provider(PROVIDER, model):
            print(f"  NOTE: SKILLSPECTOR_MODEL={model} does not belong to provider "
                  f"{PROVIDER}; ignoring it and using the provider's default model.")
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


def _load_report(report_path: Path):
    if not report_path.exists():
        return None
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def llm_run_incomplete(data) -> str:
    """Return a reason string when an LLM-requested scan did not get full LLM
    coverage (report metadata, SkillSpector >= 2.10), else ""."""
    meta = (data or {}).get("metadata") or {}
    if not meta.get("llm_requested"):
        return ""
    if meta.get("llm_error"):
        return str(meta["llm_error"])
    if not meta.get("llm_available"):
        return "LLM provider unavailable"
    attempted = meta.get("llm_calls_attempted")
    succeeded = meta.get("llm_calls_succeeded")
    if isinstance(attempted, int) and isinstance(succeeded, int) and succeeded < attempted:
        return f"{attempted - succeeded} of {attempted} LLM calls failed"
    return ""


# -- static scan + verdict ----------------------------------------------------

def run_skillspector(src: Path, runtime_hint: bool = False) -> int:
    """SkillSpector scan of `src` (a dir / zip / .md / file). Nothing from the
    scanned target is executed. Writes a JSON report to a temp file (robust
    across platforms; the terminal renderer is unreliable on legacy Windows
    consoles) and judges it.

    `runtime_hint=True` adds the MCP-specific note that a static scan cannot see
    tools a server registers only at runtime (set by the MCP wrapper, not for
    plain skills)."""
    need_skillspector()
    env = skillspector_env()
    use_llm = skillspector_llm_usable()
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "report.json"
        cmd = skillspector_command() + ["scan", str(src),
                                        "--format", "json", "--output", str(report)]
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
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace",
                                   timeout=SCAN_TIMEOUT, env=env)
            except subprocess.TimeoutExpired:
                print("\n" + "=" * 60)
                print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
                      "install. Raise AGENT_GUARD_SCAN_TIMEOUT or review manually.")
                return 2
            data = _load_report(report)
            if not use_llm or attempt >= attempts:
                break
            incomplete = llm_run_incomplete(data) if data is not None else ""
            transient = _has_transient_llm_failure(r.stderr)
            if not incomplete and not transient:
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
        if use_llm and data is not None:
            incomplete = llm_run_incomplete(data)
            if incomplete:
                print("\n" + "=" * 60)
                print(f"[BLOCK] NO VERDICT -- SkillSpector LLM analysis incomplete "
                      f"({incomplete}). Do NOT install based on a partial LLM run; "
                      "fix the provider (see .env.example) or set "
                      "AGENT_GUARD_STATIC_ONLY=1 for an explicit static-only policy.")
                return 2
        return verdict_skillspector(report, r.returncode, runtime_hint)


def verdict_skillspector(report_path: Path, code: int, runtime_hint: bool = False) -> int:
    """Turn a SkillSpector JSON report into a clear verdict. Fail closed."""
    print("\n" + "=" * 60)
    data = _load_report(report_path)
    if data is None:
        print("[BLOCK] NO VERDICT -- SkillSpector produced no parsable report "
              f"(exit {code}). Do NOT install. Re-run the scan.")
        return 2

    ra = data.get("risk_assessment") or {}
    score = ra.get("score")
    severity = str(ra.get("severity") or "").upper()
    rec = str(ra.get("recommendation") or "").upper()
    max_sev = str(ra.get("max_issue_severity") or "").upper()
    issues = data.get("issues") or []
    meta = data.get("metadata") or {}
    completeness = data.get("analysis_completeness") or {}

    # SkillSpector >= 2.5: a report with execution_successful=false is a
    # validation failure, not a clean result -- even if it carries a score.
    exec_ok = data.get("execution_successful")
    if exec_ok is None:
        exec_ok = completeness.get("execution_successful")
    if exec_ok is False:
        print("[BLOCK] NO VERDICT -- SkillSpector reports execution_successful=false. "
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

    if score is None:
        print("[BLOCK] NO VERDICT -- report has no risk score. Review manually "
              "before installing.")
        return 2

    # Coverage caveats travel with the verdict (fail-closed reporting).
    uninspected = completeness.get("entirely_uninspected_files") or 0
    partial = completeness.get("partially_inspected_files") or 0
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
    if meta.get("llm_available"):
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

    extra = f" with {len(issues)} low/medium note(s)" if issues else ""
    print(f"[SAFE] risk {score}/100 ({severity}){extra}. Installation reasonable."
          f"{llm_note}{runtime_note}")
    return 0
