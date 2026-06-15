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
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SKILLSPECTOR = shutil.which("skillspector")

# Hard cap on a single scan, so a hanging scan never blocks forever.
# (SCAN_MCP_TIMEOUT kept for backwards compatibility with the old MCP-only knob.)
SCAN_TIMEOUT = int(os.environ.get("AGENT_GUARD_SCAN_TIMEOUT")
                   or os.environ.get("SCAN_MCP_TIMEOUT", "600"))


def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def need_skillspector():
    if SKILLSPECTOR is None:
        die("skillspector not found on PATH. Run setup.sh / setup.ps1 first.")


# -- provider-aware LLM resolution --------------------------------------------
# One provider config drives SkillSpector here and (via scan_mcp.py) the Cisco
# runtime scanner. resolve_llm() reads SkillSpector-native variables, with a
# legacy SKILL_SCANNER_* fallback so an older .env keeps working.

def resolve_llm():
    """Return (provider, key, model, base_url) from the configured env.

    Precedence: SkillSpector-native vars, then legacy Cisco SKILL_SCANNER_*.
    If no provider is named, infer it from whichever credential is present.
    """
    provider = (os.environ.get("SKILLSPECTOR_PROVIDER", "")
                or os.environ.get("SKILL_SCANNER_LLM_PROVIDER", "")).strip().lower()
    model = (os.environ.get("SKILLSPECTOR_MODEL", "")
             or os.environ.get("SKILL_SCANNER_LLM_MODEL", "")).strip()
    base = (os.environ.get("OPENAI_BASE_URL", "")
            or os.environ.get("MCP_SCANNER_LLM_BASE_URL", "")
            or os.environ.get("SKILL_SCANNER_LLM_BASE_URL", "")).strip()
    legacy_key = os.environ.get("SKILL_SCANNER_LLM_API_KEY", "").strip()

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or legacy_key
    elif provider in ("openai", "openai-compatible", "custom-openai"):
        provider = "openai"
        key = os.environ.get("OPENAI_API_KEY", "").strip() or legacy_key
    elif provider in ("nv_build", "nv_inference"):
        key = os.environ.get("NVIDIA_INFERENCE_KEY", "").strip() or legacy_key
    else:
        # No provider named -- infer from whichever credential exists.
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider, key = "anthropic", os.environ["ANTHROPIC_API_KEY"].strip()
        elif os.environ.get("OPENAI_API_KEY"):
            provider, key = "openai", os.environ["OPENAI_API_KEY"].strip()
        elif os.environ.get("NVIDIA_INFERENCE_KEY"):
            provider, key = "nv_inference", os.environ["NVIDIA_INFERENCE_KEY"].strip()
        elif legacy_key:
            key = legacy_key
            provider = "anthropic" if legacy_key.startswith("sk-ant-") else "openai"
        else:
            key = ""
    return provider, key, model, base


PROVIDER, LLM_KEY, LLM_MODEL_RAW, LLM_BASE_URL = resolve_llm()


def skillspector_llm_usable() -> bool:
    """Whether SkillSpector's LLM layer can actually run with the configured
    provider. Its semantic analyzers request structured outputs whose JSON
    schema (integer/number `minimum`/`maximum`) only SkillSpector's OpenAI and
    NVIDIA providers accept. Anthropic's OpenAI-compatible endpoint rejects that
    schema (HTTP 400), so with Anthropic SkillSpector is run static-only --
    Anthropic still drives the Cisco runtime scan, which uses LiteLLM."""
    return bool(LLM_KEY and PROVIDER in ("openai", "nv_build", "nv_inference"))


def skillspector_env() -> dict:
    """Environment for SkillSpector: force UTF-8 (its rich terminal renderer
    crashes on a legacy Windows cp1252 console) and, when the provider's LLM
    path is usable, expose the provider + key under SkillSpector's native
    variable names."""
    e = dict(os.environ)
    e["PYTHONUTF8"] = "1"
    e["PYTHONIOENCODING"] = "utf-8"
    if not skillspector_llm_usable():
        for name in (
                "SKILLSPECTOR_PROVIDER",
                "SKILLSPECTOR_MODEL",
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "NVIDIA_INFERENCE_KEY"):
            e.pop(name, None)
        return e

    if skillspector_llm_usable():
        e["SKILLSPECTOR_PROVIDER"] = PROVIDER
        if PROVIDER == "openai":
            e["OPENAI_API_KEY"] = LLM_KEY
            if LLM_BASE_URL:
                e["OPENAI_BASE_URL"] = LLM_BASE_URL
        elif PROVIDER in ("nv_build", "nv_inference"):
            e["NVIDIA_INFERENCE_KEY"] = LLM_KEY
        if LLM_MODEL_RAW:
            e["SKILLSPECTOR_MODEL"] = LLM_MODEL_RAW
    return e


# -- static scan + verdict ----------------------------------------------------

def run_skillspector(src: Path, runtime_hint: bool = False) -> int:
    """Static SkillSpector scan of `src` (a dir / zip / .md / file). Nothing is
    executed. Writes a JSON report to a temp file (robust across platforms; the
    terminal renderer is unreliable on legacy Windows consoles) and judges it.

    `runtime_hint=True` adds the MCP-specific note that a static scan cannot see
    tools a server registers only at runtime (set by the MCP wrapper, not for
    plain skills)."""
    need_skillspector()
    env = skillspector_env()
    use_llm = skillspector_llm_usable()
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "report.json"
        cmd = [SKILLSPECTOR, "scan", str(src),
               "--format", "json", "--output", str(report)]
        if not use_llm:
            cmd.append("--no-llm")
        if not use_llm and PROVIDER == "anthropic" and LLM_KEY:
            suffix = ("  [static only -- SkillSpector's LLM path is incompatible "
                      "with Anthropic]")
        elif not use_llm:
            suffix = "  [static only -- no LLM provider configured]"
        else:
            suffix = ""
        print(f"  SkillSpector scan (no execution): {src}{suffix}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=SCAN_TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            print("\n" + "=" * 60)
            print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
                  "install. Raise AGENT_GUARD_SCAN_TIMEOUT or review manually.")
            return 2
        # Never hide scanner errors (fail closed): surface stderr if present.
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr)
        return verdict_skillspector(report, r.returncode, runtime_hint)


def verdict_skillspector(report_path: Path, code: int, runtime_hint: bool = False) -> int:
    """Turn a SkillSpector JSON report into a clear verdict. Fail closed."""
    print("\n" + "=" * 60)
    data = None
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = None
    if data is None:
        print("[BLOCK] NO VERDICT -- SkillSpector produced no parsable report "
              f"(exit {code}). Do NOT install. Re-run the scan.")
        return 2

    ra = data.get("risk_assessment") or {}
    score = ra.get("score")
    severity = str(ra.get("severity") or "").upper()
    rec = str(ra.get("recommendation") or "").upper()
    issues = data.get("issues") or []
    meta = data.get("metadata") or {}

    if issues:
        print(f"Findings ({len(issues)}):")
        for it in issues:
            loc = it.get("location") or {}
            where = f"{loc.get('file')}:{loc.get('start_line')}" if loc.get("file") else "?"
            print(f"  {str(it.get('severity') or '?').upper()}: "
                  f"{it.get('id') or ''} {it.get('category') or ''} @ {where}")
            if it.get("explanation"):
                print(f"      {it['explanation']}")

    if score is None:
        print("[BLOCK] NO VERDICT -- report has no risk score. Review manually "
              "before installing.")
        return 2

    sev_set = {str(it.get("severity") or "").upper() for it in issues}
    if meta.get("llm_available"):
        llm_note = ""
    elif PROVIDER == "anthropic":
        llm_note = "  (static only -- SkillSpector LLM needs OpenAI/NVIDIA)"
    else:
        llm_note = "  (static only -- configure a provider for semantic analysis)"
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
