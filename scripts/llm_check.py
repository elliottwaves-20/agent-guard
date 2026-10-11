#!/usr/bin/env python3
"""Show which LLM each scanner will use, and optionally probe one connection.

  python llm_check.py                 # table for skills / verifier / mcp / campaign, no network
  python llm_check.py --probe skills  # ONE request through SkillSpector's own client
  python llm_check.py --probe mcp     # ONE request through the Cisco scanner's LiteLLM

A probe is never run implicitly: it spends one request of the configured
provider (subscription quota or API credit). Budgeted campaigns have no probe
here -- their first request in `llm_scan.py run` is the ledgered probe, and a
request outside the ledger would bypass the cost cap.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

import _llm_profile
from _llm_budget import policy_from_profile
import _pins


def _row(scanner, source, connection="", model="", ready=False, problem=""):
    return {"scanner": scanner, "source": source, "connection": connection,
            "model": model, "ready": ready, "problem": problem}


def _skills_row(config, env, which, legacy):
    selected = _llm_profile.select_profile(config, "skills", env)
    if selected is None:
        provider, ready, reason = legacy
        return _row("skills", "legacy env", provider or "none",
                    env.get("SKILLSPECTOR_MODEL", ""), ready, "" if ready else reason)
    name, profile = selected
    out, ready, reason, _ = _llm_profile.skillspector_env(name, profile, env, which=which)
    return _row("skills", f"profile {name}", out["SKILLSPECTOR_PROVIDER"],
                out.get("SKILLSPECTOR_MODEL", "(CLI default)"), ready, "" if ready else reason)


def _mcp_row(config, env, which, skillspector_python):
    selected = _llm_profile.select_profile(config, "mcp", env)
    if selected is None:
        model = env.get("MCP_SCANNER_LLM_MODEL", "").strip()
        ready = bool(env.get("MCP_SCANNER_LLM_API_KEY", "").strip())
        return _row("mcp", "legacy env", "litellm", model or "(Cisco default gpt-4o)", ready,
                    "" if ready else "MCP_SCANNER_LLM_API_KEY is not set")
    name, profile = selected
    if profile.get("kind") == "cli":
        # Mirrors scan_mcp.cisco_llm_problem; the scan itself goes through the local bridge.
        problem = ""
        if not skillspector_python():
            problem = f"profile {name}: the CLI bridge needs SkillSpector's Python (uv tool)"
        elif which(profile["cli"]) is None:
            problem = f"profile {name}: {profile['cli']} is not on PATH"
        return _row("mcp", f"profile {name}", f"CLI bridge ({profile['cli']})",
                    profile.get("model", "(CLI default)"), not problem, problem)
    out, problem = _llm_profile.cisco_env(name, profile, env)
    return _row("mcp", f"profile {name}", "litellm", out["MCP_SCANNER_LLM_MODEL"],
                problem is None, problem or "")


def _campaign_row(config, env):
    selected = _llm_profile.select_profile(config, "campaign", env)
    if selected is None:
        return _row("campaign", "not configured", problem="no [llm.use] campaign profile")
    name, profile = selected
    policy = policy_from_profile(name, profile, _pins.SKILLSPECTOR_VERSION)
    ready = bool(env.get(policy["key_env"], "").strip())
    budget = f"cap ${policy['total_nusd'] / 1e9:g}, step ${policy['step_nusd'] / 1e9:g}"
    return _row("campaign", f"profile {name}", f"openai protocol ({budget})", policy["model"],
                ready, "" if ready else f"profile {name}: {policy['key_env']} is not set")


def describe(config: dict, env, which=shutil.which, legacy_skills=None,
             skillspector_python=None) -> list[dict]:
    """One row per scanner. Configuration problems become row problems."""
    legacy = legacy_skills or ("", False, "legacy env resolution; see the scan banner")
    if skillspector_python is None:
        import _skillspector
        skillspector_python = _skillspector.skillspector_python
    builders = (("skills", lambda: _skills_row(config, env, which, legacy)),
                ("mcp", lambda: _mcp_row(config, env, which, skillspector_python)),
                ("campaign", lambda: _campaign_row(config, env)))
    rows = []
    for scanner, build in builders:
        try:
            rows.append(build())
        except _llm_profile.ProfileError as exc:
            rows.append(_row(scanner, "invalid profile", problem=str(exc)))
    # The verifier runs through SkillSpector's own client with the scan's
    # environment, so it always shares the skills connection.
    # It also needs SkillSpector's own Python environment to start.
    skills = rows[0]
    ready, problem = skills["ready"], skills["problem"]
    if not skillspector_python():
        ready, problem = False, "SkillSpector tool Python not found"
    rows.insert(1, _row("verifier", f"follows skills ({skills['source']})", skills["connection"],
                        skills["model"], ready, problem))
    return rows


PROBE_PROMPT = "Reply with exactly the word OK."
# Through the CLI bridge only Cisco-shaped answers count, so the mcp probe asks for one.
MCP_PROBE_PROMPT = 'Reply with exactly {"threat_analysis": {"malicious_content_detected": false}}'

SKILLS_PROBE = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import _opencode_oauth\n"
    "_opencode_oauth.keep_oauth_plugins()\n"
    "from skillspector.llm_utils import get_chat_model\n"
    "reply = get_chat_model().invoke(%r)\n"
    "print(str(getattr(reply, 'content', reply))[:200])\n" % PROBE_PROMPT)

# Mirrors mcpscanner's own request shape (llm_analyzer.py), including its
# per-model parameter rules and the reasoning shim a scan would load, so the
# probe fails exactly where a scan would.
MCP_PROBE = (
    "import os, sys, litellm\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import _cisco_boot\n"
    "_cisco_boot.install()\n"
    "from mcpscanner.utils.llm_request_params import apply_model_constraints\n"
    "params = {'model': os.environ['MCP_SCANNER_LLM_MODEL'],\n"
    "          'messages': [{'role': 'user', 'content': %r}],\n"
    "          'max_tokens': 16,\n"
    "          'temperature': float(os.environ.get('MCP_SCANNER_DEFAULT_LLM_TEMPERATURE', '0.1')),\n"
    "          'timeout': int(os.environ.get('MCP_SCANNER_LLM_TIMEOUT', '30'))}\n"
    "apply_model_constraints(params['model'], params)\n"
    "if os.environ.get('MCP_SCANNER_LLM_API_KEY'): params['api_key'] = os.environ['MCP_SCANNER_LLM_API_KEY']\n"
    "if os.environ.get('MCP_SCANNER_LLM_BASE_URL'): params['api_base'] = os.environ['MCP_SCANNER_LLM_BASE_URL']\n"
    "reply = litellm.completion(**params, drop_params=True)\n"
    "print(str(reply.choices[0].message.content)[:200])\n" % MCP_PROBE_PROMPT)


def probe(scanner: str) -> int:
    import _skillspector as ss
    if scanner == "skills":
        python, env, script = ss.skillspector_python(), ss.skillspector_env(), SKILLS_PROBE
        if not ss.LLM_READY:
            ss.die(f"skills LLM not ready: {ss.LLM_REASON}")
    else:
        import scan_mcp
        problem = scan_mcp.cisco_llm_problem()
        if problem:
            ss.die(f"mcp LLM not ready: {problem}")
        python, env, script = scan_mcp.mcpscanner_python(), None, MCP_PROBE
    if not python:
        ss.die(f"{scanner}: scanner Python environment not found; run setup first")
    started = time.monotonic()
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if scanner == "mcp":
        # A CLI profile must go through a real local bridge, exactly like a scan.
        with scan_mcp.cisco_llm_env() as env:
            result = ss.run_bounded([python, "-c", script, scripts_dir], env=env, timeout=180)
    else:
        result = ss.run_bounded([python, "-c", script, scripts_dir], env=env, timeout=180)
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
        print(f"[FAIL] {scanner} probe after {elapsed:.1f}s:", *tail, sep="\n  ")
        return 1
    print(f"[OK] {scanner} probe answered in {elapsed:.1f}s: {result.stdout.strip()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--probe", choices=("skills", "mcp"),
                        help="send exactly one request through that scanner's own client")
    args = parser.parse_args()
    import _skillspector as ss
    rows = describe(ss.USER_CONFIG, os.environ, which=shutil.which,
                    skillspector_python=ss.skillspector_python,
                    legacy_skills=(ss.PROVIDER, ss.LLM_READY, ss.LLM_REASON))
    for row in rows:
        state = "ready" if row["ready"] else "NOT READY"
        print(f"{row['scanner']:<9} {state:<10} {row['source']:<22} "
              f"{row['connection']} {row['model']}".rstrip())
        if row["problem"]:
            print(f"{'':<20} -> {row['problem']}")
    return probe(args.probe) if args.probe else 0


if __name__ == "__main__":
    sys.exit(main())
