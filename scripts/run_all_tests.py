#!/usr/bin/env python3
"""Run the complete test suite in one command -- and fail on any skip.

The plain `python -m unittest discover -s tests` run is fast and free, so the
tests that need installed scanners or real LLM calls are gated by environment
variables and show up as "skipped". A release needs all of them. This runner
opens every gate and uses the interpreter each group needs:

  suite            this Python, AGENT_GUARD_INTEGRATION=1 (installed Cisco and
                   SkillSpector, no network); with --live also
                   AGENT_GUARD_LLM_INTEGRATION=1 (real LLM calls)
  budget-contract  SkillSpector's own tool Python, AGENT_GUARD_BUDGET_CONTRACT=1
                   (simulated answers, network blocked)

The run passes only when every group ran, nothing failed and nothing was
skipped. Without --live the two live LLM tests stay skipped, so the run is
reported as incomplete: --live spends real subscription budget or credit.

  python scripts/run_all_tests.py           everything except live LLM calls
  python scripts/run_all_tests.py --live    everything
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = "@@AGENT_GUARD_TEST_RESULT@@"
GROUP_TIMEOUT = 3600

# Runs inside the group's interpreter: discover, drop excluded modules, run,
# and print one machine-readable line with the counts and every skipped id.
CHILD = r"""
import json, sys, unittest
pattern, exclude = sys.argv[1], [m for m in sys.argv[2].split(",") if m]

def flat(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flat(item)
        else:
            yield item

loaded = unittest.defaultTestLoader.discover("tests", pattern=pattern)
tests = [t for t in flat(loaded) if t.id().split(".")[0] not in exclude]
result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(tests))
print(MARKER + json.dumps({
    "ran": result.testsRun,
    "failures": len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses),
    "skipped": [[t.id(), str(reason)] for t, reason in result.skipped],
}))
""".replace("MARKER", repr(MARKER))


def tool_python() -> str | None:
    """SkillSpector's tool interpreter (the budget contract imports its code)."""
    import _skillspector
    return _skillspector.skillspector_python()


def plan(live: bool) -> list[dict]:
    suite_env = {"AGENT_GUARD_INTEGRATION": "1"}
    if live:
        suite_env["AGENT_GUARD_LLM_INTEGRATION"] = "1"
    return [
        {"name": "suite", "python": sys.executable, "pattern": "test*.py",
         "exclude": ("test_llm_budget_installed",), "env": suite_env},
        {"name": "budget-contract", "python": tool_python(),
         "pattern": "test_llm_budget_installed.py", "exclude": (),
         "env": {"AGENT_GUARD_BUDGET_CONTRACT": "1"}},
    ]


def run_group(group: dict, root: Path = ROOT, echo=print) -> dict:
    result = {"name": group["name"], "ran": None, "failures": 0, "skipped": [], "error": ""}
    if not group["python"]:
        result["error"] = ("SkillSpector tool environment not found "
                           "(run setup.sh / setup.ps1 first)")
        return result
    argv = [group["python"], "-c", group.get("_child", CHILD),
            group["pattern"], ",".join(group["exclude"])]
    env = {**os.environ, **group["env"], "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    try:
        proc = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=GROUP_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["error"] = f"could not run: {exc}"
        return result
    lines = proc.stdout.splitlines()
    payload = next((line[len(MARKER):] for line in reversed(lines)
                    if line.startswith(MARKER)), None)
    if payload is None:
        result["error"] = f"no result from the test process (exit {proc.returncode})"
        echo((proc.stdout + proc.stderr)[-4000:])
        return result
    result.update(json.loads(payload))
    if result["failures"]:
        echo(proc.stderr[-20000:])
    return result


def verdict(results: list[dict], live: bool) -> tuple[int, list[str]]:
    lines, code = [], 0
    for r in results:
        if r["ran"] is None:
            code = 1
            lines.append(f"  {r['name']}: ERROR -- {r['error']}")
            continue
        state = "OK" if not (r["failures"] or r["skipped"] or r["ran"] == 0) else "FAILED"
        lines.append(f"  {r['name']}: {r['ran']} run, {r['failures']} failed, "
                     f"{len(r['skipped'])} skipped -- {state}")
        if r["ran"] == 0:
            lines.append("    no tests were collected")
        for test_id, reason in r["skipped"]:
            lines.append(f"    skipped {test_id}: {reason}")
        if state != "OK":
            code = 1
    if code and not live and any(r["skipped"] for r in results):
        lines.append("  INCOMPLETE: live LLM tests need --live (real subscription budget)")
    lines.append("ALL GREEN, NOTHING SKIPPED" if code == 0 else "NOT GREEN")
    return code, lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--live", action="store_true",
                        help="also run the live LLM tests (real calls, costs budget)")
    args = parser.parse_args()
    results = []
    for group in plan(args.live):
        print(f"== {group['name']} ({group['python'] or 'missing interpreter'})", flush=True)
        results.append(run_group(group))
    code, lines = verdict(results, args.live)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    import _console

    _console.utf8_stdio()
    sys.exit(main())
