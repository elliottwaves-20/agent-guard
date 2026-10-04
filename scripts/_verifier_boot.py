#!/usr/bin/env python3
"""Run verifier prompts through SkillSpector's hardened agent-CLI entry point.

Runs inside SkillSpector's tool environment. Reads one JSON request from stdin:
{"cli": "codex", "model": "...", "timeout": 300, "prompts": ["...", ...]}
and writes one JSON list to stdout, one entry per prompt:
{"ok": true, "text": "..."} or {"ok": false, "error": "..."}.

run_agent_cli delivers each prompt via stdin only, in an empty temporary
directory, with a scrubbed environment and a hard timeout.
"""
import json
import sys


def main() -> None:
    from skillspector.providers._agent_cli import run_agent_cli

    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    out = []
    for prompt in request["prompts"]:
        try:
            text = run_agent_cli(request["cli"], prompt, model=request["model"],
                                 timeout=float(request.get("timeout", 300)))
            out.append({"ok": True, "text": text})
        except Exception as exc:  # every failure is reported, never raised past here
            out.append({"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]})
    sys.stdout.buffer.write(json.dumps(out).encode("utf-8"))


if __name__ == "__main__":
    main()
