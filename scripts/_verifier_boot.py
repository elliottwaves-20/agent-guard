#!/usr/bin/env python3
"""Run verifier prompts through SkillSpector's own LLM client.

Runs inside SkillSpector's tool environment with the same environment as the
skill scan, so the verifier reaches exactly the provider the scan used: an
API provider through its native client, an agent CLI through SkillSpector's
hardened subprocess path (tool-less, prompt via stdin, scrubbed environment,
empty temporary directory). Reads {"timeout": 300, "prompts": [...]} from stdin
and writes one list entry per prompt: {"ok": true, "text": ...} or
{"ok": false, "error": ...}.
"""
import json
import sys


def main() -> None:
    from skillspector.llm_utils import chat_completion

    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    timeout = float(request.get("timeout", 300))
    out = []
    for prompt in request["prompts"]:
        try:
            text = chat_completion(prompt, timeout=timeout, node="agent_guard_verifier",
                                   request_kind="verifier")
            out.append({"ok": True, "text": str(text)})
        except Exception as exc:  # every failure is reported, never raised past here
            out.append({"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]})
    sys.stdout.buffer.write(json.dumps(out).encode("utf-8"))


if __name__ == "__main__":
    main()
