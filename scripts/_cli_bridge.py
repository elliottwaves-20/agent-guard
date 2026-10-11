#!/usr/bin/env python3
"""OpenAI-compatible localhost bridge in front of an agent CLI login.

Cisco's mcp-scanner reaches models only through LiteLLM with an API key. This
bridge lets it use the user's ChatGPT login instead: scan_mcp.py starts it for
one Cisco run inside SkillSpector's Python, which owns the hardened
run_agent_cli("opencode", ...) (deny-all agent, scrubbed env, temp cwd), and
kills it afterwards. It binds 127.0.0.1 only, needs a per-run token and logs
no prompt or answer text.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid

FENCE_NOTE = "Respond with the answer only, no preamble and no code fences."


class CliTimeout(Exception):
    """The CLI ran past the per-call timeout."""


def _text(content) -> str:
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content if isinstance(content, str) else ""


def build_prompt(messages: list) -> str:
    parts = [f"[{str(m.get('role', 'user')).upper()}]\n{_text(m.get('content'))}"
             for m in messages]
    return "\n\n".join(parts + [FENCE_NOTE])


def has_json_object(text: str) -> bool:
    """True when the text holds a JSON object, whole or as its first decodable {...}."""
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            value, _ = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        if isinstance(value, dict):
            return True
        start = text.find("{", start + 1)
    return False


def completion(content: str, model: str) -> dict:
    return {"id": "chatcmpl-" + uuid.uuid4().hex, "object": "chat.completion",
            "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def _error(status: int, message: str) -> tuple[int, dict]:
    return status, {"error": {"message": message}}


class Bridge:
    def __init__(self, runner, *, model: str, concurrency: int = 3, timeout: float = 120,
                 log=None):
        self.runner, self.model, self.timeout = runner, model, timeout
        self.slots = threading.Semaphore(concurrency)
        self.log = log if log is not None else sys.stderr

    def _note(self, **fields):
        print(" ".join(f"{k}={v}" for k, v in fields.items()), file=self.log, flush=True)

    def complete(self, body: dict) -> tuple[int, dict]:
        messages = body.get("messages") if isinstance(body, dict) else None
        if not isinstance(messages, list) or not messages:
            return _error(400, "messages must be a non-empty list")
        prompt = build_prompt(messages)
        queued = time.monotonic()
        with self.slots:
            wait = time.monotonic() - queued
            started = time.monotonic()
            status, payload, out = self._run(prompt)
        self._note(status=status, wait=f"{wait:.1f}s", run=f"{time.monotonic() - started:.1f}s",
                   prompt_len=len(prompt), answer_len=len(out))
        return status, payload

    def _run(self, prompt: str):
        out = ""
        for _attempt in range(2):
            try:
                out = self.runner(prompt, self.model, self.timeout)
            except CliTimeout:
                return (*_error(504, f"CLI timed out after {self.timeout:.0f}s"), out)
            except Exception as exc:  # noqa: BLE001 -- any CLI failure fails closed
                return (*_error(502, f"CLI failed: {type(exc).__name__}"), out)
            if has_json_object(out):
                return 200, completion(out, self.model), out
        return (*_error(502, "CLI answer holds no JSON object (after one retry)"), out)
