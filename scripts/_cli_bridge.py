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

import argparse
import hmac
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1_048_576
ROUTE = "/v1/chat/completions"
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


def make_server(bridge: Bridge, token: str, host: str = "127.0.0.1",
                port: int = 0) -> ThreadingHTTPServer:
    expected = f"Bearer {token}".encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # the bridge logs its own lines, never content
            pass

        def _send(self, status: int, payload: dict):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.client_address[0] != "127.0.0.1":
                return self._send(*_error(403, "loopback only"))
            given = (self.headers.get("Authorization") or "").encode()
            if not hmac.compare_digest(given, expected):
                return self._send(*_error(401, "bad token"))
            if self.path.rstrip("/") != ROUTE:
                return self._send(*_error(404, "not found"))
            try:
                length = int(self.headers.get("Content-Length") or "")
            except ValueError:
                return self._send(*_error(400, "Content-Length required"))
            if length > MAX_BODY:
                # drain (bounded) so the reply is not lost to a connection reset
                left = min(length, 4 * MAX_BODY)
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                self.close_connection = True
                return self._send(*_error(413, "request too large"))
            try:
                body = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                return self._send(*_error(400, "body is not JSON"))
            self._send(*bridge.complete(body))

    return ThreadingHTTPServer((host, port), Handler)


def opencode_runner(cli: str):
    """Runner over SkillSpector's hardened run_agent_cli; needs SkillSpector's Python."""
    import _opencode_oauth
    from skillspector.providers import _agent_cli
    if cli == "opencode" and not _opencode_oauth.keep_oauth_plugins():
        raise RuntimeError("OpenCode login plugins could not be kept on")

    def run(prompt: str, model: str, timeout: float) -> str:
        try:
            return _agent_cli.run_agent_cli(cli, prompt, model=model, timeout=timeout)
        except _agent_cli.AgentCLIError as exc:
            if "timed out" in str(exc) or "TimeoutExpired" in repr(exc.__cause__):
                raise CliTimeout(str(exc)) from exc
            raise
    return run


def main(argv=None, runner_factory=None, out=None) -> int:
    out = out if out is not None else sys.stdout
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile-json", required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.profile_json, encoding="utf-8") as fh:
            profile = json.load(fh)
        os.remove(args.profile_json)
        runner = (runner_factory or opencode_runner)(profile["cli"])
        bridge = Bridge(runner, model=profile["model"],
                        concurrency=int(profile.get("concurrency") or 3),
                        timeout=float(profile.get("timeout") or 120))
        server = make_server(bridge, profile["token"])
    except Exception as exc:  # noqa: BLE001 -- report and exit without READY
        print(f"bridge start failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"READY {server.server_address[1]}", file=out, flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
