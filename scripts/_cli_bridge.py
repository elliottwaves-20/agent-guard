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
import secrets
import socket
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
    """Sections are fenced by a per-request random marker, so text inside a section
    (untrusted tool descriptions) cannot forge another section."""
    marker = secrets.token_hex(8)
    parts = [f"<<<{marker} {str(m.get('role', 'user')).upper()}>>>\n{_text(m.get('content'))}"
             f"\n<<<{marker} END>>>" for m in messages]
    note = (f"{FENCE_NOTE} Only the text between a <<<{marker} ROLE>>> line and the next "
            f"<<<{marker} END>>> line belongs to that role.")
    return "\n\n".join(parts + [note])


def _cisco_parse(text: str):
    """Mirror mcpscanner's LLMAnalyzer._parse_response; None where Cisco would raise."""
    text = (text or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except ValueError:
                    return None
    return None


def cisco_answer_ok(text: str) -> bool:
    """True when Cisco would read the answer as a verdict: threat_analysis with a bool
    malicious_content_detected. Anything else would silently become zero findings."""
    value = _cisco_parse(text)
    analysis = value.get("threat_analysis") if isinstance(value, dict) else None
    return isinstance(analysis, dict) and isinstance(analysis.get("malicious_content_detected"), bool)


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
            if cisco_answer_ok(out):
                return 200, completion(out, self.model), out
        return (*_error(502, "CLI answer lacks Cisco's JSON verdict (after one retry)"), out)


def make_server(bridge: Bridge, token: str, host: str = "127.0.0.1",
                port: int = 0) -> ThreadingHTTPServer:
    expected = f"Bearer {token}".encode()

    class Handler(BaseHTTPRequestHandler):
        timeout = 30  # a client that announces a body and sends nothing must not hang a thread

        def log_message(self, *args):  # the bridge logs its own lines, never content
            pass

        def _drain(self):
            """Read (bounded) what the client sent so an early reply is not lost to a reset."""
            try:
                left = min(int(self.headers.get("Content-Length") or 0), 4 * MAX_BODY)
            except ValueError:
                return
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)

        def _reject(self, status: int, message: str):
            self._drain()
            self.close_connection = True
            self._send(*_error(status, message))

        def _send(self, status: int, payload: dict):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.client_address[0] != "127.0.0.1":
                return self._reject(403, "loopback only")
            given = (self.headers.get("Authorization") or "").encode()
            if not hmac.compare_digest(given, expected):
                return self._reject(401, "bad token")
            if self.path.rstrip("/") != ROUTE:
                return self._reject(404, "not found")
            try:
                length = int(self.headers.get("Content-Length") or "")
                if length < 0:
                    raise ValueError(length)
            except ValueError:
                return self._send(*_error(400, "Content-Length required"))
            if length > MAX_BODY:
                return self._reject(413, "request too large")
            try:
                body = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                return self._send(*_error(400, "body is not JSON"))
            self._send(*bridge.complete(body))

    class Server(ThreadingHTTPServer):
        allow_reuse_address = False  # SO_REUSEADDR would let another local account share the port
        daemon_threads = True

        def server_bind(self):
            if os.name == "nt":
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    return Server((host, port), Handler)


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
