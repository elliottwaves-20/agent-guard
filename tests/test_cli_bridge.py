"""CLI bridge: OpenAI-compatible localhost endpoint in front of an agent CLI login."""
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import _cli_bridge as cb

BODY = {"model": "openai/m", "messages": [{"role": "system", "content": "rules"},
                                          {"role": "user", "content": "tool text"}]}


def runner_returning(*answers):
    calls = []

    def run(prompt, model, timeout):
        calls.append(prompt)
        return answers[min(len(calls), len(answers)) - 1]
    run.calls = calls
    return run


class PromptTests(unittest.TestCase):
    def test_messages_become_labelled_sections_in_order(self):
        prompt = cb.build_prompt(BODY["messages"])
        self.assertLess(prompt.index("[SYSTEM]\nrules"), prompt.index("[USER]\ntool text"))
        self.assertIn("no code fences", prompt)

    def test_list_content_parts_are_joined(self):
        prompt = cb.build_prompt([{"role": "user", "content": [{"type": "text", "text": "a"},
                                                               {"type": "text", "text": "b"}]}])
        self.assertIn("[USER]\nab", prompt)


class JsonCheckTests(unittest.TestCase):
    def test_plain_object(self):
        self.assertTrue(cb.has_json_object('{"a": 1}'))

    def test_object_inside_prose_or_fences(self):
        self.assertTrue(cb.has_json_object('Here:\n```json\n{"a": {"b": 2}}\n```'))

    def test_no_object(self):
        for text in ("", "SAFE", "[1, 2]", "{broken"):
            with self.subTest(text):
                self.assertFalse(cb.has_json_object(text))


class CompleteTests(unittest.TestCase):
    def bridge(self, runner, **kw):
        return cb.Bridge(runner, model="openai/m", log=io.StringIO(), **kw)

    def test_answer_has_openai_shape(self):
        status, payload = self.bridge(runner_returning('{"ok": true}')).complete(BODY)
        self.assertEqual(status, 200)
        self.assertEqual(payload["object"], "chat.completion")
        choice = payload["choices"][0]
        self.assertEqual(choice["message"], {"role": "assistant", "content": '{"ok": true}'})
        self.assertEqual(choice["finish_reason"], "stop")

    def test_embedded_json_passes_without_retry(self):
        run = runner_returning('```json\n{"ok": true}\n```')
        status, payload = self.bridge(run).complete(BODY)
        self.assertEqual((status, len(run.calls)), (200, 1))
        self.assertEqual(payload["choices"][0]["message"]["content"], '```json\n{"ok": true}\n```')

    def test_missing_json_is_retried_once(self):
        run = runner_returning("Sorry, let me think", '{"ok": true}')
        status, _ = self.bridge(run).complete(BODY)
        self.assertEqual((status, len(run.calls)), (200, 2))

    def test_missing_json_twice_is_502(self):
        run = runner_returning("no", "still no")
        status, payload = self.bridge(run).complete(BODY)
        self.assertEqual((status, len(run.calls)), (502, 2))
        self.assertIn("JSON", payload["error"]["message"])

    def test_timeout_is_504(self):
        def run(prompt, model, timeout):
            raise cb.CliTimeout("opencode timed out")
        self.assertEqual(self.bridge(run).complete(BODY)[0], 504)

    def test_cli_failure_is_502_without_prompt(self):
        def run(prompt, model, timeout):
            raise RuntimeError("exit code 1")
        status, payload = self.bridge(run).complete(BODY)
        self.assertEqual(status, 502)
        self.assertNotIn("tool text", json.dumps(payload))

    def test_bad_body_is_400(self):
        for body in ({}, {"messages": "x"}, {"messages": []}):
            with self.subTest(body):
                self.assertEqual(self.bridge(runner_returning("{}")).complete(body)[0], 400)

    def test_never_more_than_concurrency_runs(self):
        active, peak, lock = [0], [0], threading.Lock()

        def run(prompt, model, timeout):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return "{}"
        bridge = self.bridge(run, concurrency=2)
        threads = [threading.Thread(target=bridge.complete, args=(BODY,)) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(peak[0], 2)

    def test_log_has_no_prompt_or_answer(self):
        log = io.StringIO()
        cb.Bridge(runner_returning('{"secret": 1}'), model="m", log=log).complete(BODY)
        self.assertNotIn("tool text", log.getvalue())
        self.assertNotIn("secret", log.getvalue())
        self.assertIn("status=200", log.getvalue())


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.bridge = cb.Bridge(runner_returning('{"ok": true}'), model="m", log=io.StringIO())
        self.server = cb.make_server(self.bridge, "tok")
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, path="/v1/chat/completions", body=BODY, token="tok", raw=None):
        data = raw if raw is not None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_valid_request_is_answered(self):
        status, payload = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(payload["choices"][0]["message"]["content"], '{"ok": true}')

    def test_missing_or_wrong_token_is_401(self):
        self.assertEqual(self.post(token=None)[0], 401)
        self.assertEqual(self.post(token="nope")[0], 401)

    def test_other_path_is_404(self):
        self.assertEqual(self.post(path="/v1/embeddings")[0], 404)

    def test_oversized_body_is_413(self):
        self.assertEqual(self.post(raw=b"{" + b" " * cb.MAX_BODY + b"}")[0], 413)

    def test_invalid_json_is_400(self):
        self.assertEqual(self.post(raw=b"not json")[0], 400)

    def test_negative_content_length_is_400(self):
        port = self.server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n"
                         b"Authorization: Bearer tok\r\nContent-Length: -5\r\n\r\n")
            status_line = sock.recv(1024).split(b"\r\n")[0]
        self.assertIn(b"400", status_line)

    def test_get_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.url + "/v1/chat/completions", timeout=10)
        self.assertIn(ctx.exception.code, (404, 405, 501))


class MainTests(unittest.TestCase):
    def test_main_reads_and_deletes_profile_then_reports_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            path.write_text(json.dumps({"token": "tok", "model": "m", "cli": "opencode",
                                        "concurrency": 2, "timeout": 30}), encoding="utf-8")
            out = io.StringIO()
            seen = {}

            def factory(cli):
                seen["cli"] = cli
                return runner_returning("{}")
            servers = []
            original = cb.make_server

            def capture(*a, **kw):
                servers.append(original(*a, **kw))
                return servers[-1]
            cb.make_server = capture
            try:
                t = threading.Thread(target=cb.main,
                                     args=(["--profile-json", str(path)], factory, out),
                                     daemon=True)
                t.start()
                for _ in range(100):
                    if out.getvalue():
                        break
                    time.sleep(0.02)
            finally:
                cb.make_server = original
            self.assertRegex(out.getvalue(), r"^READY \d+\n$")
            self.assertFalse(path.exists())
            self.assertEqual(seen["cli"], "opencode")
            self.assertEqual(servers[0].server_address[1], int(out.getvalue().split()[1]))
            servers[0].shutdown()
            servers[0].server_close()

    def test_unreadable_profile_exits_nonzero_without_ready(self):
        out = io.StringIO()
        self.assertNotEqual(cb.main(["--profile-json", "missing.json"], lambda c: None, out), 0)
        self.assertEqual(out.getvalue(), "")


@unittest.skipUnless(os.environ.get("AGENT_GUARD_LLM_INTEGRATION") == "1",
                     "set AGENT_GUARD_LLM_INTEGRATION=1 to call the real OpenCode login")
class LiveBridgeTests(unittest.TestCase):
    def test_opencode_answers_with_a_json_object(self):
        import subprocess as sp
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        import _skillspector as ss
        python = ss.skillspector_python()
        self.assertIsNotNone(python, "SkillSpector's Python is missing")
        model = os.environ.get("AGENT_GUARD_BRIDGE_MODEL", "openai/gpt-6-luna")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps({"token": "t" * 32, "model": model, "cli": "opencode",
                                        "concurrency": 1, "timeout": 120}), encoding="utf-8")
            script = Path(__file__).resolve().parents[1] / "scripts" / "_cli_bridge.py"
            proc = sp.Popen([python, str(script), "--profile-json", str(path)],
                            stdout=sp.PIPE, text=True)
            try:
                port = int(proc.stdout.readline().split()[1])
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/chat/completions", method="POST",
                    data=json.dumps({"messages": [{"role": "user", "content":
                        'Reply with exactly {"ok": true}'}]}).encode(),
                    headers={"Authorization": "Bearer " + "t" * 32})
                with urllib.request.urlopen(req, timeout=180) as r:
                    content = json.loads(r.read())["choices"][0]["message"]["content"]
                self.assertTrue(cb.has_json_object(content))
            finally:
                ss._terminate_tree(proc)


if __name__ == "__main__":
    unittest.main()
