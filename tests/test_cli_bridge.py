"""CLI bridge: OpenAI-compatible localhost endpoint in front of an agent CLI login."""
import io
import json
import sys
import threading
import time
import unittest
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


if __name__ == "__main__":
    unittest.main()
