"""Live LLM integration: the semantic layer must really run, not just be mocked.

Every other test stubs the LLM out, so a broken provider path (wrong argv,
missing auth, a CLI whose flags changed) would pass the whole suite. These
tests drive the configured coding-agent CLI for real and assert the report's
own LLM accounting.

They cost real subscription budget and need a logged-in CLI, so they are gated:

    AGENT_GUARD_LLM_INTEGRATION=1 python -m unittest discover -s tests

The provider follows the configured SKILLSPECTOR_PROVIDER / SKILLSPECTOR_MODEL
so these tests exercise the setup that real scans use; claude_cli with Haiku 4.5
is only the fallback when nothing is configured. Override either with
AGENT_GUARD_LLM_INTEGRATION_PROVIDER / AGENT_GUARD_LLM_INTEGRATION_MODEL.
"""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
ss = importlib.import_module("_skillspector")

PROVIDER = (os.environ.get("AGENT_GUARD_LLM_INTEGRATION_PROVIDER")
            or os.environ.get("SKILLSPECTOR_PROVIDER")
            or "claude_cli")
MODEL = (os.environ.get("AGENT_GUARD_LLM_INTEGRATION_MODEL")
         or os.environ.get("SKILLSPECTOR_MODEL")
         or "claude-haiku-4-5-20251001")
# Mirror the wrapper: a model from another vendor is dropped rather than passed
# to the CLI, which would exit 1 on every call. Without this the test fails on a
# leftover SKILLSPECTOR_MODEL that real scans never send.
if not ss.model_matches_provider(PROVIDER, MODEL):
    MODEL = ""

HARMLESS_SKILL = """---
name: greeting-fixture
description: Minimal harmless fixture used to verify the semantic analysis path.
---

# Greeting fixture

This skill greets the user. It reads no files, contacts no network service,
and ships no scripts.
"""


@unittest.skipUnless(os.environ.get("AGENT_GUARD_LLM_INTEGRATION") == "1",
                     "set AGENT_GUARD_LLM_INTEGRATION=1 to run the live LLM path "
                     "(uses the local CLI login and real subscription budget)")
class LiveLLMProviderTests(unittest.TestCase):
    """The configured provider answers a real prompt through SkillSpector's runner."""

    def setUp(self):
        self.env = {"SKILLSPECTOR_PROVIDER": PROVIDER, "SKILLSPECTOR_MODEL": MODEL,
                    "AGENT_GUARD_STATIC_ONLY": ""}
        with patch.dict(os.environ, self.env):
            importlib.reload(ss)
            self.assertTrue(ss.LLM_READY, ss.LLM_REASON)

    def tearDown(self):
        importlib.reload(ss)

    def test_provider_is_authenticated_and_answers(self):
        """The configured provider's auth probe and output contract still hold.

        CLI providers are checked through their own argv/subprocess transport,
        because a changed flag there breaks every scan. Key-based providers
        (anthropic, openai_compatible, ...) have no binary, so they are driven
        through ``llm_utils.get_chat_model`` -- the same entry point the
        analyzers use -- so this test covers the configured provider instead
        of failing whenever that provider is not a CLI.
        """
        python = ss.skillspector_python()
        self.assertIsNotNone(python, "SkillSpector tool environment not found")
        binary = ss.CLI_PROVIDERS.get(PROVIDER)
        if binary is not None:
            probe = (
                "import json, sys\n"
                "from skillspector.providers import _agent_cli\n"
                f"ok, reason = _agent_cli.is_available({binary!r})\n"
                "if not ok:\n"
                "    print(json.dumps({'available': False, 'reason': reason})); sys.exit(0)\n"
                f"text = _agent_cli.run_agent_cli({binary!r}, 'Reply with exactly: OK',\n"
                f"                                model={MODEL!r}, timeout=180)\n"
                "print(json.dumps({'available': True, 'text': text.strip()}))\n"
            )
        else:
            probe = (
                "import json, sys\n"
                "from skillspector import llm_utils\n"
                "available, reason = llm_utils.is_llm_available()\n"
                "if not available:\n"
                "    print(json.dumps({'available': False, 'reason': reason})); sys.exit(0)\n"
                f"model = llm_utils.get_chat_model({MODEL!r}, timeout=180)\n"
                "answer = model.invoke('Reply with exactly: OK')\n"
                "text = getattr(answer, 'content', answer)\n"
                "print(json.dumps({'available': True, 'text': str(text).strip()}))\n"
            )
        import subprocess
        with patch.dict(os.environ, self.env):
            env = ss.skillspector_env()
        result = subprocess.run([python, "-c", probe], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", env=env, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(payload["available"], payload.get("reason"))
        self.assertIn("OK", payload["text"])

    def test_scan_of_a_harmless_skill_has_complete_llm_coverage(self):
        """A real wrapper scan must reach SAFE with every LLM call accounted for."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skill"
            target.mkdir()
            (target / "SKILL.md").write_text(HARMLESS_SKILL, encoding="utf-8")
            report = Path(tmp) / "report.json"
            with patch.dict(os.environ, self.env):
                code = ss.run_skillspector(target, report_output=report)
            self.assertEqual(code, 0, "harmless fixture must scan SAFE")
            self.assertTrue(report.is_file(), "no JSON report was written")
            data = json.loads(report.read_text(encoding="utf-8"))
            meta = data["metadata"]
            self.assertTrue(meta.get("llm_requested"), meta)
            self.assertTrue(meta.get("llm_available"), meta)
            attempted = meta.get("llm_calls_attempted")
            self.assertIsInstance(attempted, int)
            self.assertGreater(attempted, 0, "no LLM call was made at all")
            self.assertEqual(meta.get("llm_calls_succeeded"), attempted, meta)
            self.assertEqual(ss.llm_run_incomplete(data, expected=True), "")


if __name__ == "__main__":
    unittest.main()
