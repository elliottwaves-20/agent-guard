"""Live LLM integration: the semantic layer must really run, not just be mocked.

Every other test stubs the LLM out, so a broken provider path (wrong argv,
missing auth, a CLI whose flags changed) would pass the whole suite. These
tests drive the configured coding-agent CLI for real and assert the report's
own LLM accounting.

They cost real subscription budget and need a logged-in CLI, so they are gated:

    AGENT_GUARD_LLM_INTEGRATION=1 python -m unittest discover -s tests

The live run uses the machine's real setup, because that is what scans use:
the active `skills` profile of the personal agent-guard config (read even
though the rest of the suite ignores it), or the profile named by
AGENT_GUARD_LLM_INTEGRATION_PROFILE. Without a config it follows
SKILLSPECTOR_PROVIDER / SKILLSPECTOR_MODEL, and claude_cli with the CLI's own
default model is only the last fallback. AGENT_GUARD_LLM_INTEGRATION_PROVIDER / _MODEL bypass
the config entirely.
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
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
ss = importlib.import_module("_skillspector")
import _llm_profile
import _user_config

LEGACY_PROVIDER = "claude_cli"
LEGACY_MODEL = ""


def live_selection(env) -> tuple[dict, str]:
    """Environment overlay for the live run, plus a label naming the choice.

    The overlay only steers the wrapper; provider and model are read back from
    the wrapper afterwards, so the tests drive exactly what a real scan sends."""
    clear = {"AGENT_GUARD_STATIC_ONLY": "", "AGENT_GUARD_LLM": ""}
    provider = env.get("AGENT_GUARD_LLM_INTEGRATION_PROVIDER", "").strip()
    wanted = env.get("AGENT_GUARD_LLM_INTEGRATION_PROFILE", "").strip()
    if not provider:
        search = {k: v for k, v in env.items() if k != "AGENT_GUARD_NO_USER_CONFIG"}
        path = _user_config.find_config(search)
        selected = None
        if path is not None:
            config = _user_config.load_config(env={"AGENT_GUARD_CONFIG": str(path)})
            selected = _llm_profile.select_profile(
                config, "skills", {"AGENT_GUARD_LLM_SKILLS": wanted} if wanted else {})
        if selected is not None:
            return ({**clear, "AGENT_GUARD_CONFIG": str(path),
                     "AGENT_GUARD_LLM_SKILLS": selected[0]}, f"profile {selected[0]}")
        if wanted:
            raise _llm_profile.ProfileError(
                f"AGENT_GUARD_LLM_INTEGRATION_PROFILE={wanted} needs a personal "
                "agent-guard config that defines it")
    provider = provider or env.get("SKILLSPECTOR_PROVIDER", "").strip() or LEGACY_PROVIDER
    model = (env.get("AGENT_GUARD_LLM_INTEGRATION_MODEL", "").strip()
             or env.get("SKILLSPECTOR_MODEL", "").strip() or LEGACY_MODEL)
    # Mirror the wrapper: a model from another vendor is dropped rather than
    # passed to the CLI, which would exit 1 on every call.
    if not ss.model_matches_provider(provider, model):
        model = ""
    return ({**clear, "AGENT_GUARD_CONFIG": "", "AGENT_GUARD_NO_USER_CONFIG": "1",
             "AGENT_GUARD_LLM_SKILLS": "", "SKILLSPECTOR_PROVIDER": provider,
             "SKILLSPECTOR_MODEL": model}, f"{provider} {model}".strip())


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
        self.env, label = live_selection(os.environ)
        with patch.dict(os.environ, self.env):
            importlib.reload(ss)
            self.assertTrue(ss.LLM_READY, f"{label}: {ss.LLM_REASON}")
            run_env = ss.skillspector_env()
        self.provider = run_env["SKILLSPECTOR_PROVIDER"]
        self.model = run_env.get("SKILLSPECTOR_MODEL", "")

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
        binary = ss.CLI_PROVIDERS.get(self.provider)
        if binary is not None:
            probe = (
                "import json, sys\n"
                "from skillspector.providers import _agent_cli\n"
                f"ok, reason = _agent_cli.is_available({binary!r})\n"
                "if not ok:\n"
                "    print(json.dumps({'available': False, 'reason': reason})); sys.exit(0)\n"
                f"text = _agent_cli.run_agent_cli({binary!r}, 'Reply with exactly: OK',\n"
                f"                                model={self.model!r}, timeout=180)\n"
                "print(json.dumps({'available': True, 'text': text.strip()}))\n"
            )
        else:
            probe = (
                "import json, sys\n"
                "from skillspector import llm_utils\n"
                "available, reason = llm_utils.is_llm_available()\n"
                "if not available:\n"
                "    print(json.dumps({'available': False, 'reason': reason})); sys.exit(0)\n"
                f"model = llm_utils.get_chat_model({self.model!r}, timeout=180)\n"
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


class LiveSelectionTests(unittest.TestCase):
    """Which setup the live tests drive -- checked without any LLM call."""

    CONFIG = """
[llm.use]
skills = "luna"

[llm.profiles.luna]
kind = "cli"
cli = "claude"
model = "<model-id>"

[llm.profiles.second]
kind = "cli"
cli = "claude"
model = "<model-id-2>"
"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name) / "config.toml"
        self.config.write_text(self.CONFIG, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_active_skills_profile_wins_even_in_an_isolated_suite(self):
        env = {"AGENT_GUARD_CONFIG": str(self.config), "AGENT_GUARD_NO_USER_CONFIG": "1",
               "SKILLSPECTOR_PROVIDER": "claude_cli"}
        overlay, label = live_selection(env)
        self.assertEqual(overlay["AGENT_GUARD_CONFIG"], str(self.config))
        self.assertEqual(overlay["AGENT_GUARD_LLM_SKILLS"], "luna")
        self.assertEqual(overlay["AGENT_GUARD_STATIC_ONLY"], "")
        self.assertEqual(label, "profile luna")

    def test_profile_can_be_chosen_for_the_live_run(self):
        env = {"AGENT_GUARD_CONFIG": str(self.config),
               "AGENT_GUARD_LLM_INTEGRATION_PROFILE": "second"}
        overlay, label = live_selection(env)
        self.assertEqual(overlay["AGENT_GUARD_LLM_SKILLS"], "second")

    def test_unknown_or_unconfigured_profile_is_an_error(self):
        with self.assertRaises(_llm_profile.ProfileError):
            live_selection({"AGENT_GUARD_CONFIG": str(self.config),
                            "AGENT_GUARD_LLM_INTEGRATION_PROFILE": "nope"})
        with patch.object(_user_config, "find_config", return_value=None), \
             self.assertRaises(_llm_profile.ProfileError):
            live_selection({"AGENT_GUARD_LLM_INTEGRATION_PROFILE": "second"})

    def test_explicit_provider_bypasses_the_config(self):
        env = {"AGENT_GUARD_CONFIG": str(self.config),
               "AGENT_GUARD_LLM_INTEGRATION_PROVIDER": "claude_cli",
               "AGENT_GUARD_LLM_INTEGRATION_MODEL": "claude-test-model"}
        overlay, _ = live_selection(env)
        self.assertEqual(overlay["AGENT_GUARD_NO_USER_CONFIG"], "1")
        self.assertEqual(overlay["AGENT_GUARD_CONFIG"], "")
        self.assertEqual(overlay["SKILLSPECTOR_PROVIDER"], "claude_cli")
        self.assertEqual(overlay["SKILLSPECTOR_MODEL"], "claude-test-model")

    def test_without_config_the_legacy_fallback_applies(self):
        with patch.object(_user_config, "find_config", return_value=None):
            overlay, _ = live_selection({})
        self.assertEqual(overlay["SKILLSPECTOR_PROVIDER"], LEGACY_PROVIDER)
        self.assertEqual(overlay["SKILLSPECTOR_MODEL"], LEGACY_MODEL)

    def test_overlay_drives_the_wrapper_to_the_profile(self):
        overlay, _ = live_selection({"AGENT_GUARD_CONFIG": str(self.config)})
        try:
            with patch.dict(os.environ, overlay):
                importlib.reload(ss)
                self.assertEqual(ss.LLM_PROFILE[0], "luna")
                self.assertEqual(ss.PROVIDER, "claude_cli")
        finally:
            importlib.reload(ss)


if __name__ == "__main__":
    unittest.main()
