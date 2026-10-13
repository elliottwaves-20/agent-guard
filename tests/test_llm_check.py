"""llm_check reports the effective LLM connection per scanner without network."""
import importlib
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
llm_check = importlib.import_module("llm_check")

CONFIG = {"llm": {"use": {"skills": "luna", "mcp": "cerebras", "campaign": "cerebras"},
                  "profiles": {
    "luna": {"kind": "cli", "cli": "claude", "model": "<model-id>"},
    "cerebras": {"kind": "api", "protocol": "openai", "base_url": "https://api.cerebras.ai/v1",
                 "model": "gpt-oss-120b", "key_env": "CEREBRAS_API_KEY", "max_output": 8192,
                 "price": {"input_usd_per_mtok": 0.35, "output_usd_per_mtok": 0.75},
                 "budget": {"total_usd": 4, "step_usd": 0.5}},
}}}


def config(use=None, **profiles):
    return {"llm": {"use": use or {}, "profiles": profiles}}


def describe(config, env, **kw):
    # Never let a test fall through to importing the real _skillspector wrapper.
    kw.setdefault("skillspector_python", lambda: "python")
    return llm_check.describe(config, env, **kw)


def rows_by_scanner(rows):
    return {row["scanner"]: row for row in rows}


class DescribeTests(unittest.TestCase):
    def test_describe_does_not_import_the_wrapper(self):
        saved = sys.modules.pop("_skillspector", None)
        if saved is not None:
            self.addCleanup(sys.modules.__setitem__, "_skillspector", saved)
        self.addCleanup(sys.modules.pop, "_skillspector", None)
        describe(CONFIG, {}, which=lambda name: None)
        self.assertNotIn("_skillspector", sys.modules)

    def test_profiles_are_reported_per_scanner(self):
        rows = rows_by_scanner(describe(
            CONFIG, {"CEREBRAS_API_KEY": "csk-x"}, which=lambda name: f"/bin/{name}"))
        self.assertEqual(rows["skills"]["source"], "profile luna")
        self.assertEqual(rows["skills"]["connection"], "claude_cli")
        self.assertEqual(rows["skills"]["model"], "<model-id>")
        self.assertTrue(rows["skills"]["ready"])
        self.assertEqual(rows["mcp"]["model"], "openai/gpt-oss-120b")
        self.assertTrue(rows["mcp"]["ready"])
        self.assertTrue(rows["campaign"]["ready"])

    def test_missing_key_and_binary_are_reported_not_raised(self):
        rows = rows_by_scanner(describe(CONFIG, {}, which=lambda name: None))
        self.assertFalse(rows["skills"]["ready"])
        self.assertIn("claude", rows["skills"]["problem"])
        self.assertFalse(rows["mcp"]["ready"])
        self.assertIn("CEREBRAS_API_KEY", rows["mcp"]["problem"])
        self.assertFalse(rows["campaign"]["ready"])
        self.assertIn("CEREBRAS_API_KEY", rows["campaign"]["problem"])

    def test_broken_profile_becomes_a_row_problem(self):
        cfg = {"llm": {"use": {"skills": "missing"}, "profiles": {}}}
        rows = rows_by_scanner(describe(cfg, {}, which=lambda name: None))
        self.assertFalse(rows["skills"]["ready"])
        self.assertIn("missing", rows["skills"]["problem"])

    def test_without_profiles_scanners_report_legacy_sources(self):
        rows = rows_by_scanner(describe(
            {}, {"MCP_SCANNER_LLM_MODEL": "openai/gpt-x"}, which=lambda name: None))
        self.assertEqual(rows["skills"]["source"], "legacy env")
        self.assertEqual(rows["mcp"]["source"], "legacy env")
        self.assertEqual(rows["mcp"]["model"], "openai/gpt-x")
        self.assertFalse(rows["mcp"]["ready"])
        self.assertEqual(rows["campaign"]["source"], "not configured")

    def test_verifier_row_follows_the_skills_row(self):
        cfg = config({"skills": "claude"}, claude={"kind": "cli", "cli": "claude"})
        rows = describe(cfg, {}, which=lambda n: f"/bin/{n}",
                        skillspector_python=lambda: "/py")
        scanners = [r["scanner"] for r in rows]
        self.assertEqual(scanners[:2], ["skills", "verifier"])
        self.assertEqual(rows[1]["connection"], rows[0]["connection"])
        self.assertEqual(rows[1]["ready"], rows[0]["ready"])

    def test_verifier_row_is_not_ready_without_the_tool_python(self):
        cfg = config({"skills": "claude"}, claude={"kind": "cli", "cli": "claude"})
        rows = describe(cfg, {}, which=lambda n: f"/bin/{n}",
                        skillspector_python=lambda: None)
        self.assertTrue(rows[0]["ready"])
        self.assertFalse(rows[1]["ready"])
        self.assertEqual(rows[1]["problem"], "SkillSpector tool Python not found")

    def test_disabled_provider_shows_its_reason(self):
        cfg = config({"skills": "luna"}, luna={"kind": "cli", "cli": "codex"})
        rows = describe(cfg, {}, which=lambda n: f"/bin/{n}",
                        skillspector_python=lambda: "/py")
        self.assertIn("codex_cli is disabled", rows[0]["problem"])
        self.assertIn("codex_cli is disabled", rows[1]["problem"])


if __name__ == "__main__":
    unittest.main()
