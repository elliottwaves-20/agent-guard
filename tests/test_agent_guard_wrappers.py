import importlib
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


class SkillSpectorWrapperTests(unittest.TestCase):
    def test_anthropic_provider_disables_skillspector_llm(self):
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({
                "SKILLSPECTOR_PROVIDER": "anthropic",
                "ANTHROPIC_API_KEY": "sk-ant-test",
                "SKILLSPECTOR_MODEL": "claude-test",
            })
            module = importlib.import_module("_skillspector")
            module = importlib.reload(module)

            self.assertFalse(module.skillspector_llm_usable())
            env = module.skillspector_env()
            self.assertEqual(env["PYTHONUTF8"], "1")
            self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
            self.assertNotIn("SKILLSPECTOR_PROVIDER", env)
            self.assertNotIn("ANTHROPIC_API_KEY", env)
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("_skillspector"))

    def test_scan_mcp_delegates_static_scan_to_shared_wrapper_with_runtime_hint(self):
        scan_mcp = importlib.import_module("scan_mcp")

        calls = []

        def fake_run_skillspector(src, runtime_hint=False):
            calls.append((Path(src), runtime_hint))
            return 0

        original = scan_mcp.shared_run_skillspector
        try:
            scan_mcp.shared_run_skillspector = fake_run_skillspector
            self.assertEqual(scan_mcp.run_skillspector(Path("example")), 0)
        finally:
            scan_mcp.shared_run_skillspector = original

        self.assertEqual(calls, [(Path("example"), True)])

    def test_docs_use_scan_skill_wrapper_for_skill_scans(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("python scripts/scan_skill.py", readme)
        self.assertIn("python \"$SKILL_DIR/scripts/scan_skill.py\"", skill)
        self.assertNotIn("PYTHONUTF8=1 skillspector scan", readme)
        self.assertNotIn("PYTHONUTF8=1 skillspector scan", skill)
        self.assertNotIn("fast + cheap for scanning", readme)


if __name__ == "__main__":
    unittest.main()
