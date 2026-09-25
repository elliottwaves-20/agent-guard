"""The one-command test runner: right interpreter per group, no silent skips."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

runner = importlib.import_module("run_all_tests")

SAMPLE = '''
import unittest

class Sample(unittest.TestCase):
    def test_pass(self):
        pass

    @unittest.skip("needs something")
    def test_skip(self):
        pass

class Other(unittest.TestCase):
    def test_fail(self):
        self.fail("boom")
'''


class ChildRunnerTests(unittest.TestCase):
    """The child snippet really runs unittest and reports every skip by id."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tests = Path(self.tmp.name) / "tests"
        self.tests.mkdir()
        (self.tests / "test_sample.py").write_text(SAMPLE, encoding="utf-8")
        (self.tests / "test_excluded.py").write_text(
            "import unittest\nclass X(unittest.TestCase):\n"
            "    def test_x(self):\n        raise SystemExit('must not run')\n",
            encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_group(self, **group):
        group = {"name": "g", "python": sys.executable, "pattern": "test*.py",
                 "exclude": (), "env": {}, **group}
        return runner.run_group(group, root=Path(self.tmp.name), echo=lambda _t: None)

    def test_counts_failures_and_names_skips(self):
        result = self.run_group(exclude=("test_excluded",))
        self.assertEqual(result["ran"], 3)
        self.assertEqual(result["failures"], 1)
        self.assertEqual(result["skipped"], [["test_sample.Sample.test_skip", "needs something"]])

    def test_pattern_selects_one_module(self):
        result = self.run_group(pattern="test_sample.py")
        self.assertEqual(result["ran"], 3)

    def test_group_env_reaches_the_child(self):
        (self.tests / "test_env.py").write_text(
            "import os, unittest\nclass E(unittest.TestCase):\n"
            "    def test_env(self):\n        assert os.environ['MARK'] == 'on'\n",
            encoding="utf-8")
        result = self.run_group(pattern="test_env.py", env={"MARK": "on"})
        self.assertEqual((result["ran"], result["failures"]), (1, 0))

    def test_crashing_child_is_a_failure(self):
        result = self.run_group(python=sys.executable, pattern="test_sample.py",
                                env={"PYTHONPATH": "", "PYTHONSTARTUP": ""},
                                _child="raise SystemExit(7)")
        self.assertIsNone(result["ran"])
        self.assertIn("exit 7", result["error"])


class PlanTests(unittest.TestCase):
    def test_groups_cover_every_gate_and_the_budget_contract_runs_once(self):
        with patch.object(runner, "tool_python", return_value="tool-python"):
            groups = runner.plan(live=False)
        suite, contract = groups
        self.assertEqual(suite["python"], sys.executable)
        self.assertIn("test_llm_budget_installed", suite["exclude"])
        self.assertEqual(suite["env"]["AGENT_GUARD_INTEGRATION"], "1")
        self.assertNotIn("AGENT_GUARD_LLM_INTEGRATION", suite["env"])
        self.assertEqual(contract["python"], "tool-python")
        self.assertEqual(contract["pattern"], "test_llm_budget_installed.py")
        self.assertEqual(contract["env"]["AGENT_GUARD_BUDGET_CONTRACT"], "1")

    def test_live_flag_opens_the_live_gate(self):
        with patch.object(runner, "tool_python", return_value="tool-python"):
            suite, _ = runner.plan(live=True)
        self.assertEqual(suite["env"]["AGENT_GUARD_LLM_INTEGRATION"], "1")

    def test_missing_tool_python_fails_that_group(self):
        with patch.object(runner, "tool_python", return_value=None):
            _, contract = runner.plan(live=False)
        self.assertIsNone(contract["python"])
        result = runner.run_group(contract, root=ROOT, echo=lambda _t: None)
        self.assertIn("SkillSpector tool environment", result["error"])


class VerdictTests(unittest.TestCase):
    def ok(self, **extra):
        return {"name": "g", "ran": 5, "failures": 0, "skipped": [], "error": "", **extra}

    def test_all_green_and_nothing_skipped_passes(self):
        self.assertEqual(runner.verdict([self.ok(), self.ok()], live=True)[0], 0)

    def test_any_skip_fails_the_run(self):
        code, lines = runner.verdict([self.ok(skipped=[["a.B.c", "why"]])], live=True)
        self.assertEqual(code, 1)
        self.assertTrue(any("a.B.c" in line for line in lines))

    def test_skips_without_live_point_to_the_flag(self):
        code, lines = runner.verdict([self.ok(skipped=[["a.B.c", "why"]])], live=False)
        self.assertEqual(code, 1)
        self.assertTrue(any("--live" in line for line in lines))

    def test_failures_and_errors_fail_the_run(self):
        self.assertEqual(runner.verdict([self.ok(failures=1)], live=True)[0], 1)
        self.assertEqual(runner.verdict([self.ok(ran=None, error="x")], live=True)[0], 1)

    def test_an_empty_group_fails_the_run(self):
        self.assertEqual(runner.verdict([self.ok(ran=0)], live=True)[0], 1)


if __name__ == "__main__":
    unittest.main()
