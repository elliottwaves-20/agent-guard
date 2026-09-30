"""agent-guard's own tree must stay fully inspectable by the pinned SkillSpector.

A file SkillSpector inspects only partially gives no verdict, and no reviewed
baseline can accept that. Ordinary edits have caused it: a quoted Docker flag
read as a text-removal directive, a literal backtick in Python code, a quoted
placeholder in a shell example. This test scans the tracked files of the
working tree statically (no LLM) and names every file that is not fully
inspected, so such an edit fails here instead of in the release self-scan.
"""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
ss = importlib.import_module("_skillspector")


def tracked_files() -> list:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True,
                         check=True, timeout=60)
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to test with the installed SkillSpector")
class SelfInspectionTests(unittest.TestCase):
    def test_own_tree_is_fully_inspected(self):
        ss.need_skillspector()
        if shutil.which("git") is None or not (ROOT / ".git").exists():
            self.fail("needs a git checkout of agent-guard to know which files ship")
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "agent-guard"
            for rel in tracked_files():
                source = ROOT / rel
                if source.is_file():
                    dest = tree / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
            report = Path(tmp) / "report.json"
            cmd = ss.skillspector_command() + ["scan", str(tree), "--no-llm",
                                               "--format", "json", "--output", str(report)]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", env=ss.skillspector_env(), timeout=600)
            self.assertTrue(report.is_file(), result.stderr[-2000:])
            completeness = json.loads(report.read_text(encoding="utf-8"))["analysis_completeness"]
        gaps = [f"{e.get('path')}: {e.get('reason_code')}"
                for e in completeness.get("ledger_exceptions") or []
                if e.get("reason_code") != "reference_missing"]
        self.assertEqual(gaps, [], "not fully inspected -- see the module docstring")
        self.assertEqual(completeness.get("partially_inspected_files"), 0)
        self.assertEqual(completeness.get("entirely_uninspected_files"), 0)
        self.assertEqual(completeness.get("limitations") or [], [])


if __name__ == "__main__":
    unittest.main()
