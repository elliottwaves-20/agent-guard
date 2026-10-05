"""Locating the lines behind a parser-limit AE1: answers are taken only when complete."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
ps = importlib.import_module("_parse_spans")


class AnswerTests(unittest.TestCase):
    def test_complete_answer_is_taken(self):
        self.assertEqual(ps.parse_answer({"spans": [[3, 5], [9, 9]]}), [(3, 5), (9, 9)])
        self.assertEqual(ps.parse_answer({"spans": []}), [])

    def test_errors_and_malformed_answers_are_none(self):
        for item in ({"error": "time limit reached"}, {"spans": [[0, 2]]}, {"spans": [[5, 3]]},
                     {"spans": [[1]]}, {"spans": [["1", "2"]]}, {"spans": "1-2"}, None, [],
                     {"spans": [[1, 1]] * (ps.MAX_SPANS + 1)}, {"spans": [[1, 2]], "error": "x"}):
            with self.subTest(item):
                self.assertIsNone(ps.parse_answer(item))


class RunBootTests(unittest.TestCase):
    def run_with(self, returncode=0, stdout=b"[]", exc=None):
        done = type("Done", (), {"returncode": returncode, "stdout": stdout})()
        with patch.object(ps.subprocess, "run", side_effect=exc, return_value=done):
            return ps.run_boot("python", [Path("a.md"), Path("b.md")])

    def test_every_failure_is_none_for_every_file(self):
        import subprocess
        for kw in ({"returncode": 1}, {"stdout": b"not json"}, {"stdout": b'[{"spans": []}]'},
                   {"stdout": b"\xff"}, {"exc": subprocess.TimeoutExpired("x", 1)},
                   {"exc": OSError("missing")}):
            with self.subTest(kw):
                self.assertEqual(self.run_with(**kw), [None, None])

    def test_answers_are_matched_to_files(self):
        out = self.run_with(stdout=b'[{"spans": [[2, 2]]}, {"error": "x"}]')
        self.assertEqual(out, [[(2, 2)], None])

    def test_locator_asks_once_per_file(self):
        seen = []
        locator = ps.Locator(lambda paths: seen.append(paths) or [[(1, 1)]] * len(paths))
        found = locator(Path("skill"), ["b.md", "a.md", "b.md"])
        self.assertEqual(found, {"a.md": [(1, 1)], "b.md": [(1, 1)]})
        self.assertEqual(seen, [[Path("skill") / "a.md", Path("skill") / "b.md"]])


def _tool_python():
    import _skillspector
    return _skillspector.skillspector_python()


@unittest.skipUnless(_tool_python(), "SkillSpector tool environment not installed")
class PinnedParserTests(unittest.TestCase):
    """The boot against the real pinned parser; it only reads text."""

    def spans(self, name, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(text, encoding="utf-8")
            return ps.run_boot(_tool_python(), [path])[0]

    def test_table_cell_named_like_a_command_is_located(self):
        text = "# Guide\n\nSome prose.\n\n|---|---|\n| timeout | Max wait in seconds |\n\nMore prose.\n"
        spans = self.spans("guide.md", text)
        self.assertTrue(spans, spans)
        lines = text.splitlines()
        located = "\n".join(lines[s - 1] for a, b in spans for s in range(a, b + 1))
        self.assertIn("timeout", located)
        self.assertNotIn("More prose", located)

    def test_every_trigger_is_located(self):
        table = "|---|---|\n| timeout | Max wait in seconds |\n"
        text = table + "\nplain words\n" * 30 + table
        spans = self.spans("guide.md", text)
        self.assertIsNotNone(spans)
        self.assertGreaterEqual(len(spans), 2)

    def test_clean_file_has_no_spans(self):
        self.assertEqual(self.spans("guide.md", "# Guide\n\nPlain prose only.\n"), [])


if __name__ == "__main__":
    unittest.main()
