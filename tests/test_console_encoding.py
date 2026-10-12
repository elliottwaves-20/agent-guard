"""Redirected Windows output defaults to cp1252; the CLIs must still emit UTF-8 (issue #3)."""
import ast
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

# Written as code points so the file survives any editor or shell encoding.
ARROW = chr(0x2192)
CHECK = chr(0x2713)
NL = chr(10)

ENTRY_POINTS = ["audit_installed", "install_skill", "llm_check", "llm_scan", "scan_cli",
                "scan_mcp", "scan_skill", "scan_url", "update_skills", "verify_skills_cli",
                "run_all_tests"]


class Utf8StdioTests(unittest.TestCase):
    def test_cp1252_streams_become_utf8(self):
        import _console
        out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline=NL)
        err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline=NL)
        saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            _console.utf8_stdio()
            print(ARROW + " " + CHECK)
            print(ARROW + " " + CHECK, file=sys.stderr)
            out.flush()
            err.flush()
        finally:
            sys.stdout, sys.stderr = saved
        self.assertEqual(out.buffer.getvalue(), (ARROW + " " + CHECK + NL).encode("utf-8"))
        self.assertEqual(err.buffer.getvalue(), (ARROW + " " + CHECK + NL).encode("utf-8"))

    def test_streams_without_reconfigure_are_skipped(self):
        import _console
        saved = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = None, io.StringIO()
        try:
            _console.utf8_stdio()
        finally:
            sys.stdout, sys.stderr = saved

    def test_import_does_not_reconfigure_streams(self):
        code = ("import sys, io; sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='cp1252');"
                "sys.path.insert(0, sys.argv[1]); import _console, scan_mcp, scan_cli;"
                "sys.__stdout__.write(sys.stdout.encoding)")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"}
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        proc = subprocess.run([sys.executable, "-c", code, str(SCRIPTS)],
                              capture_output=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertEqual(proc.stdout.decode("ascii").strip(), "cp1252")


class EntryPointTests(unittest.TestCase):
    def test_unknown_argument_error_is_utf8_under_cp1252(self):
        # Every entry point uses argparse, which rejects an unknown flag with exit 2 and echoes it
        # on stderr before any network or install work. A leading positional trips the invalid-choice
        # error of subcommand scripts (required arguments would otherwise be reported first).
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"}
        env["PYTHONIOENCODING"] = "cp1252"
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        for name in ENTRY_POINTS:
            with self.subTest(script=name):
                proc = subprocess.run([sys.executable, str(SCRIPTS / f"{name}.py"), ARROW, "--bogus-" + ARROW],
                                      capture_output=True, env=env, timeout=60)
                self.assertNotIn(b"Traceback", proc.stderr)
                self.assertNotIn(b"UnicodeEncodeError", proc.stderr)
                self.assertIn(ARROW, proc.stderr.decode("utf-8"))
                self.assertEqual(proc.returncode, 2)

    def test_main_block_calls_utf8_stdio_first(self):
        for name in ENTRY_POINTS:
            with self.subTest(script=name):
                tree = ast.parse((SCRIPTS / f"{name}.py").read_text(encoding="utf-8"))
                main_blocks = [n for n in tree.body if isinstance(n, ast.If)
                               and ast.unparse(n.test).replace("'", '"') == '__name__ == "__main__"']
                self.assertEqual(len(main_blocks), 1)
                first = next(n for n in main_blocks[0].body if not isinstance(n, ast.Import))
                self.assertIsInstance(first, ast.Expr)
                self.assertRegex(ast.unparse(first.value), r"^(_console\.)?utf8_stdio\(\)$")


if __name__ == "__main__":
    unittest.main()
