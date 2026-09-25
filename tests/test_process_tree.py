"""A timed-out scan must not leave the CLI's grandchildren running.

The scanner drives coding-agent CLIs, and on Windows those are npm shims:
killing the direct child leaves the real worker (`codex.exe`, `node`, a
docker client's container attachment) alive, burning the user's subscription
after the wrapper has already given up. These tests drive a real three-level
process tree through the wrapper's bounded runner and assert the grandchild
stops when the parent's deadline expires.
"""
import os
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
ss = importlib.import_module("_skillspector")

# Grandchild: append a heartbeat forever. Its file stops growing once it dies.
GRANDCHILD = """
import sys, time
beat = sys.argv[1]
while True:
    with open(beat, 'a', encoding='utf-8') as fh:
        fh.write('x')
    time.sleep(0.2)
"""

# Child: spawn the grandchild, then block. Mirrors a CLI shim that outlives
# nothing of its own but holds a real worker underneath it.
CHILD = """
import subprocess, sys, time
grandchild_src, beat = sys.argv[1], sys.argv[2]
subprocess.Popen([sys.executable, grandchild_src, beat])
time.sleep(600)
"""


def heartbeat_stopped(beat: Path, settle: float = 2.0, watch: float = 2.0) -> bool:
    """True when *beat* stops growing (the writing process is gone)."""
    time.sleep(settle)
    first = beat.stat().st_size if beat.exists() else 0
    time.sleep(watch)
    second = beat.stat().st_size if beat.exists() else 0
    return first == second


class ProcessTreeTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.grandchild_src = root / "grandchild.py"
        self.grandchild_src.write_text(GRANDCHILD, encoding="utf-8")
        self.child_src = root / "child.py"
        self.child_src.write_text(CHILD, encoding="utf-8")
        self.beat = root / "beat.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def command(self):
        return [sys.executable, str(self.child_src), str(self.grandchild_src),
                str(self.beat)]

    def test_timeout_kills_the_whole_process_tree(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            ss.run_bounded(self.command(), timeout=3)
        # Give the grandchild a moment to actually start before judging it.
        for _ in range(25):
            if self.beat.exists():
                break
            time.sleep(0.2)
        self.assertTrue(self.beat.exists(), "grandchild never started; test is inconclusive")
        self.assertTrue(heartbeat_stopped(self.beat),
                        "grandchild survived the parent's timeout")

    def test_keyboard_interrupt_kills_the_whole_process_tree(self):
        original = subprocess.Popen.communicate
        beat = self.beat

        def interrupting(self_proc, *args, **kwargs):
            # Interrupt only once the grandchild is really running, so the test
            # measures the kill and not a race against process startup. Restore
            # the real communicate immediately: the tree kill itself runs a
            # subprocess and must not be interrupted too.
            subprocess.Popen.communicate = original
            for _ in range(50):
                if beat.exists():
                    break
                time.sleep(0.2)
            raise KeyboardInterrupt

        subprocess.Popen.communicate = interrupting
        try:
            with self.assertRaises(KeyboardInterrupt):
                ss.run_bounded(self.command(), timeout=60)
        finally:
            subprocess.Popen.communicate = original
        for _ in range(25):
            if self.beat.exists():
                break
            time.sleep(0.2)
        self.assertTrue(self.beat.exists(), "grandchild never started; test is inconclusive")
        self.assertTrue(heartbeat_stopped(self.beat),
                        "grandchild survived the interrupt")

    def test_scan_paths_use_the_bounded_runner(self):
        """Regression: no long-running scan child may go back to subprocess.run.

        subprocess.run's timeout kills only the direct child, which is what
        left orphaned CLI workers behind.
        """
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        for name in ("_skillspector.py", "scan_cli.py", "scan_mcp.py"):
            lines = (scripts / name).read_text(encoding="utf-8").splitlines()
            offenders = [
                number for number, line in enumerate(lines, 1)
                if "timeout=SCAN_TIMEOUT" in line
                and "run_bounded" not in "\n".join(lines[max(0, number - 4):number])
            ]
            self.assertEqual(offenders, [],
                             f"{name} runs a scan child through subprocess.run "
                             f"at line(s) {offenders}; use run_bounded")

    def test_normal_completion_returns_output_and_exit_code(self):
        result = ss.run_bounded(
            [sys.executable, "-c",
             "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
            timeout=60)
        self.assertEqual(result.returncode, 3)
        self.assertIn("out", result.stdout)
        self.assertIn("err", result.stderr)


if __name__ == "__main__":
    unittest.main()
