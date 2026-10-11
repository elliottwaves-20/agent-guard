"""scan_mcp starts the CLI bridge for one Cisco run and always removes it."""
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
import scan_mcp  # noqa: E402

PROFILE = {"kind": "cli", "cli": "opencode", "model": "openai/m"}


def alive(pid: int) -> bool:
    if os.name == "nt":
        # Bytes, not text: tasklist output is in the OEM code page (umlauts).
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True)
        return str(pid).encode() in out.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class FakeBridge:
    """A stand-in bridge script: optional READY, writes its own and a child's PID."""

    def __init__(self, tmp: Path, ready: bool = True):
        self.pids = tmp / "pids.txt"
        self.script = tmp / "fake_bridge.py"
        self.script.write_text(textwrap.dedent(f"""
            import json, subprocess, sys, time
            path = sys.argv[sys.argv.index("--profile-json") + 1]
            json.load(open(path, encoding="utf-8"))
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
            open({str(self.pids)!r}, "w").write(f"{{child.pid}}")
            if {ready!r}:
                print("READY 4242", flush=True)
            time.sleep(120)
        """), encoding="utf-8")

    def child_pid(self) -> int:
        for _ in range(100):
            if self.pids.exists() and self.pids.read_text():
                return int(self.pids.read_text())
            time.sleep(0.05)
        raise AssertionError("fake bridge did not start")


class CliBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_yields_port_and_token_and_kills_tree(self):
        fake = FakeBridge(Path(self.tmp.name))
        with scan_mcp.cli_bridge(PROFILE, python=sys.executable, script=fake.script) as (port, token):
            self.assertEqual(port, 4242)
            self.assertGreaterEqual(len(token), 32)
            child = fake.child_pid()
            self.assertTrue(alive(child))
        time.sleep(0.5)
        self.assertFalse(alive(child))

    def test_bridge_tree_is_killed_on_exception(self):
        fake = FakeBridge(Path(self.tmp.name))
        with self.assertRaises(RuntimeError):
            with scan_mcp.cli_bridge(PROFILE, python=sys.executable, script=fake.script):
                child = fake.child_pid()
                raise RuntimeError("scan crashed")
        time.sleep(0.5)
        self.assertFalse(alive(child))

    def test_no_ready_fails_closed(self):
        fake = FakeBridge(Path(self.tmp.name), ready=False)
        with self.assertRaises(SystemExit) as ctx:
            with scan_mcp.cli_bridge(PROFILE, python=sys.executable, script=fake.script, wait=2):
                self.fail("must not yield without READY")
        self.assertEqual(ctx.exception.code, 2)
        time.sleep(0.5)
        self.assertFalse(alive(fake.child_pid()))

    def test_token_is_not_in_the_command_line(self):
        fake = FakeBridge(Path(self.tmp.name))
        seen = {}
        original = subprocess.Popen

        def spy(cmd, *a, **kw):
            seen["cmd"] = cmd
            return original(cmd, *a, **kw)
        with patch.object(scan_mcp.subprocess, "Popen", side_effect=spy):
            with scan_mcp.cli_bridge(PROFILE, python=sys.executable, script=fake.script) as (_, token):
                pass
        self.assertNotIn(token, " ".join(map(str, seen["cmd"])))


    def test_token_file_is_removed_when_popen_fails(self):
        made = []
        original = tempfile.mkstemp

        def spy(*a, **kw):
            fd, path = original(*a, **kw)
            made.append(path)
            return fd, path
        with patch.object(scan_mcp.tempfile, "mkstemp", side_effect=spy),              patch.object(scan_mcp.subprocess, "Popen", side_effect=OSError("no exec")):
            with self.assertRaises(OSError):
                with scan_mcp.cli_bridge(PROFILE, python=sys.executable):
                    self.fail("must not yield")
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))


class ProblemTests(unittest.TestCase):
    def test_problem_without_skillspector_python(self):
        with patch.object(scan_mcp, "CISCO_PROFILE", ("chatgpt", PROFILE)), \
             patch.object(scan_mcp, "skillspector_python", return_value=None):
            self.assertIn("SkillSpector", scan_mcp.cisco_llm_problem())

    def test_problem_without_opencode(self):
        with patch.object(scan_mcp, "CISCO_PROFILE", ("chatgpt", PROFILE)), \
             patch.object(scan_mcp, "skillspector_python", return_value=sys.executable), \
             patch.object(scan_mcp.shutil, "which", return_value=None):
            self.assertIn("opencode", scan_mcp.cisco_llm_problem())

    def test_cisco_llm_env_uses_the_bridge_for_cli_profiles(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = FakeBridge(Path(tmp.name))
        with patch.object(scan_mcp, "CISCO_PROFILE", ("chatgpt", PROFILE)), \
             patch.object(scan_mcp, "skillspector_python", return_value=sys.executable), \
             patch.object(scan_mcp, "BRIDGE_SCRIPT", fake.script):
            with scan_mcp.cisco_llm_env() as env:
                self.assertEqual(env["MCP_SCANNER_LLM_BASE_URL"], "http://127.0.0.1:4242/v1")


if __name__ == "__main__":
    unittest.main()
