"""The MCP sandbox image really carries the pinned runtimes.

Builds the real image (needs Docker) and asks each runtime for its version.
A distro package or an unpinned base would report a different version here.
"""
import importlib
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")

sm = importlib.import_module("scan_mcp")


@unittest.skipUnless(shutil.which("docker"), "Docker not on PATH")
class SandboxRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tag = sm.build_sandbox_image()

    def run_in_image(self, *cmd):
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                            "-e", "HOME=/tmp", self.tag, *cmd],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return (r.stdout + r.stderr).strip()

    def test_node_is_the_pinned_version(self):
        self.assertEqual(self.run_in_image("node", "--version"), "v" + sm.SANDBOX_NODE)

    def test_npx_runs_on_the_pinned_node(self):
        out = self.run_in_image("npx", "--offline", "-c", "node --version")
        self.assertEqual(out.splitlines()[-1], "v" + sm.SANDBOX_NODE)

    def test_python_is_the_pinned_version(self):
        self.assertEqual(self.run_in_image("python", "--version"), "Python " + sm.SANDBOX_PYTHON)

    def test_uv_is_the_pinned_version(self):
        self.assertTrue(self.run_in_image("uv", "--version").startswith("uv " + sm.SANDBOX_UV + " "))
        self.assertTrue(self.run_in_image("uvx", "--version").startswith("uvx " + sm.SANDBOX_UV + " "))

    def test_uv_uses_the_image_python(self):
        out = self.run_in_image("uv", "run", "--no-project", "--python-preference", "only-system",
                                "python", "-c", "import platform; print(platform.python_version())")
        self.assertEqual(out.splitlines()[-1], sm.SANDBOX_PYTHON)


if __name__ == "__main__":
    unittest.main()
