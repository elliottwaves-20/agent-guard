"""The MCP sandbox image really carries the pinned runtimes and refuses packages
that need another runtime.

Builds the real image and asks each runtime for its version; the runtime check
runs inside that image. Needs Docker and network (registry metadata), so it is
gated like the other integration tests (scripts/run_all_tests.py opens the gate).
"""
import importlib
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")

sm = importlib.import_module("scan_mcp")

SEQ = "@modelcontextprotocol/server-sequential-thinking"


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to build and test the sandbox image (Docker)")
class SandboxImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("docker") is None:
            raise AssertionError("AGENT_GUARD_INTEGRATION=1 needs Docker on PATH")
        cls.tag = sm.build_sandbox_image()

    def run_in_image(self, *cmd, ok=True):
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                            *sm.SANDBOX_ENV, self.tag, *cmd],
                           capture_output=True, text=True, timeout=120)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr)
        return r.returncode, (r.stdout + r.stderr).strip()

    # -- pinned runtimes ---------------------------------------------------------

    def test_node_is_the_pinned_version(self):
        self.assertEqual(self.run_in_image("node", "--version")[1], "v" + sm.SANDBOX_NODE)

    def test_npx_runs_on_the_pinned_node(self):
        out = self.run_in_image("npx", "--offline", "-c", "node --version")[1]
        self.assertEqual(out.splitlines()[-1], "v" + sm.SANDBOX_NODE)

    def test_python_is_the_pinned_version(self):
        self.assertEqual(self.run_in_image("python", "--version")[1], "Python " + sm.SANDBOX_PYTHON)

    def test_uv_is_the_pinned_version(self):
        self.assertTrue(self.run_in_image("uv", "--version")[1].startswith("uv " + sm.SANDBOX_UV + " "))
        self.assertTrue(self.run_in_image("uvx", "--version")[1].startswith("uvx " + sm.SANDBOX_UV + " "))

    def test_uv_uses_the_image_python(self):
        out = self.run_in_image("uv", "run", "--no-project", "--python-preference", "only-system",
                                "python", "-c", "import platform; print(platform.python_version())")[1]
        self.assertEqual(out.splitlines()[-1], sm.SANDBOX_PYTHON)

    # -- runtime check inside the image -------------------------------------------

    def test_image_runtime_satisfies_ranges(self):
        self.assertIs(sm.image_satisfies(self.tag, "node", ">=24"), True)
        self.assertIs(sm.image_satisfies(self.tag, "node", ">=99"), False)
        self.assertIs(sm.image_satisfies(self.tag, "python", ">=3.10"), True)
        self.assertIs(sm.image_satisfies(self.tag, "python", ">=3.8,<3.12"), False)

    def test_unreadable_range_is_no_answer(self):
        self.assertIsNone(sm.image_satisfies(self.tag, "python", "not a specifier"))

    def test_npm_refuses_a_package_whose_engines_exclude_the_image_node(self):
        # Backstop for what the pre-check cannot see (a dependency deep in the tree):
        # with the sandbox environment npm stops instead of only warning.
        script = ("mkdir -p /tmp/p && cd /tmp/p && printf '%s' "
                  "'{\"name\":\"p\",\"version\":\"1.0.0\",\"engines\":{\"node\":\">=99\"},"
                  "\"bin\":{\"p\":\"x.js\"}}' > package.json "
                  "&& printf '#!/usr/bin/env node\\nconsole.log(\"PACKAGE RAN\")\\n' > x.js "
                  "&& npx --offline --yes /tmp/p")
        code, out = self.run_in_image("sh", "-c", script, ok=False)
        self.assertNotIn("PACKAGE RAN", out)
        self.assertNotEqual(code, 0, out)
        self.assertIn("EBADENGINE", out)

    def test_pre_check_passes_a_package_the_image_can_run(self):
        self.assertIsNone(sm.launch_runtime_problem(["npx", "-y", SEQ + "@2.1.1"], self.tag))

    def test_pre_check_refuses_npm_engines_the_image_lacks(self):
        doc = {"dist-tags": {"latest": "1.0.0"},
               "versions": {"1.0.0": {"engines": {"node": ">=99"}}}}
        with patch.object(sm, "http_json", return_value=doc):
            problem = sm.launch_runtime_problem(["npx", "-y", "pkg@1.0.0"], self.tag)
        self.assertIn(">=99", problem)
        self.assertIn(sm.SANDBOX_NODE, problem)

    def test_pre_check_refuses_requires_python_the_image_lacks(self):
        meta = {"info": {"version": "1.0", "requires_python": ">=3.8,<3.12"}}
        with patch.object(sm, "http_json", return_value=meta):
            problem = sm.launch_runtime_problem(["uvx", "pkg==1.0"], self.tag)
        self.assertIn("<3.12", problem)
        self.assertIn(sm.SANDBOX_PYTHON, problem)

    def test_pre_check_fails_closed_when_the_registry_is_unreachable(self):
        with patch.object(sm, "http_json", side_effect=OSError("offline")):
            problem = sm.launch_runtime_problem(["npx", "-y", "pkg@1.0.0"], self.tag)
        self.assertIn("offline", problem)

    def test_registry_metadata_has_the_fields_the_pre_check_reads(self):
        # Contract for the http_json stand-ins above: the real registries answer
        # with these shapes.
        doc = sm.http_json("https://registry.npmjs.org/" + SEQ.replace("/", "%2F"))
        self.assertEqual(doc["versions"]["2.1.1"]["engines"]["node"], ">=24")
        meta = sm.http_json("https://pypi.org/pypi/mcp-server-fetch/json")
        self.assertIn("requires_python", meta["info"])


if __name__ == "__main__":
    unittest.main()
