"""The dynamic analysis image really upgrades gVisor runsc and parses real strace.

Builds the real local overlay image on top of the digest-pinned OpenSSF analysis
image, checks `runsc --version`, and runs real npm and PyPI packages through
Docker without any mocks or fakes. Gated by AGENT_GUARD_INTEGRATION=1
(scripts/run_all_tests.py opens the gate).
"""
from datetime import datetime, timedelta, timezone
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import uuid
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")

dyn = importlib.import_module("_dynamic")
_pins = importlib.import_module("_pins")
_url_resolver = importlib.import_module("_url_resolver")


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to build and test the dynamic analysis image (Docker)")
class DynamicImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("docker") is None:
            raise AssertionError("AGENT_GUARD_INTEGRATION=1 needs Docker on PATH")
        cls.tag = dyn.build_analysis_image()

    def _run_real_package(self, ecosystem: str, name: str, version: str):
        container = "agent-guard-dynamic-test-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="agent-guard-dyn-test-") as tmp:
            out = Path(tmp)
            for sub in ("results", "static", "writes", "analyzed", "strace"):
                (out / sub).mkdir()
            argv = dyn.docker_argv(ecosystem, name, version, out, container, image=self.tag)
            try:
                proc = subprocess.run(argv, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=600)
            except subprocess.TimeoutExpired:
                dyn._remove(container)
                raise
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
            self.assertEqual(proc.returncode, 0, combined[-1500:])
            parse_warns = [ln for ln in combined.splitlines() if "Failed to parse" in ln]
            self.assertEqual(parse_warns, [], f"strace parse warnings: {parse_warns[:5]}")
            files = sorted((out / "results").glob("*.json"))
            self.assertTrue(files, "dynamic analysis wrote no result JSON")
            result = json.loads(files[0].read_text(encoding="utf-8"))
        return result

    def test_runsc_is_the_pinned_release(self):
        proc = subprocess.run(["docker", "run", "--rm", self.tag, "runsc", "--version"],
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"runsc version release-{_pins.DYNAMIC_GVISOR_VERSION}", proc.stdout)
        self.assertNotIn("20260216", proc.stdout)

    def test_npm_clean_package_is_safe_and_parses_strace(self):
        result = self._run_real_package("npm", "is-number", "7.0.0")
        analysis = result.get("Analysis") or {}
        install = analysis.get("install") or {}
        self.assertEqual(install.get("Status"), "completed")
        self.assertEqual((analysis.get("import") or {}).get("Status"), "completed")
        self.assertTrue(install.get("Files"), "install recorded no file events")
        self.assertTrue(install.get("DNS"), "install recorded no DNS events")
        self.assertTrue(install.get("Sockets"), "install recorded no socket events")
        self.assertTrue(install.get("Commands"), "install recorded no command events")
        hosts = {q.get("Hostname", "").rstrip(".").lower()
                 for b in install.get("DNS") or [] for q in b.get("Queries") or []}
        self.assertIn("registry.npmjs.org", hosts)
        report = dyn.analyse(result, "npm", expect_name="is-number")
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(dyn.verdict(report), 0)

    def test_pypi_clean_package_is_safe_and_parses_strace(self):
        result = self._run_real_package("pypi", "six", "1.17.0")
        analysis = result.get("Analysis") or {}
        install = analysis.get("install") or {}
        self.assertEqual(install.get("Status"), "completed")
        self.assertEqual((analysis.get("import") or {}).get("Status"), "completed")
        self.assertTrue(install.get("Files"), "install recorded no file events")
        self.assertTrue(install.get("DNS"), "install recorded no DNS events")
        self.assertTrue(install.get("Sockets"), "install recorded no socket events")
        self.assertTrue(install.get("Commands"), "install recorded no command events")
        hosts = {q.get("Hostname", "").rstrip(".").lower()
                 for b in install.get("DNS") or [] for q in b.get("Queries") or []}
        self.assertTrue(hosts & {"pypi.org", "files.pythonhosted.org"}, hosts)
        report = dyn.analyse(result, "pypi", expect_name="six")
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(dyn.verdict(report), 0)

    def test_gvisor_pin_is_a_real_release_at_least_seven_days_old(self):
        tag = f"release-{_pins.DYNAMIC_GVISOR_VERSION}"
        req = _url_resolver.attach_github_auth(urllib.request.Request(
            f"https://api.github.com/repos/google/gvisor/releases/tags/{tag}",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "agent-guard-tests"},
        ))
        with urllib.request.urlopen(req, timeout=30) as r:
            rel = json.load(r)
        self.assertEqual(rel["tag_name"], tag)
        self.assertFalse(rel.get("draft"))
        self.assertFalse(rel.get("prerelease"))
        published = datetime.strptime(rel["published_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
        self.assertLessEqual(published, datetime.now(timezone.utc) - timedelta(days=7))


if __name__ == "__main__":
    unittest.main()
