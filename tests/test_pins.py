"""The scanner pin has one source; the setup scripts must install exactly it."""
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
import _pins


class PinTests(unittest.TestCase):
    def test_setup_scripts_install_the_pinned_commit(self):
        for script in ("setup.sh", "setup.ps1"):
            with self.subTest(script=script):
                text = (ROOT / script).read_text(encoding="utf-8")
                self.assertIn(f'"{_pins.SKILLSPECTOR_REPO}"', text)
                self.assertIn(f'"{_pins.SKILLSPECTOR_SHA}"', text)
                self.assertIn(f"# v{_pins.SKILLSPECTOR_VERSION}", text)


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to verify the fork pin on GitHub")
class ForkPinTests(unittest.TestCase):
    """A fork pin is trusted only as 'upstream release + upstream merged fix'."""

    def api(self, path: str):
        import urllib.request
        req = urllib.request.Request(f"https://api.github.com/{path}",
                                     headers={"Accept": "application/vnd.github+json",
                                              "User-Agent": "agent-guard-tests"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def test_fork_pin_is_the_release_plus_the_upstream_fix_only(self):
        if "github.com/NVIDIA/" in _pins.SKILLSPECTOR_REPO:
            self.skipTest("pin points to NVIDIA")
        fork = _pins.SKILLSPECTOR_REPO.removeprefix("https://github.com/")
        diff = self.api(f"repos/{fork}/compare/{_pins.FORK_BASE_SHA}...{_pins.SKILLSPECTOR_SHA}")
        self.assertEqual(diff["merge_base_commit"]["sha"], _pins.FORK_BASE_SHA)
        changed = {f["filename"]: f["sha"] for f in diff["files"]}
        self.assertEqual(sorted(changed), sorted(_pins.FORK_FILES))
        for name, blob in changed.items():
            with self.subTest(name):
                upstream = self.api(f"repos/NVIDIA/SkillSpector/contents/{name}"
                                    f"?ref={_pins.FORK_UPSTREAM_MERGE}")
                self.assertEqual(blob, upstream["sha"])


if __name__ == "__main__":
    unittest.main()
