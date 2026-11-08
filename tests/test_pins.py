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

    def test_scanner_images_are_pinned_by_digest(self):
        # tag@digest: Docker runs the digest; the tag only keeps it readable.
        import re
        pattern = re.compile(r"^[a-z0-9.\-/]+:[\w.\-]+@sha256:[0-9a-f]{64}$")
        for image in (_pins.GUARDDOG_IMAGE, _pins.MALCONTENT_IMAGE):
            with self.subTest(image=image):
                self.assertRegex(image, pattern)

    def test_guarddog_image_tag_is_the_pinned_version(self):
        tag = _pins.GUARDDOG_IMAGE.split("@", 1)[0].rsplit(":", 1)[1]
        self.assertEqual(tag, _pins.GUARDDOG_VERSION)


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to verify the pin on GitHub")
class UpstreamPinTests(unittest.TestCase):
    """The pin is a commit that NVIDIA/SkillSpector main already contains."""

    def api(self, path: str):
        import urllib.request
        req = urllib.request.Request(f"https://api.github.com/{path}",
                                     headers={"Accept": "application/vnd.github+json",
                                              "User-Agent": "agent-guard-tests"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def test_pin_is_on_nvidia_main(self):
        self.assertEqual(_pins.SKILLSPECTOR_REPO, "https://github.com/NVIDIA/SkillSpector")
        diff = self.api(f"repos/NVIDIA/SkillSpector/compare/{_pins.SKILLSPECTOR_SHA}...main")
        self.assertIn(diff["status"], ("ahead", "identical"))


if __name__ == "__main__":
    unittest.main()
