"""The scanner pin has one source; the setup scripts must install exactly it."""
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


if __name__ == "__main__":
    unittest.main()
