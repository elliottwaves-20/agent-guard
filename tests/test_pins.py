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

    # Variable names per setup script: spec of each scanner, litellm
    # requirement, dependency window.
    SETUP_VARS = {
        "setup.sh": {"ss_spec": "SS_SPEC", "cisco_spec": "CISCO_SPEC",
                     "cisco_repo": "CISCO_REPO", "cisco_sha": "CISCO_SHA",
                     "litellm": "CISCO_LITELLM", "window": "EXCLUDE_NEWER"},
        "setup.ps1": {"ss_spec": "ssSpec", "cisco_spec": "ciscoSpec",
                      "cisco_repo": "CiscoRepo", "cisco_sha": "CiscoSha",
                      "litellm": "CiscoLitellm", "window": "ExcludeNewer"},
    }

    @staticmethod
    def ref(name):
        # $NAME or ${NAME}
        return r'\$\{?' + name + r'\}?'

    @classmethod
    def var(cls, name):
        # a variable reference, optionally inside double quotes
        return '"?' + cls.ref(name) + '"?'

    @staticmethod
    def assignment(name, value):
        return r'(?m)^\$?' + name + r'\s*=\s*"' + value + '"'

    def install_lines(self, text):
        # Join continuation lines so a wrapped command is checked as a whole.
        import re
        text = re.sub(r"[`\\]\r?\n\s*", " ", text)
        return [" ".join(line.split()) for line in text.splitlines()
                if "uv tool install" in " ".join(line.split())
                and not line.lstrip().startswith(("#", "echo", "Write-Host"))]

    def test_setup_scripts_install_the_pinned_cisco_commit(self):
        import re
        for script, v in self.SETUP_VARS.items():
            with self.subTest(script=script):
                text = (ROOT / script).read_text(encoding="utf-8")
                self.assertRegex(text, self.assignment(v["cisco_repo"],
                                                       re.escape(_pins.CISCO_MCP_SCANNER_REPO)))
                self.assertRegex(text, self.assignment(v["cisco_sha"],
                                                       _pins.CISCO_MCP_SCANNER_SHA))
                self.assertRegex(text, self.assignment(v["litellm"],
                                                       re.escape(_pins.CISCO_LITELLM_REQUIREMENT)))
                self.assertIn(f"package version {_pins.CISCO_MCP_SCANNER_VERSION}", text)
                spec = self.assignment(v["cisco_spec"],
                                       "git[+]" + self.ref(v["cisco_repo"])
                                       + "@" + self.ref(v["cisco_sha"]))
                self.assertRegex(text, spec)
                cisco = [l for l in self.install_lines(text)
                         if re.search(self.var(v["cisco_spec"]), l)]
                self.assertEqual(len(cisco), 1, cisco)
                self.assertRegex(cisco[0], r"--with " + self.var(v["litellm"]))

    def test_setup_scripts_install_skillspector_from_its_spec(self):
        import re
        for script, v in self.SETUP_VARS.items():
            with self.subTest(script=script):
                text = (ROOT / script).read_text(encoding="utf-8")
                ss = [l for l in self.install_lines(text)
                      if re.search(self.var(v["ss_spec"]), l)]
                self.assertEqual(len(ss), 1, ss)

    def test_litellm_floor_excludes_known_vulnerable_releases(self):
        # 1.106.5 is the first release past the published advisories;
        # 1.107.0 was the compromised upload of 2026-10-21.
        parts = [p.strip() for p in _pins.CISCO_LITELLM_REQUIREMENT.split(",")]
        self.assertEqual(parts[0], "litellm>=1.106.5")
        self.assertIn("!=1.107.0", parts)

    def test_dependency_window_is_at_least_seven_days_old(self):
        from datetime import datetime, timedelta, timezone
        self.assertRegex(_pins.UV_EXCLUDE_NEWER, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        cutoff = datetime.fromisoformat(_pins.UV_EXCLUDE_NEWER.replace("Z", "+00:00"))
        self.assertLessEqual(cutoff, datetime.now(timezone.utc) - timedelta(days=7))

    def test_every_tool_install_is_forced_with_the_shared_window(self):
        # --force always: a re-run re-pins an existing (possibly unpinned)
        # install instead of depending on an "already installed" check.
        import re
        for script, v in self.SETUP_VARS.items():
            with self.subTest(script=script):
                text = (ROOT / script).read_text(encoding="utf-8")
                self.assertRegex(text, self.assignment(v["window"], _pins.UV_EXCLUDE_NEWER))
                self.assertNotIn("uv tool upgrade", text)
                installs = self.install_lines(text)
                self.assertEqual(len(installs), 2, installs)  # one per scanner
                for line in installs:
                    self.assertIn("uv tool install --force ", line)
                    self.assertRegex(line, r"--exclude-newer " + self.var(v["window"]))

    def test_setup_ps1_stops_when_an_install_fails(self):
        # $ErrorActionPreference = "Stop" ignores native exit codes.
        text = (ROOT / "setup.ps1").read_text(encoding="utf-8")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if self.install_lines(line):
                with self.subTest(line=line.strip()):
                    self.assertIn("$LASTEXITCODE -ne 0", lines[i + 1])
                    self.assertIn("exit 1", lines[i + 1])

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

    def test_upstream_pin_api_uses_unredirected_github_auth_header(self):
        import urllib.request
        from unittest.mock import patch

        seen = []

        class _Resp:
            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_open(req, timeout=30):
            seen.append(req)
            return _Resp()

        with patch.dict(os.environ, {"GITHUB_TOKEN": " tok-pins\n", "GH_TOKEN": ""}, clear=False):
            with patch.object(urllib.request, "urlopen", side_effect=fake_open):
                UpstreamPinTests().api("repos/o/r/compare/a...b")

        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok-pins")
        self.assertNotIn("Authorization", seen[0].headers)
        self.assertIn("Authorization", seen[0].unredirected_hdrs)


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to verify the pin on GitHub")
class UpstreamPinTests(unittest.TestCase):
    """The pin is a commit that NVIDIA/SkillSpector main already contains."""

    def api(self, path: str):
        import urllib.request
        import _url_resolver
        req = _url_resolver.attach_github_auth(
            urllib.request.Request(f"https://api.github.com/{path}",
                                   headers={"Accept": "application/vnd.github+json",
                                            "User-Agent": "agent-guard-tests"})
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def test_pin_is_on_nvidia_main(self):
        self.assertEqual(_pins.SKILLSPECTOR_REPO, "https://github.com/NVIDIA/SkillSpector")
        diff = self.api(f"repos/NVIDIA/SkillSpector/compare/{_pins.SKILLSPECTOR_SHA}...main")
        self.assertIn(diff["status"], ("ahead", "identical"))

    def test_pin_is_the_commit_of_its_release_tag(self):
        # The pin is an NVIDIA release. A main commit is only for a fix no
        # release carries yet; that exception then has to change this test.
        ref = self.api(f"repos/NVIDIA/SkillSpector/git/ref/tags/v{_pins.SKILLSPECTOR_VERSION}")
        target = ref["object"]
        if target["type"] == "tag":  # annotated tag: follow it to its commit
            target = self.api(f"repos/NVIDIA/SkillSpector/git/tags/{target['sha']}")["object"]
        self.assertEqual(target["type"], "commit")
        self.assertEqual(target["sha"], _pins.SKILLSPECTOR_SHA)

    def test_cisco_pin_is_on_official_main(self):
        self.assertEqual(_pins.CISCO_MCP_SCANNER_REPO,
                         "https://github.com/cisco-ai-defense/mcp-scanner")
        diff = self.api("repos/cisco-ai-defense/mcp-scanner/compare/"
                        f"{_pins.CISCO_MCP_SCANNER_SHA}...main")
        self.assertIn(diff["status"], ("ahead", "identical"))


if __name__ == "__main__":
    unittest.main()
