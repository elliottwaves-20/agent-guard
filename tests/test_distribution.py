"""Local skill distribution: `[distribution]` in the user config.

With `mode = "sync"` the installer publishes a SAFE skill into one inbox
directory and hands everything else (store, links, profiles) to the user's own
sync command. The tests use a fake sync command, never a real one, and never
read this machine's personal config.
"""
import importlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

dist = importlib.import_module("_distribution")
uc = importlib.import_module("_user_config")
installer = importlib.import_module("install_skill")

# Fake sync: moves <inbox>/<name> into <store>, leaves a pointer behind and
# reports the profile the way a real sync might. argv: inbox store name [exit].
FAKE_SYNC = r"""
import shutil, sys
from pathlib import Path
inbox, store, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
code = int(sys.argv[4]) if len(sys.argv) > 4 else 0
if code == 0:
    shutil.move(str(inbox / name), str(store / name))
    shutil.copytree(store / name, inbox / name)
    print("Status: ok")
    print(f"Neu im Lager: {name} -> Profil 'tools'")
else:
    print("sync broke", file=sys.stderr)
sys.exit(code)
"""


def section(**values):
    return {"distribution": values}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inbox = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_without_section_the_default_installer_stays_active(self):
        self.assertIsNone(dist.from_config({}))
        self.assertIsNone(dist.from_config({"llm": {}}))

    def test_valid_section(self):
        d = dist.from_config(section(mode="sync", inbox=str(self.inbox),
                                     sync=["pwsh", "-File", "x.ps1"], sync_timeout=30))
        self.assertEqual(d.inbox, self.inbox.resolve())
        self.assertEqual(d.sync, ("pwsh", "-File", "x.ps1"))
        self.assertEqual(d.timeout, 30)

    def test_sync_command_is_optional(self):
        d = dist.from_config(section(mode="sync", inbox=str(self.inbox)))
        self.assertIsNone(d.sync)
        self.assertEqual(d.timeout, dist.DEFAULT_SYNC_TIMEOUT)

    def test_inbox_may_start_with_home(self):
        home = str(self.inbox.parent)
        with patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
            d = dist.from_config(section(mode="sync", inbox=f"~/{self.inbox.name}"))
        self.assertEqual(d.inbox, self.inbox.resolve())

    def test_invalid_sections_are_refused(self):
        inbox = str(self.inbox)
        bad = [
            {"mode": "sync"},                                        # no inbox
            {"inbox": inbox},                                        # no mode
            {"mode": "store", "inbox": inbox},                       # unknown mode
            {"mode": "sync", "inbox": "relative/dir"},
            {"mode": "sync", "inbox": str(self.inbox / "missing")},
            {"mode": "sync", "inbox": inbox, "sync": "pwsh x.ps1"},  # must be argv
            {"mode": "sync", "inbox": inbox, "sync": []},
            {"mode": "sync", "inbox": inbox, "sync": ["pwsh", 3]},
            {"mode": "sync", "inbox": inbox, "sync": ["", "x"]},
            {"mode": "sync", "inbox": inbox, "sync_timeout": 0},
            {"mode": "sync", "inbox": inbox, "sync_timeout": "60"},
            {"mode": "sync", "inbox": inbox, "sync_timeout": True},
            {"mode": "sync", "inbox": inbox, "profile": "core"},     # unknown key
        ]
        for values in bad:
            with self.subTest(values=values), self.assertRaises(uc.ConfigError):
                dist.from_config(section(**values))
        with self.assertRaises(uc.ConfigError):
            dist.from_config({"distribution": ["sync"]})

    def test_shipped_example_section_validates(self):
        example = ROOT / "config.example.toml"
        cfg = uc.load_config(env={"AGENT_GUARD_CONFIG": str(example)})
        values = dict(cfg["distribution"])
        values["inbox"] = str(self.inbox)  # the example path need not exist here
        d = dist.from_config({"distribution": values})
        self.assertEqual(d.inbox, self.inbox.resolve())
        self.assertIsNotNone(d.sync)


class InstallTests(unittest.TestCase):
    """install_skill() with a distribution: inbox + sync, no target agents."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.inbox, self.store, self.source = base / "inbox", base / "store", base / "src" / "demo"
        for p in (self.inbox, self.store, self.source):
            p.mkdir(parents=True)
        (self.source / "SKILL.md").write_text("---\nname: demo\ndescription: d\n---\nhi\n",
                                              encoding="utf-8")
        (self.source / "notes.txt").write_text("data", encoding="utf-8")
        script = base / "fake_sync.py"
        script.write_text(FAKE_SYNC, encoding="utf-8")
        self.sync = [sys.executable, str(script), str(self.inbox), str(self.store), "demo"]
        self.guards = [
            patch.object(installer, "run_skillspector", return_value=0),
            patch.object(installer._skills_cli, "distribute",
                         side_effect=AssertionError("skills CLI must not run")),
            patch.object(installer, "make_link",
                         side_effect=AssertionError("built-in linker must not run")),
        ]
        for g in self.guards:
            g.start()

    def tearDown(self):
        for g in self.guards:
            g.stop()
        self.tmp.cleanup()

    def install(self, sync=None, *, dry=False, timeout=60, selected=None):
        d = dist.Distribution(inbox=self.inbox.resolve(),
                              sync=tuple(sync) if sync else None, timeout=timeout)
        out = io.StringIO()
        with redirect_stdout(out):
            installer.install_skill(self.source, "demo", Path("unused"), dry,
                                    selected=selected, distribution=d)
        return out.getvalue()

    def test_safe_skill_goes_to_inbox_and_sync_reports_profile(self):
        out = self.install(self.sync)
        self.assertTrue((self.store / "demo" / "SKILL.md").is_file())
        self.assertIn("Neu im Lager: demo -> Profil 'tools'", out)
        self.assertNotIn("Status: ok", out)  # only lines about this skill
        self.assertIn("[OK] Skill 'demo' installed", out)
        self.assertEqual(list(self.inbox.glob(".guard-stage-*")), [])

    def test_without_sync_command_the_skill_stays_in_the_inbox(self):
        out = self.install(None)
        self.assertTrue((self.inbox / "demo" / "SKILL.md").is_file())
        self.assertIn("no sync command configured", out)

    def test_failed_sync_keeps_the_inbox_copy_and_warns(self):
        out = self.install(self.sync + ["3"])
        self.assertTrue((self.inbox / "demo" / "SKILL.md").is_file())
        self.assertIn("sync command failed (exit 3)", out)
        self.assertIn("sync broke", out)

    def test_sync_timeout_is_a_warning(self):
        with patch.object(dist, "run_bounded",
                          side_effect=subprocess.TimeoutExpired(self.sync, 5)):
            out = self.install(self.sync, timeout=5)
        self.assertTrue((self.inbox / "demo" / "SKILL.md").is_file())
        self.assertIn("timed out after 5s", out)

    def test_missing_sync_program_is_a_warning(self):
        out = self.install([str(Path(self.tmp.name) / "no-such-program.exe")])
        self.assertTrue((self.inbox / "demo" / "SKILL.md").is_file())
        self.assertIn("sync command could not start", out)

    def test_sync_that_alters_the_skill_is_an_error(self):
        tamper = [sys.executable, "-c",
                  f"open(r'{self.inbox / 'demo' / 'notes.txt'}', 'w').write('evil')"]
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(io.StringIO()):
            self.install(tamper)
        self.assertIn("changed the scanned skill", str(ctx.exception))

    def test_blocked_skill_never_reaches_the_inbox_or_the_sync(self):
        with patch.object(installer, "run_skillspector", return_value=1), \
             patch.object(dist, "run_bounded",
                          side_effect=AssertionError("sync must not run")), \
             self.assertRaises(SystemExit):
            self.install(self.sync)
        self.assertEqual([p.name for p in self.inbox.iterdir()], [])

    def test_dry_run_writes_nothing_and_does_not_sync(self):
        with patch.object(dist, "run_bounded",
                          side_effect=AssertionError("sync must not run")):
            out = self.install(self.sync, dry=True)
        self.assertEqual([p.name for p in self.inbox.iterdir()], [])
        self.assertIn("[DRY]", out)

    def test_tool_selection_conflicts_with_the_distribution(self):
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(io.StringIO()):
            self.install(self.sync, selected=["claude-code"])
        self.assertIn("--tools", str(ctx.exception))
        self.assertEqual([p.name for p in self.inbox.iterdir()], [])

    def test_sync_runs_without_credentials_in_its_environment(self):
        seen = {}

        def fake(cmd, *, env=None, timeout, cwd=None):
            seen.update(env or {})
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "x", "ANTHROPIC_API_KEY": "y"}), \
             patch.object(dist, "run_bounded", side_effect=fake):
            self.install(self.sync)
        self.assertTrue(seen)
        self.assertNotIn("OPENAI_API_KEY", seen)
        self.assertNotIn("ANTHROPIC_API_KEY", seen)


class MainSelectionTests(unittest.TestCase):
    def test_main_passes_the_configured_distribution(self):
        marker = dist.Distribution(inbox=Path("x"), sync=None, timeout=1)
        with patch.object(installer, "configured_distribution", return_value=marker), \
             patch.object(installer, "install_skill") as inst, \
             patch.object(sys, "argv", ["install_skill.py", "skill", "somewhere/demo"]):
            installer.main()
        self.assertIs(inst.call_args.kwargs["distribution"], marker)

    def test_workspace_option_conflicts_with_the_distribution(self):
        marker = dist.Distribution(inbox=Path("x"), sync=None, timeout=1)
        with patch.object(installer, "configured_distribution", return_value=marker), \
             patch.object(installer, "install_skill") as inst, \
             patch.object(sys, "argv", ["install_skill.py", "--workspace", "w",
                                        "skill", "somewhere/demo"]), \
             self.assertRaises(SystemExit) as ctx:
            installer.main()
        inst.assert_not_called()
        self.assertIn("--workspace", str(ctx.exception))

    def test_invalid_distribution_config_fails_closed(self):
        with patch.object(installer._skillspector, "USER_CONFIG",
                          {"distribution": {"mode": "bogus"}}), \
             self.assertRaises(SystemExit) as ctx:
            installer.configured_distribution()
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
