"""Shared core of the locked MCP installs (#48): settings, names, tree swap.

Every refusal carries the wrapper exit code (1 finding, 2 no verdict), and a
failed swap must leave the previous tree exactly where it was.
"""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
locked = importlib.import_module("_mcp_locked")


class Settings(unittest.TestCase):
    def test_default_location_per_platform(self):
        self.assertEqual(locked.settings({}, {"LOCALAPPDATA": "C:/L"}, "win32").install_dir,
                         Path("C:/L") / "agent-guard" / "mcp")
        self.assertEqual(locked.settings({}, {"XDG_DATA_HOME": "/d"}, "linux").install_dir,
                         Path("/d") / "agent-guard" / "mcp")
        self.assertEqual(locked.settings({}, {"HOME": "/h"}, "darwin").install_dir,
                         Path("/h") / ".local" / "share" / "agent-guard" / "mcp")

    def test_without_register_nothing_is_handed_over(self):
        result = locked.settings({}, {"LOCALAPPDATA": "C:/L"}, "win32")
        self.assertIsNone(result.register)
        self.assertEqual(result.register_timeout, 300)

    def test_configured_location_and_register_win(self):
        config = {"mcp": {"install_dir": str(Path(tempfile.gettempdir()) / "servers"),
                          "register": ["pwsh", "-File", "reg.ps1"], "register_timeout": 60}}
        result = locked.settings(config, {"LOCALAPPDATA": "C:/L"}, "win32")
        self.assertEqual(result.install_dir, Path(tempfile.gettempdir()) / "servers")
        self.assertEqual(result.register, ("pwsh", "-File", "reg.ps1"))
        self.assertEqual(result.register_timeout, 60)

    def test_unknown_mcp_setting_is_refused(self):
        with self.assertRaises(locked.Refused) as ctx:
            locked.settings({"mcp": {"install_dri": "x"}}, {}, "win32")
        self.assertEqual(ctx.exception.code, 2)

    def test_relative_install_dir_is_refused(self):
        with self.assertRaises(locked.Refused):
            locked.settings({"mcp": {"install_dir": "servers"}}, {}, "win32")

    def test_onedrive_location_is_refused(self):
        base = Path(tempfile.gettempdir()) / "od"
        for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
            with self.subTest(var=var):
                with self.assertRaises(locked.Refused) as ctx:
                    locked.settings({"mcp": {"install_dir": str(base / "mcp")}},
                                    {var: str(base)}, "win32")
                self.assertEqual(ctx.exception.code, 2)
        with self.assertRaises(locked.Refused):
            locked.settings({}, {"LOCALAPPDATA": str(base / "L"), "OneDrive": str(base)}, "win32")

    def test_register_must_be_a_list_of_strings(self):
        for bad in ("pwsh reg.ps1", [], [""], ["pwsh", 3], {"a": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(locked.Refused):
                    locked.settings({"mcp": {"register": bad}}, {"LOCALAPPDATA": "C:/L"}, "win32")

    def test_register_timeout_must_be_positive(self):
        for bad in (0, -1, True, "60"):
            with self.subTest(bad=bad):
                with self.assertRaises(locked.Refused):
                    locked.settings({"mcp": {"register_timeout": bad}},
                                    {"LOCALAPPDATA": "C:/L"}, "win32")


class Names(unittest.TestCase):
    def test_default_names(self):
        self.assertEqual(locked.default_name("npm", "@scope/server-files"), "server-files")
        self.assertEqual(locked.default_name("npm", "plain"), "plain")
        self.assertEqual(locked.default_name("pypi", "Mcp_Server.Time"), "mcp-server-time")
        self.assertEqual(locked.default_name("git", "My_Pkg"), "my-pkg")

    def test_invalid_names(self):
        for bad in ("", "-x", ".x", "a/b", "a b", "x" * 65, "x&y", 'x"y', "a\\b"):
            with self.subTest(bad=bad):
                with self.assertRaises(locked.Refused) as ctx:
                    locked.check_name(bad)
                self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(locked.check_name("a" * 64), "a" * 64)

    def test_adhoc_launchers_are_recognised(self):
        adhoc = [("npx", ["-y", "x"]), ("NPX.CMD", []), ("C:/x/uvx.exe", ["x"]),
                 ("bunx", []), ("pnpx", []), ("uv", ["tool", "run", "x"]),
                 ("uv.exe", ["run", "--with", "x", "y"]), ("uv", ["run", "--with=x", "y"]),
                 ("pnpm", ["dlx", "x"]), ("yarn", ["dlx", "x"]), ("pipx", ["run", "x"]),
                 ("npm", ["exec", "x"]), ("npm.cmd", ["x", "y"]), ("bun", ["x", "y"])]
        for command, args in adhoc:
            with self.subTest(command=command, args=args):
                self.assertTrue(locked.is_adhoc_launch(command, args))
        fixed = [("node", ["C:/srv/index.js"]), ("C:/Program Files/nodejs/node.exe", ["a.js"]),
                 ("uv", ["run", "--project", "d", "--locked", "--no-dev", "srv"]),
                 ("python", ["-m", "srv"]), ("npm", ["start"])]
        for command, args in fixed:
            with self.subTest(command=command, args=args):
                self.assertFalse(locked.is_adhoc_launch(command, args))

    def test_python_310_is_refused(self):
        with mock.patch.object(locked.sys, "version_info", (3, 10, 12)):
            with self.assertRaises(locked.Refused) as ctx:
                locked.require_python_311()
        self.assertEqual(ctx.exception.code, 2)
        locked.require_python_311()


class TreeSwap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "srv"

    def tearDown(self):
        self.tmp.cleanup()

    def old_tree(self):
        self.target.mkdir()
        (self.target / "marker.txt").write_text("old", encoding="utf-8")

    def new_stage(self):
        stage = locked.new_stage(self.root, "srv")
        (stage / "marker.txt").write_text("new", encoding="utf-8")
        return stage

    def marker(self):
        return (self.target / "marker.txt").read_text(encoding="utf-8")

    def test_stage_is_a_hidden_sibling(self):
        stage = locked.new_stage(self.root, "srv")
        self.assertTrue(stage.is_dir())
        self.assertTrue(stage.name.startswith(".srv.staging-"))
        self.assertEqual(stage.parent, self.root)

    def test_replace_tree_swaps_and_leaves_nothing(self):
        self.old_tree()
        locked.replace_tree(self.new_stage(), self.target)
        self.assertEqual(self.marker(), "new")
        self.assertEqual([p.name for p in self.root.iterdir()], ["srv"])

    def test_first_install_needs_no_old_tree(self):
        locked.replace_tree(self.new_stage(), self.target)
        self.assertEqual(self.marker(), "new")

    def test_finish_runs_in_the_target(self):
        seen = []
        locked.replace_tree(self.new_stage(), self.target, finish=seen.append)
        self.assertEqual(seen, [self.target])

    def test_failed_finish_restores_the_old_tree(self):
        self.old_tree()

        def finish(target):
            raise locked.Refused(2, "sync failed")
        with self.assertRaises(locked.Refused) as ctx:
            locked.replace_tree(self.new_stage(), self.target, finish=finish)
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(self.marker(), "old")
        self.assertEqual([p.name for p in self.root.iterdir()], ["srv"])

    def test_locked_old_tree_keeps_everything(self):
        self.old_tree()
        stage = self.new_stage()
        with mock.patch.object(locked.os, "replace", side_effect=PermissionError("in use")):
            with self.assertRaises(locked.Refused) as ctx:
                locked.replace_tree(stage, self.target)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("close", str(ctx.exception).lower())
        self.assertEqual(self.marker(), "old")

    def test_staged_removes_an_unused_stage(self):
        with self.assertRaises(locked.Refused):
            with locked.staged(self.root, "srv") as stage:
                (stage / "x").write_text("x", encoding="utf-8")
                raise locked.Refused(1, "finding")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_leftovers_are_reported_not_removed(self):
        (self.root / ".srv.staging-dead").mkdir()
        (self.root / ".srv.old-dead").mkdir()
        (self.root / ".other.old-dead").mkdir()
        found = sorted(p.name for p in locked.stale_leftovers(self.root, "srv"))
        self.assertEqual(found, [".srv.old-dead", ".srv.staging-dead"])
        locked.replace_tree(self.new_stage(), self.target)
        self.assertTrue((self.root / ".srv.staging-dead").is_dir())
        self.assertEqual(self.marker(), "new")


class Metadata(unittest.TestCase):
    def test_metadata_records_the_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            installed = locked.Installed(
                name="srv", kind="npm", package="@s/srv", requested="1.0.0",
                command="node", args=["x.js"], tree=Path(tmp), lockfile_sha256="ab" * 32,
                overrides={"dep": "2.0.0"}, override_reason="CVE fix", secrets=(), accepted=None)
            locked.write_metadata(Path(tmp), installed)
            meta = json.loads((Path(tmp) / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["kind"], "npm")
        self.assertEqual((meta["package"], meta["version"]), ("@s/srv", "1.0.0"))
        self.assertEqual(meta["overrides"], {"dep": "2.0.0"})
        self.assertEqual(meta["override_reason"], "CVE fix")
        self.assertEqual(meta["lockfile_sha256"], "ab" * 32)
        self.assertEqual(meta["agent_guard"], (ROOT / "VERSION").read_text(encoding="utf-8").strip())
        self.assertIn("at", meta)

    def test_metadata_has_tier_fast_lane_and_source(self):
        fast_lane = [{"kind": "npm", "package": "dep", "version": "2.0.0"}]
        source = "https://github.com/example/srv"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            values = {
                "name": "srv", "kind": "npm", "package": "srv", "requested": "1.0.0",
                "command": "node", "args": ["x.js"], "tree": root,
                "lockfile_sha256": "ab" * 32, "overrides": {}, "override_reason": None,
                "secrets": (), "accepted": None,
            }
            default = locked.Installed(**values)
            custom = locked.Installed(**(values | {"tier": "s1", "fast_lane": fast_lane,
                                                   "source": source}))
            for installed, expected in ((default, ("s2", [], "")),
                                        (custom, ("s1", fast_lane, source))):
                with self.subTest(expected=expected):
                    locked.write_metadata(root, installed)
                    meta = json.loads((root / locked.METADATA).read_text(encoding="utf-8"))
                    self.assertEqual((meta["tier"], meta["fast_lane"], meta["source"]), expected)


class NeedsScan(unittest.TestCase):
    def test_needs_scan_lists_commands(self):
        items = [
            {"kind": "npm", "package": "@scope/srv", "version": "1.2.3"},
            {"kind": "pypi", "package": "server", "version": "4.5.6"},
        ]
        error = locked.NeedsScan(items)
        self.assertIsInstance(error, locked.Refused)
        self.assertEqual(error.code, 2)
        self.assertEqual(error.items, items)
        self.assertIn("python scripts/scan_url.py npm:@scope/srv@1.2.3", str(error).splitlines())
        self.assertIn("python scripts/scan_url.py pypi:server==4.5.6", str(error).splitlines())


class FakeRegister:
    def __init__(self, rc=0, exc=None):
        self.rc = rc
        self.exc = exc
        self.calls = []

    def __call__(self, cmd, *, env=None, timeout=None, cwd=None):
        import subprocess
        self.calls.append({"cmd": list(cmd), "env": env, "timeout": timeout})
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.rc, "registered", "")


class Register(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = Path(self.tmp.name) / "with space" / "srv"
        self.tree.mkdir(parents=True)
        self.installs = []

    def tearDown(self):
        self.tmp.cleanup()

    def installed(self, accepted=None, secrets=("API_TOKEN",)):
        return locked.Installed(
            name="srv", kind="npm", package="@s/srv", requested="1.0.0",
            command="C:/Program Files/nodejs/node.exe", args=[str(self.tree / "x.js")],
            tree=self.tree, lockfile_sha256="ab" * 32, overrides={"dep": "2.0.0"},
            override_reason="CVE fix", secrets=secrets, accepted=accepted)

    def settings(self, register=("pwsh", "-File", "C:/tools/mcp register.ps1"), timeout=300):
        return locked.Settings(install_dir=self.tree.parent, register=register,
                               register_timeout=timeout)

    def install(self, name, entry, dry, selected=None):
        self.installs.append((name, entry, dry, selected))

    def deliver(self, settings, run=None, dry=False, installed=None):
        return locked.deliver(installed or self.installed(), settings, dry=dry,
                              selected=["codex"], install=self.install, run=run or FakeRegister())

    def test_without_register_writes_agent_configs(self):
        run = FakeRegister()
        self.assertEqual(self.deliver(self.settings(register=None), run=run), 0)
        self.assertEqual(self.installs, [("srv", {"command": "C:/Program Files/nodejs/node.exe",
                                                  "args": [str(self.tree / "x.js")]},
                                          False, ["codex"])])
        self.assertEqual(run.calls, [])
        self.assertFalse((self.tree / locked.REGISTER_FILE).exists())

    def test_with_register_never_calls_install_mcp(self):
        run = FakeRegister()
        self.assertEqual(self.deliver(self.settings(), run=run), 0)
        self.assertEqual(self.installs, [])
        self.assertEqual(len(run.calls), 1)

    def test_register_payload_fields(self):
        payload = locked.register_payload(self.installed())
        self.assertEqual(payload, {
            "version": 1, "name": "srv", "kind": "npm", "package": "@s/srv",
            "requested": "1.0.0", "command": "C:/Program Files/nodejs/node.exe",
            "args": [str(self.tree / "x.js")], "tree": str(self.tree),
            "lockfile_sha256": "ab" * 32, "overrides": {"dep": "2.0.0"},
            "override_reason": "CVE fix",
            "scan": {"verdict": "SAFE", "agent_guard": locked.agent_guard_version()},
            "secrets": ["API_TOKEN"]})
        accepted = {"version": "1.0.0", "at": "2026-11-22", "grund": "reviewed"}
        payload = locked.register_payload(self.installed(accepted=accepted))
        self.assertEqual(payload["accepted"], accepted)
        self.assertEqual(payload["scan"]["verdict"], "BLOCK")

    def test_register_gets_the_file_written_into_the_tree(self):
        run = FakeRegister()
        self.deliver(self.settings(), run=run)
        path = self.tree / locked.REGISTER_FILE
        self.assertEqual(run.calls[0]["cmd"], ["pwsh", "-File", "C:/tools/mcp register.ps1",
                                               str(path)])
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")),
                         locked.register_payload(self.installed()))
        self.assertEqual(run.calls[0]["timeout"], 300)

    def test_register_argv_keeps_spaces(self):
        run = FakeRegister()
        self.deliver(self.settings(), run=run)
        cmd = run.calls[0]["cmd"]
        self.assertEqual(len(cmd), 4)
        self.assertIn(" ", cmd[-1])
        self.assertTrue(Path(cmd[-1]).is_file())

    def test_register_failure_keeps_tree_and_names_retry(self):
        with self.assertRaises(locked.Refused) as ctx:
            self.deliver(self.settings(), run=FakeRegister(rc=3))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("installed but not registered", str(ctx.exception))
        self.assertIn(f"mcp-register {self.tree}", str(ctx.exception))
        self.assertTrue((self.tree / locked.REGISTER_FILE).is_file())
        self.assertEqual(self.installs, [])

    def test_register_timeout_is_no_verdict(self):
        import subprocess
        for exc in (subprocess.TimeoutExpired(["pwsh"], 300), OSError("not found")):
            with self.subTest(exc=type(exc).__name__):
                with self.assertRaises(locked.Refused) as ctx:
                    self.deliver(self.settings(), run=FakeRegister(exc=exc))
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("mcp-register", str(ctx.exception))

    def test_register_runs_without_credentials(self):
        run = FakeRegister()
        secret_env = {"ANTHROPIC_API_KEY": "sk-test", "GITHUB_TOKEN": "ghp-test"}
        with mock.patch.dict(os.environ, secret_env):
            self.deliver(self.settings(), run=run)
        env = run.calls[0]["env"]
        self.assertIsNotNone(env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_dry_run_shows_and_writes_nothing(self):
        run = FakeRegister()
        self.deliver(self.settings(), run=run, dry=True)
        self.assertEqual(run.calls, [])
        self.assertEqual(self.installs, [])
        self.assertFalse((self.tree / locked.REGISTER_FILE).exists())

    def test_mcp_register_repeats_the_handoff(self):
        with self.assertRaises(locked.Refused):
            self.deliver(self.settings(), run=FakeRegister(rc=1))
        run = FakeRegister()
        self.assertEqual(locked.rerun_register(self.tree, self.settings(), run=run), 0)
        self.assertEqual(run.calls[0]["cmd"][-1], str(self.tree / locked.REGISTER_FILE))

    def test_mcp_register_checks_the_file(self):
        path = self.tree / locked.REGISTER_FILE
        for content in ("not json", json.dumps({"version": 2, "tree": str(self.tree)}),
                        json.dumps({"version": 1, "tree": str(self.tree.parent)})):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                run = FakeRegister()
                with self.assertRaises(locked.Refused) as ctx:
                    locked.rerun_register(self.tree, self.settings(), run=run)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(run.calls, [])
        path.unlink()
        with self.assertRaises(locked.Refused):
            locked.rerun_register(self.tree, self.settings(), run=FakeRegister())

    def test_mcp_register_without_register_setting_is_refused(self):
        self.deliver(self.settings(), run=FakeRegister())
        with self.assertRaises(locked.Refused) as ctx:
            locked.rerun_register(self.tree, self.settings(register=None), run=FakeRegister())
        self.assertEqual(ctx.exception.code, 2)

    def test_secret_names_only(self):
        for names in (("sk-abc",), ("lower",), ("A B",), ("",)):
            with self.subTest(names=names):
                with self.assertRaises(locked.Refused) as ctx:
                    locked.check_secrets(names)
                self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(locked.check_secrets(("DATAFORSEO_LOGIN",)), ("DATAFORSEO_LOGIN",))


if __name__ == "__main__":
    unittest.main()
