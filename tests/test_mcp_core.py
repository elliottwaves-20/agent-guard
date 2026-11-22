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


if __name__ == "__main__":
    unittest.main()
