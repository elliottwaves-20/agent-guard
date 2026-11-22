"""Locked npm MCP installs (#48): exact pin, checked lockfile, no ad-hoc runner.

The npm commands are replaced by a fake runner that writes what the real tool
would write; the lockfile check is replaced by a stub. Every failure must leave
an existing install untouched and write no config.
"""
import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
locked = importlib.import_module("_mcp_locked")
lockcheck = importlib.import_module("_lockcheck")
receipts = importlib.import_module("_mcp_receipts")
npm_mod = importlib.import_module("_mcp_npm")

PKG = "@scope/server-files"
INTEGRITY = "sha512-x"


def lock_for(pkg, version, integrity=INTEGRITY):
    base = pkg.rsplit("/", 1)[-1]
    packages = {"": {"name": "mcp-files", "dependencies": {pkg: version}},
                f"node_modules/{pkg}": {
                    "version": version,
                    "resolved": f"https://registry.npmjs.org/{pkg}/-/{base}-{version}.tgz",
                    "integrity": integrity}}
    return {"lockfileVersion": 3, "packages": packages}


class FakeNpm:
    def __init__(self, version="12.2.2", bin_field=None, write_bin=True, lock_version=None,
                 install_rc=0, install_output="npm ERR! simulated", ci_rc=0,
                 installed_version=None, integrity=INTEGRITY, overrides_resolved=True):
        self.version = version
        self.bin_field = bin_field
        self.write_bin = write_bin
        self.lock_version = lock_version
        self.install_rc = install_rc
        self.install_output = install_output
        self.ci_rc = ci_rc
        self.installed_version = installed_version
        self.integrity = integrity
        self.overrides_resolved = overrides_resolved
        self.commands = []

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        args = cmd[1:]
        if args == ["--version"]:
            return 0, self.version + "\n"
        manifest = json.loads((Path(cwd) / "package.json").read_text(encoding="utf-8"))
        pkg, version = next(iter(manifest["dependencies"].items()))
        if args[0] == "install":
            if self.install_rc:
                return self.install_rc, self.install_output
            lock = lock_for(pkg, self.lock_version or version, self.integrity)
            for name, wanted in manifest.get("overrides", {}).items():
                lock["packages"][f"node_modules/{name}"] = {
                    "version": wanted if self.overrides_resolved else "0.0.1",
                    "resolved": f"https://registry.npmjs.org/{name}/-/x-{wanted}.tgz",
                    "integrity": "sha512-o"}
            (Path(cwd) / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            return 0, ""
        if args[0] == "ci":
            if self.ci_rc:
                return self.ci_rc, "npm ERR! simulated"
            pkg_dir = Path(cwd) / "node_modules" / Path(*pkg.split("/"))
            pkg_dir.mkdir(parents=True)
            bin_field = (self.bin_field if self.bin_field is not None
                         else {pkg.rsplit("/", 1)[-1]: "dist/index.js"})
            (pkg_dir / "package.json").write_text(json.dumps(
                {"name": pkg, "version": self.installed_version or version, "bin": bin_field}),
                encoding="utf-8")
            if self.write_bin:
                (pkg_dir / "dist").mkdir()
                (pkg_dir / "dist" / "index.js").write_text("// server", encoding="utf-8")
            return 0, ""
        raise AssertionError(f"unexpected npm call {cmd}")


def stub_check(code):
    def check(entries, **_kwargs):
        check.entries = entries
        return lockcheck.Result(code, [f"stub result {code}"])
    check.entries = None
    return check


def which(name):
    return {"npm": "C:/node/npm.cmd", "node": "C:/node/node.exe"}.get(name)


def receipt(version="1.2.3", integrity=INTEGRITY, package=PKG):
    return receipts.Receipt(kind="npm", package=package, version=version,
                            archive_sha256="ab" * 32, integrity=integrity, verdict="SAFE",
                            at="2026-11-22T00:00:00+00:00", agent_guard="0.5.2")


class NpmInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, npm=None, check=None, **kwargs):
        opts = {"name": "files", "package": PKG, "version": "1.2.3", "overrides": {},
                "override_reason": None, "bin_name": None, "secrets": (),
                "root": self.root, "receipt": receipt(), "accepted": None,
                "run": npm if npm is not None else FakeNpm(),
                "check": check or stub_check(0), "which": which}
        opts.update(kwargs)
        return npm_mod.npm_install(**opts)

    def old_install(self):
        target = self.root / "files"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("old tree", encoding="utf-8")
        return target

    def assert_old_untouched(self):
        target = self.root / "files"
        self.assertEqual((target / "marker.txt").read_text(encoding="utf-8"), "old tree")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["files"])

    def test_clean_install_starts_node_with_the_package_bin(self):
        installed = self.install()
        target = self.root.resolve() / "files"
        self.assertIsInstance(installed, locked.Installed)
        self.assertEqual(installed.command, "C:/node/node.exe")
        self.assertEqual(installed.args, [str(target / "node_modules" / "@scope" / "server-files"
                                              / "dist" / "index.js")])
        self.assertTrue(Path(installed.args[0]).is_file())
        self.assertEqual(installed.tree, target)
        self.assertEqual((installed.kind, installed.package, installed.requested),
                         ("npm", PKG, "1.2.3"))
        manifest = json.loads((target / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["dependencies"], {PKG: "1.2.3"})
        self.assertTrue(manifest["private"])
        meta = json.loads((target / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual((meta["package"], meta["version"]), (PKG, "1.2.3"))
        self.assertEqual(meta["lockfile_sha256"], installed.lockfile_sha256)
        self.assertEqual(len(installed.lockfile_sha256), 64)

    def test_resolution_and_install_never_run_scripts(self):
        npm = FakeNpm()
        self.install(npm=npm)
        install = next(c for c in npm.commands if c[1] == "install")
        ci = next(c for c in npm.commands if c[1] == "ci")
        for flag in ("--ignore-scripts", "--package-lock-only", "--min-release-age=7",
                     "--registry=https://registry.npmjs.org/"):
            self.assertIn(flag, install)
        for flag in ("--ignore-scripts", "--registry=https://registry.npmjs.org/"):
            self.assertIn(flag, ci)
        self.assertNotIn("npx", " ".join(" ".join(c) for c in npm.commands))

    def test_check_sees_every_lockfile_entry(self):
        check = stub_check(0)
        self.install(check=check)
        self.assertEqual([e.label for e in check.entries], [f"{PKG}@1.2.3"])

    def test_lockfile_finding_keeps_the_old_tree(self):
        self.old_install()
        npm = FakeNpm()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=npm, check=stub_check(1))
        self.assertEqual(ctx.exception.code, 1)
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))
        self.assert_old_untouched()

    def test_lockfile_no_verdict_keeps_the_old_tree(self):
        self.old_install()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(check=stub_check(2))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_lockfile_integrity_must_match_the_scanned_tarball(self):
        self.old_install()
        npm = FakeNpm(integrity="sha512-other")
        check = stub_check(0)
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=npm, check=check)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("scanned", str(ctx.exception))
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))
        self.assert_old_untouched()

    def test_npm_etarget_means_wait(self):
        npm = FakeNpm(install_rc=1, install_output="npm error code ETARGET\nnpm error notarget")
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=npm)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("younger than 7 days", str(ctx.exception))

    def test_update_replaces_the_old_tree_after_every_check(self):
        self.old_install()
        self.install()
        target = self.root / "files"
        self.assertFalse((target / "marker.txt").exists())
        self.assertTrue((target / "package-lock.json").is_file())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["files"])

    def test_reinstall_same_version_gives_same_lockfile_hash(self):
        first = self.install()
        second = self.install()
        self.assertEqual(first.lockfile_sha256, second.lockfile_sha256)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["files"])

    def test_gitignore_excludes_node_modules(self):
        self.install()
        lines = (self.root / "files" / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("node_modules/", lines)

    def test_bin_outside_the_package_is_refused(self):
        self.old_install()
        for bin_field in ("../../../marker.txt", "../server-files-evil/x.js"):
            with self.subTest(bin=bin_field):
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=FakeNpm(bin_field={"server-files": bin_field}))
                self.assertEqual(ctx.exception.code, 2)
                self.assert_old_untouched()

    def test_missing_bin_file_is_refused(self):
        with self.assertRaises(locked.Refused):
            self.install(npm=FakeNpm(write_bin=False))
        self.assertFalse((self.root / "files").exists())

    def test_package_without_bin_is_refused(self):
        with self.assertRaises(locked.Refused):
            self.install(npm=FakeNpm(bin_field={}))

    def test_ambiguous_bins_need_an_explicit_choice(self):
        bins = {"a": "dist/index.js", "b": "dist/index.js"}
        with self.assertRaises(locked.Refused):
            self.install(npm=FakeNpm(bin_field=bins))
        installed = self.install(npm=FakeNpm(bin_field=bins), bin_name="b")
        self.assertTrue(installed.args[0].endswith("index.js"))

    def test_unknown_bin_choice_is_refused(self):
        with self.assertRaises(locked.Refused):
            self.install(npm=FakeNpm(bin_field={"a": "dist/index.js"}), bin_name="c")

    def test_string_bin_is_accepted(self):
        installed = self.install(npm=FakeNpm(bin_field="dist/index.js"))
        self.assertTrue(installed.args[0].endswith("index.js"))

    def test_lockfile_with_another_top_level_version_is_refused(self):
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=FakeNpm(lock_version="9.9.9"))
        self.assertEqual(ctx.exception.code, 2)

    def test_installed_version_must_match_the_pin(self):
        with self.assertRaises(locked.Refused):
            self.install(npm=FakeNpm(installed_version="9.9.9"))

    def test_npm_failures_keep_the_old_tree(self):
        self.old_install()
        for npm in (FakeNpm(install_rc=1), FakeNpm(ci_rc=1)):
            with self.subTest(npm=npm.__dict__):
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm)
                self.assertEqual(ctx.exception.code, 2)
                self.assert_old_untouched()

    def test_npm_without_min_release_age_is_refused(self):
        for version in ("11.9.0", "10.9.2", "garbage"):
            with self.subTest(version=version):
                npm = FakeNpm(version=version)
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(len(npm.commands), 1)
        self.install(npm=FakeNpm(version="11.10.0"))

    def test_override_needs_a_reason_and_an_exact_version(self):
        for overrides, reason in (({"dep": "1.0.1"}, ""), ({"dep": "1.0.1"}, None),
                                  ({"dep": "^1.0.1"}, "advisory")):
            with self.subTest(overrides=overrides, reason=reason):
                npm = FakeNpm()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm, overrides=overrides, override_reason=reason)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(npm.commands, [])

    def test_override_not_resolved_exactly_is_refused(self):
        npm = FakeNpm(overrides_resolved=False)
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=npm, overrides={"dep": "1.0.1"}, override_reason="advisory")
        self.assertEqual(ctx.exception.code, 2)
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))

    def test_override_is_written_with_its_reason(self):
        installed = self.install(overrides={"@modelcontextprotocol/sdk": "1.25.0"},
                                 override_reason="GHSA advisory in the pinned SDK")
        target = self.root / "files"
        manifest = json.loads((target / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["overrides"], {"@modelcontextprotocol/sdk": "1.25.0"})
        self.assertEqual(manifest["_overrides"], "GHSA advisory in the pinned SDK")
        meta = json.loads((target / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["override_reason"], "GHSA advisory in the pinned SDK")
        self.assertEqual(installed.overrides, {"@modelcontextprotocol/sdk": "1.25.0"})

    def test_invalid_input_is_refused_before_anything_runs(self):
        cases = [{"name": "../x"}, {"name": "a b"}, {"package": "srv;calc"},
                 {"package": "Upper"}, {"version": "1.0.0 --foo"}, {"version": "latest"},
                 {"secrets": ("lower",)}, {"bin_name": "a b"}]
        for case in cases:
            with self.subTest(case=case):
                npm = FakeNpm()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm, **case)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(npm.commands, [])

    def test_batch_metacharacters_never_reach_npm(self):
        cases = [{"version": "1.0.0&calc"},
                 {"overrides": {"a": "1.0.0|x"}, "override_reason": "r"},
                 {"overrides": {"a%PATH%": "1.0.0"}, "override_reason": "r"},
                 {"name": 'x"y'}, {"package": "a^b"}]
        for case in cases:
            with self.subTest(case=case):
                npm = FakeNpm()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm, **case)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(npm.commands, [])

    def test_receipt_for_another_package_is_refused(self):
        npm = FakeNpm()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(npm=npm, receipt=receipt(package="@scope/other"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(npm.commands, [])

    def test_command_keeps_paths_with_spaces(self):
        spaced = {"npm": "C:/Program Files/nodejs/npm.cmd",
                  "node": "C:/Program Files/nodejs/node.exe"}
        root = Path(self.tmp.name) / "with space" / "mcp"
        installed = self.install(which=spaced.get, root=root)
        self.assertEqual(installed.command, "C:/Program Files/nodejs/node.exe")
        self.assertEqual(len(installed.args), 1)
        self.assertTrue(Path(installed.args[0]).is_file())

    def test_missing_node_or_npm_is_refused(self):
        for missing in ("node", "npm"):
            with self.subTest(missing=missing):
                npm = FakeNpm()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(npm=npm, which=lambda n, m=missing: None if n == m else which(n))
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(npm.commands, [])

    def test_dry_run_writes_nothing(self):
        npm = FakeNpm()
        installed = self.install(npm=npm, dry=True)
        self.assertEqual(npm.commands, [])
        self.assertFalse(self.root.exists())
        self.assertEqual(installed.command, "C:/node/node.exe")

    def test_leftovers_of_an_aborted_run_do_not_stop_the_install(self):
        self.root.mkdir(parents=True)
        (self.root / ".files.staging-dead").mkdir()
        self.install()
        self.assertTrue((self.root / ".files.staging-dead").is_dir())
        self.assertTrue((self.root / "files" / "package-lock.json").is_file())


class NpmCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **overrides):
        values = {"package": PKG, "version": "1.2.3", "name": None, "override": [],
                  "override_reason": None, "bin": None, "secret": [], "accept": None,
                  "tools": None, "dry_run": False}
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_missing_receipt_runs_nothing(self):
        install_skill = importlib.import_module("install_skill")
        npm = FakeNpm()
        config = {"mcp": {"install_dir": str(self.base / "mcp")}}
        with self.assertRaises(locked.Refused) as ctx:
            install_skill.cmd_mcp_npm(self.args(), config=config, env={}, platform="win32",
                                      run=npm, which=which, check=stub_check(0),
                                      deliver=lambda *a, **k: self.fail("delivered"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("scan first", str(ctx.exception))
        self.assertEqual(npm.commands, [])

    def test_safe_receipt_installs_and_delivers_node_and_bin(self):
        install_skill = importlib.import_module("install_skill")
        root = self.base / "mcp"
        receipts.write_receipt(root, receipt())
        delivered = []
        config = {"mcp": {"install_dir": str(root)}}
        install_skill.cmd_mcp_npm(
            self.args(override=["dep=1.0.1"], override_reason="advisory",
                      secret=["API_TOKEN"]),
            config=config, env={}, platform="win32", run=FakeNpm(), which=which,
            check=stub_check(0), deliver=lambda *a, **k: delivered.append((a, k)))
        (name, entry, dry), kwargs = delivered[0]
        self.assertEqual(name, "server-files")
        self.assertEqual(entry["command"], "C:/node/node.exe")
        self.assertNotIn("env", entry)
        self.assertFalse(dry)

    def test_register_setting_hands_over_instead_of_writing_configs(self):
        install_skill = importlib.import_module("install_skill")
        root = self.base / "mcp"
        receipts.write_receipt(root, receipt())
        calls = []

        def register_run(cmd, *, env=None, timeout=None, cwd=None):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        config = {"mcp": {"install_dir": str(root), "register": ["pwsh", "-File", "r.ps1"]}}
        install_skill.cmd_mcp_npm(self.args(secret=["API_TOKEN"]), config=config, env={},
                                  platform="win32", run=FakeNpm(), which=which,
                                  check=stub_check(0),
                                  deliver=lambda *a, **k: self.fail("wrote agent configs"),
                                  register_run=register_run)
        path = root.resolve() / "server-files" / locked.REGISTER_FILE
        self.assertEqual(calls, [["pwsh", "-File", "r.ps1", str(path)]])
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((payload["kind"], payload["secrets"]), ("npm", ["API_TOKEN"]))

    def test_bad_override_syntax_is_refused(self):
        install_skill = importlib.import_module("install_skill")
        for override in (["dep"], ["dep=1.0.0", "dep=1.0.1"]):
            with self.subTest(override=override):
                with self.assertRaises(locked.Refused) as ctx:
                    install_skill.cmd_mcp_npm(
                        self.args(override=override, override_reason="r"),
                        config={"mcp": {"install_dir": str(self.base / "mcp")}}, env={},
                        platform="win32", run=FakeNpm(), which=which, check=stub_check(0),
                        deliver=lambda *a, **k: self.fail("delivered"))
                self.assertEqual(ctx.exception.code, 2)

    def test_cli_exits_with_the_refusal_code(self):
        env = dict(os.environ)
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        env["LOCALAPPDATA"] = str(self.base)
        env["XDG_DATA_HOME"] = str(self.base)
        for var in locked.ONEDRIVE_VARS:
            env.pop(var, None)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "install_skill.py"), "mcp-npm",
             "--package", PKG, "--version", "1.2.3"],
            capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scan first", result.stderr)


if __name__ == "__main__":
    unittest.main()
