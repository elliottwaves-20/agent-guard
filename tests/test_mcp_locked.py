"""Locked npm MCP installs (#48): exact pin, checked lockfile, no ad-hoc runner.

The npm commands are replaced by a fake runner that writes what the real tool
would write; the lockfile check is replaced by a stub. Every failure must leave
an existing install untouched and write no config.
"""
import argparse
import datetime as dt
import hashlib
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
locked = importlib.import_module("_mcp_locked")
lockcheck = importlib.import_module("_lockcheck")
receipts = importlib.import_module("_mcp_receipts")
npm_mod = importlib.import_module("_mcp_npm")
fastlane = importlib.import_module("_fastlane")

PKG = "@scope/server-files"
INTEGRITY = "sha512-x"
NOW = dt.datetime(2026, 11, 22, 12, 0, tzinfo=dt.timezone.utc)
SLSA = "https://slsa.dev/provenance/v1"
REPO = "github.com/o/r"


def stamp(days):
    return (NOW - dt.timedelta(days=days)).isoformat().replace("+00:00", "Z")


class Times(dict):
    """Publish times of one registry document; every version is old unless listed."""

    def __init__(self, listed, default_days):
        super().__init__(listed)
        self.default_days = default_days

    def __missing__(self, version):
        return stamp(self.default_days)


class FakeRegistry:
    """Answers the npm registry document of any package (no network)."""

    def __init__(self, ages=None, default_days=100):
        self.ages = dict(ages or {})  # (name, version): days since publication
        self.default_days = default_days
        self.requests = []

    def __call__(self, url, payload=None):
        prefix = "https://registry.npmjs.org/"
        if not url.startswith(prefix):
            raise AssertionError(f"unexpected request: {url}")
        self.requests.append(url)
        name = urllib.parse.unquote(url[len(prefix):])
        listed = {version: stamp(days) for (pkg, version), days in self.ages.items()
                  if pkg == name}
        return {"time": Times(listed, self.default_days)}, None


def audit_json(verified=(), invalid=(), missing=(), predicate=SLSA):
    rows = [{"name": name, "version": version, "location": f"node_modules/{name}",
             "registry": "https://registry.npmjs.org/",
             "attestations": {"url": "https://registry.npmjs.org/x",
                              "provenance": {"predicateType": predicate}}}
            for name, version in verified]
    return json.dumps({"invalid": list(invalid), "missing": list(missing), "verified": rows})


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
                 installed_version=None, integrity=INTEGRITY, overrides_resolved=True,
                 extra=None, integrities=None, top_integrity=None, etarget_unless_excluded=None,
                 audit=None):
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
        self.extra = dict(extra or {})  # name: (version, integrity) of further lockfile entries
        self.integrities = list(integrities or [])  # top-level integrity per resolution
        self.top_integrity = dict(top_integrity or {})  # top-level integrity per version
        self.etarget_unless_excluded = etarget_unless_excluded
        self.audit = audit  # (return code, output) of npm audit signatures
        self.commands = []
        self.seeds = []  # whether a lockfile was present at each resolution
        self.install_dirs = []
        self.installs = 0

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        args = cmd[1:]
        if args == ["--version"]:
            return 0, self.version + "\n"
        manifest = json.loads((Path(cwd) / "package.json").read_text(encoding="utf-8"))
        pkg, version = next(iter(manifest["dependencies"].items()))
        if args[0] == "audit":
            return self.audit if self.audit is not None else (0, audit_json())
        if args[0] == "install":
            self.seeds.append((Path(cwd) / "package-lock.json").exists())
            self.install_dirs.append(str(cwd))
            index, self.installs = self.installs, self.installs + 1
            if self.install_rc:
                return self.install_rc, self.install_output
            if (self.etarget_unless_excluded is not None
                    and f"--min-release-age-exclude={self.etarget_unless_excluded}" not in args):
                return 1, "npm error code ETARGET\nnpm error notarget"
            integrity = self.integrities[index] if index < len(self.integrities) else (
                self.top_integrity.get(version, self.integrity))
            lock = lock_for(pkg, self.lock_version or version, integrity)
            for name, (extra_version, extra_integrity) in self.extra.items():
                lock["packages"][f"node_modules/{name}"] = {
                    "version": extra_version,
                    "resolved": f"https://registry.npmjs.org/{name}/-/x-{extra_version}.tgz",
                    "integrity": extra_integrity}
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
                "check": check or stub_check(0), "which": which,
                "fetch": FakeRegistry(), "now": NOW}
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
            check=stub_check(0), fetch=FakeRegistry(),
            deliver=lambda *a, **k: delivered.append((a, k)))
        (name, entry, dry), kwargs = delivered[0]
        self.assertEqual(name, "server-files")
        self.assertEqual(entry["command"], "C:/node/node.exe")
        self.assertNotIn("env", entry)
        self.assertFalse(dry)

    def install_with_fake_npm(self, *options):
        install_skill = importlib.import_module("install_skill")
        root = self.base / "mcp"
        receipts.write_receipt(root, receipt())
        npm = FakeNpm()
        cmd_mcp_npm = install_skill.cmd_mcp_npm

        def install(args, **kwargs):
            kwargs.update(config={"mcp": {"install_dir": str(root)}}, run=npm,
                          which=which, check=stub_check(0), deliver=lambda *a, **k: None)
            return cmd_mcp_npm(args, **kwargs)

        argv = ["install_skill.py", "mcp-npm", "--package", PKG, "--version", "1.2.3", *options]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
                install_skill, "cmd_mcp_npm", install):
            install_skill.main()
        return npm

    def test_min_release_age_follows_the_setting(self):
        npm = self.install_with_fake_npm("--min-age-days", "10")
        resolution = next(command for command in npm.commands if "install" in command)
        self.assertIn("--min-release-age=10", resolution)

    def test_json_keeps_install_output_on_stderr(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
            self.install_with_fake_npm("--json", "--dry-run")
        status = json.loads(stdout.getvalue())
        self.assertEqual((status["code"], status["tier"]), (0, "s2"))
        self.assertIn("[DRY]", stderr.getvalue())

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
        result = self.invoke_cli()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scan first", result.stderr)

    def invoke_cli(self, *options):
        env = dict(os.environ)
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        env["LOCALAPPDATA"] = str(self.base)
        env["XDG_DATA_HOME"] = str(self.base)
        for var in locked.ONEDRIVE_VARS:
            env.pop(var, None)
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "install_skill.py"), "mcp-npm",
             "--package", PKG, "--version", "1.2.3", *options],
            capture_output=True, text=True, env=env, timeout=120)

    def test_invalid_settings_are_refused(self):
        cases = [("--trusted-days", "8", "--min-age-days", "7"),
                 ("--min-age-days", "-1"), ("--trusted-days", "-1"),
                 ("--min-age-days", "2.5")]
        for options in cases:
            with self.subTest(options=options):
                result = self.invoke_cli(*options, "--json")
                self.assertEqual(result.returncode, 2)
                status = json.loads(result.stdout)
                self.assertEqual(status["code"], 2)
                self.assertIn("integers", status["message"])
                self.assertEqual(status["needs_scan"], [])

    def test_json_output_is_one_object(self):
        result = self.invoke_cli("--json")
        self.assertEqual(result.returncode, 2)
        status = json.loads(result.stdout)
        self.assertEqual(status, {
            "code": 2, "message": status["message"],
            "needs_scan": [{"kind": "npm", "package": PKG, "version": "1.2.3"}],
            "fast_lane": [], "tier": "",
        })
        self.assertIn("scan first", status["message"])
        self.assertIn(f"python scripts/scan_url.py npm:{PKG}@1.2.3", status["message"])
        self.assertIn("scan first", result.stderr)

    def test_json_reports_a_block_receipt(self):
        values = vars(receipt()) | {"verdict": "BLOCK"}
        receipts.write_receipt(self.base / "agent-guard" / "mcp", receipts.Receipt(**values))
        result = self.invoke_cli("--json")
        self.assertEqual(result.returncode, 1)
        status = json.loads(result.stdout)
        self.assertEqual((status["code"], status["needs_scan"]), (1, []))
        self.assertIn("BLOCK", status["message"])


class UnexpectedErrorTests(unittest.TestCase):
    """An unexpected exception is no verdict (2), never a finding (1)."""

    def run_handler(self, as_json):
        install_skill = importlib.import_module("install_skill")

        def handler(args, **_kwargs):
            raise KeyError("unexpected answer shape")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            with self.assertRaises(SystemExit) as raised:
                install_skill._run_locked_mcp(argparse.Namespace(json=as_json), handler)
        return raised.exception.code, out.getvalue(), err.getvalue()

    def test_unexpected_error_is_no_verdict_in_json_mode(self):
        code, out, err = self.run_handler(True)
        self.assertEqual(code, 2)
        status = json.loads(out)
        self.assertEqual(status["code"], 2)
        self.assertIn("unexpected answer shape", status["message"])
        self.assertIn("KeyError", err)

    def test_unexpected_error_is_no_verdict_without_json(self):
        code, out, err = self.run_handler(False)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("NO VERDICT", err)


class ScriptedCheck:
    """Returns the scripted results one by one (the last one repeats) and records calls."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, entries, **kwargs):
        self.calls.append((list(entries), kwargs))
        return self.results[min(len(self.calls) - 1, len(self.results) - 1)]


def high_advisory(name="dep", version="1.0.0", fixed="1.0.3", ident="GHSA-aaaa-bbbb-cccc",
                  severity="high"):
    entry = lockcheck.Entry("npm", name, version, integrity="sha512-d")
    interval = {"lower": None, "lower_inclusive": True, "upper": fixed,
                "upper_inclusive": False, "fixed": fixed}
    return lockcheck.Advisory(entry, ident, "github-reviewed", aliases=("CVE-2026-0001",),
                              severity=severity, affected=(interval,))


def finding(*advisories, failures=()):
    lines = [f"[BLOCK] lockfile finding: {a.id}" for a in advisories]
    return lockcheck.Result(1, lines, list(advisories), [], list(failures))


class FastLaneBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"
        self.continuity_calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def lookups(self, provenance=None, kev=frozenset(), continuity="same"):
        """Fixed answers for KEV, fix advisories, provenance and continuity (no network)."""
        table = dict(provenance or {})

        def npm_provenance(name, version, fetch):
            answer = table[(name, version)]
            if isinstance(answer, Exception):
                raise answer
            return answer

        def continuity_of(ecosystem, name, old, new, fetch):
            self.continuity_calls.append((name, old, new))
            return continuity

        for target, replacement in (("kev_cves", lambda fetch: kev),
                                    ("advisories_for", lambda entries, fetch=None: ([], [])),
                                    ("npm_provenance", npm_provenance),
                                    ("continuity", continuity_of)):
            patcher = mock.patch.object(fastlane, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, name, version, integrity, package_root=None):
        receipts.write_receipt(package_root or self.root, receipts.Receipt(
            kind="npm", package=name, version=version, archive_sha256="cd" * 32,
            integrity=integrity, verdict="SAFE", at="2026-11-22T00:00:00+00:00",
            agent_guard="0.5.2"))

    def install(self, npm=None, check=None, **kwargs):
        opts = {"name": "files", "package": PKG, "version": "1.2.3", "overrides": {},
                "override_reason": None, "bin_name": None, "secrets": (),
                "root": self.root, "receipt": receipt(), "accepted": None,
                "run": npm if npm is not None else FakeNpm(),
                "check": check or stub_check(0), "which": which,
                "fetch": FakeRegistry(), "now": NOW}
        opts.update(kwargs)
        buffer = io.StringIO()
        with mock.patch.object(sys, "stderr", buffer):
            try:
                return npm_mod.npm_install(**opts)
            finally:
                self.stderr = buffer.getvalue()

    def old_tree(self, version, package=PKG, tier="s2", with_tier=True, lock_matches=True):
        target = self.root / "files"
        target.mkdir(parents=True)
        lock = json.dumps(lock_for(package, version)).encode()
        (target / "package-lock.json").write_bytes(lock)
        meta = {"kind": "npm", "package": package, "version": version,
                "lockfile_sha256": hashlib.sha256(lock if lock_matches else b"x").hexdigest()}
        if with_tier:
            meta["tier"] = tier
        (target / locked.METADATA).write_text(json.dumps(meta), encoding="utf-8")
        (target / "marker.txt").write_text("old tree", encoding="utf-8")
        return target

    def assert_old_untouched(self):
        target = self.root / "files"
        self.assertEqual((target / "marker.txt").read_text(encoding="utf-8"), "old tree")
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.name != ".receipts"),
                         ["files"])

    def refused(self, code, **kwargs):
        with self.assertRaises(locked.Refused) as ctx:
            self.install(**kwargs)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))
        return ctx.exception


class FastLaneInstall(FastLaneBase):
    """Security fixes that are younger than the waiting period (#48, 15.2)."""

    def fix_setup(self, provenance=None, scanned=True, **kwargs):
        provenance = provenance if provenance is not None else {
            ("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO}
        self.lookups(provenance=provenance)
        if scanned:
            self.scan("dep", "1.0.3", "sha512-o")
        npm = kwargs.pop("npm", None) or FakeNpm(
            extra={"dep": ("1.0.0", "sha512-d")},
            audit=(0, audit_json(verified=[("dep", "1.0.3")])))
        check = kwargs.pop("check", None) or ScriptedCheck(
            finding(high_advisory()), lockcheck.Result(0, ["ok"]))
        return npm, check

    def test_fast_lane_installs_scanned_fix_of_transitive_high(self):
        npm, check = self.fix_setup()
        installed = self.install(npm=npm, check=check)
        manifest = json.loads((self.root / "files" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["overrides"], {"dep": "1.0.3"})
        self.assertEqual(manifest["_overrides"], "agent-guard fast lane: GHSA-aaaa-bbbb-cccc")
        expected = [{"package": "dep", "from": "1.0.0", "to": "1.0.3",
                     "advisories": ["GHSA-aaaa-bbbb-cccc"], "repo": REPO,
                     "receipt_integrity": "sha512-o", "tier": "fast_lane"}]
        self.assertEqual(installed.fast_lane, expected)
        meta = json.loads((self.root / "files" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["fast_lane"], expected)
        self.assertEqual(check.calls[1][1]["age_limits"], {("npm", "dep", "1.0.3"): 0})
        self.assertIn("fast lane: dep 1.0.0 -> 1.0.3 (GHSA-aaaa-bbbb-cccc, provenance "
                      f"{REPO}, receipt sha512-o)", self.stderr)
        self.assertTrue(any(c[1:3] == ["audit", "signatures"] for c in npm.commands))

    def test_fast_lane_excludes_only_the_fix_packages(self):
        npm, check = self.fix_setup()
        self.install(npm=npm, check=check)
        installs = [c for c in npm.commands if c[1] == "install"]
        self.assertEqual(len(installs), 2)
        rebuild = installs[1]
        self.assertIn("--min-release-age=7", rebuild)
        self.assertEqual([a for a in rebuild if a.startswith("--min-release-age-exclude")],
                         ["--min-release-age-exclude=dep"])
        self.assertNotIn("--min-release-age=0", rebuild)
        self.assertEqual(npm.seeds, [False, True])
        self.assertEqual(len(set(npm.install_dirs)), 2)

    def test_fast_lane_without_receipt_needs_scan(self):
        npm, check = self.fix_setup(scanned=False)
        self.old_tree("1.2.2")
        exc = self.refused(2, npm=npm, check=check)
        self.assertIsInstance(exc, locked.NeedsScan)
        self.assertEqual(exc.items, [{"kind": "npm", "package": "dep", "version": "1.0.3"}])
        self.assertIn("python scripts/scan_url.py npm:dep@1.0.3", str(exc))
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)
        self.assertEqual(len(set(npm.install_dirs)), 1)
        self.assert_old_untouched()

    def test_missing_provenance_reports_with_override_hint(self):
        npm, check = self.fix_setup(provenance={("dep", "1.0.0"): REPO,
                                                ("dep", "1.0.3"): "missing"})
        exc = self.refused(1, npm=npm, check=check)
        self.assertIn("--override dep=1.0.3", str(exc) + self.stderr)
        self.assertIn("--override-reason", str(exc) + self.stderr)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_provenance_lookup_failure_has_no_verdict(self):
        failed = lockcheck.LookupFailed("registry down", 500)
        npm, check = self.fix_setup(provenance={("dep", "1.0.0"): REPO,
                                                ("dep", "1.0.3"): failed})
        self.refused(2, npm=npm, check=check)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_receipt_hash_differs_from_lockfile(self):
        npm, check = self.fix_setup(scanned=False)
        self.scan("dep", "1.0.3", "sha512-other")
        self.old_tree("1.2.2")
        self.refused(2, npm=npm, check=check)
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))
        self.assert_old_untouched()

    def user_override_setup(self, provenance, audit_verified=(), audit_invalid=()):
        self.lookups(provenance=provenance)
        self.scan("dep", "1.0.3", "sha512-o")
        npm = FakeNpm(extra={"dep": ("1.0.0", "sha512-d")},
                      audit=(0, audit_json(verified=audit_verified, invalid=audit_invalid)))
        check = ScriptedCheck(finding(high_advisory()), lockcheck.Result(0, ["ok"]))
        options = {"overrides": {"dep": "1.0.3"}, "override_reason": "own reason",
                   "fetch": FakeRegistry(ages={("dep", "1.0.3"): 3})}
        return npm, check, options

    def test_user_override_installs_when_provenance_missing(self):
        npm, check, options = self.user_override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing"})
        installed = self.install(npm=npm, check=check, **options)
        manifest = json.loads((self.root / "files" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["overrides"], {"dep": "1.0.3"})
        self.assertEqual(manifest["_overrides"],
                         "own reason; agent-guard fast lane: GHSA-aaaa-bbbb-cccc")
        self.assertEqual([item["tier"] for item in installed.fast_lane], ["override"])
        self.assertEqual(npm.seeds, [False, True])

    def test_audit_signatures_override_fix_needs_no_attestation(self):
        npm, check, options = self.user_override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing"})
        self.install(npm=npm, check=check, **options)
        self.assertTrue(any(c[1:3] == ["audit", "signatures"] for c in npm.commands))
        npm, check, options = self.user_override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing"},
            audit_invalid=[{"name": "dep", "version": "1.0.3"}])
        (self.root / "files").rename(self.root / "done")
        self.refused(2, npm=npm, check=check, **options)

    def test_user_override_does_not_help_a_failed_lookup(self):
        failed = lockcheck.LookupFailed("registry down", 500)
        npm, check, options = self.user_override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): failed})
        self.refused(2, npm=npm, check=check, **options)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_user_override_does_not_help_a_changed_repo(self):
        npm, check, options = self.user_override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "github.com/x/y"})
        self.refused(1, npm=npm, check=check, **options)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_no_fast_lane_option_reports(self):
        npm, check = self.fix_setup(scanned=False)
        self.refused(1, npm=npm, check=check, policy=fastlane.policy(None, None, True))
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_old_npm_has_no_fast_lane(self):
        npm, check = self.fix_setup(scanned=False)
        npm.version = "11.16.0"
        exc = self.refused(1, npm=npm, check=check)
        self.assertIn("fast lane not available for npm trees on this npm", str(exc) + self.stderr)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_new_young_dependency_of_fix_waits(self):
        young = lockcheck.Young(lockcheck.Entry("npm", "newdep", "2.0.0"), stamp(1), 7,
                                "2026-11-28")
        npm, check = self.fix_setup(check=ScriptedCheck(
            finding(high_advisory()),
            lockcheck.Result(2, ["NO VERDICT -- newdep young"], [], [young], [])))
        self.old_tree("1.2.2")
        self.refused(2, npm=npm, check=check)
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))
        self.assert_old_untouched()

    def test_lookup_failure_next_to_fixable_finding_blocks_rebuild(self):
        npm, check = self.fix_setup(check=ScriptedCheck(
            finding(high_advisory(), failures=["GitHub reviewed: unreadable"])))
        self.refused(2, npm=npm, check=check)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_kev_unavailable_blocks_fast_lane(self):
        npm, check = self.fix_setup()
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO}, kev=None)
        self.refused(2, npm=npm, check=check)
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_rebuild_checks_top_receipt(self):
        npm, check = self.fix_setup(npm=FakeNpm(
            extra={"dep": ("1.0.0", "sha512-d")}, integrities=[INTEGRITY, "sha512-changed"]))
        exc = self.refused(2, npm=npm, check=check)
        self.assertIn("scanned", str(exc))
        self.assertFalse(any(c[1] == "ci" for c in npm.commands))

    def test_conflicting_user_override_is_refused(self):
        self.lookups(provenance={("dep", "1.0.1"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", "sha512-o")
        npm = FakeNpm()
        check = ScriptedCheck(finding(high_advisory(version="1.0.1")))
        self.refused(2, npm=npm, check=check, overrides={"dep": "1.0.1"},
                     override_reason="pinned for compatibility")
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_pending_override_without_advisory_waits(self):
        npm = FakeNpm()
        exc = self.refused(2, npm=npm, overrides={"dep": "1.0.3"}, override_reason="r",
                           fetch=FakeRegistry(ages={("dep", "1.0.3"): 3}))
        self.assertIn("younger than 7 days", str(exc))
        self.assertIn("2026-11-26", str(exc))
        self.assertEqual(len([c for c in npm.commands if c[1] == "install"]), 1)

    def test_fix_of_top_package_pins_the_fix_version(self):
        self.lookups(provenance={(PKG, "1.2.3"): REPO, (PKG, "1.2.4"): REPO})
        self.scan(PKG, "1.2.4", "sha512-top2")
        npm = FakeNpm(top_integrity={"1.2.4": "sha512-top2"},
                      audit=(0, audit_json(verified=[(PKG, "1.2.4")])))
        advisory = high_advisory(name=PKG, version="1.2.3", fixed="1.2.4")
        check = ScriptedCheck(finding(advisory), lockcheck.Result(0, ["ok"]))
        installed = self.install(npm=npm, check=check)
        manifest = json.loads((self.root / "files" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["dependencies"], {PKG: "1.2.4"})
        self.assertNotIn("overrides", manifest)
        self.assertEqual(installed.requested, "1.2.4")
        meta = json.loads((self.root / "files" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["version"], "1.2.4")
        self.assertEqual((installed.fast_lane[0]["from"], installed.fast_lane[0]["to"]),
                         ("1.2.3", "1.2.4"))
        self.assertEqual(check.calls[1][1]["age_limits"], {("npm", PKG, "1.2.4"): 0})
        rebuild = [c for c in npm.commands if c[1] == "install"][1]
        self.assertIn(f"--min-release-age-exclude={PKG}", rebuild)
        self.assertTrue(Path(installed.args[0]).is_file())

    def test_audit_signatures_failure_has_no_verdict(self):
        cases = {"exit code": (1, audit_json(verified=[("dep", "1.0.3")])),
                 "unreadable": (0, "npm warn something\nnot json"),
                 "no verified key": (0, json.dumps({"invalid": [], "missing": []})),
                 "invalid": (0, audit_json(verified=[("dep", "1.0.3")],
                                           invalid=[{"name": "x"}])),
                 "missing": (0, audit_json(verified=[("dep", "1.0.3")],
                                           missing=[{"name": "x"}]))}
        for label, audit in cases.items():
            with self.subTest(case=label):
                npm, check = self.fix_setup(npm=FakeNpm(
                    extra={"dep": ("1.0.0", "sha512-d")}, audit=audit))
                self.refused(2, npm=npm, check=check)
                self.assertFalse((self.root / "files").exists())

    def test_audit_signatures_without_verified_attestation_for_fix_has_no_verdict(self):
        cases = {"empty": audit_json(),
                 "other version": audit_json(verified=[("dep", "1.0.2")]),
                 "other package": audit_json(verified=[("other", "1.0.3")]),
                 "no slsa": audit_json(verified=[("dep", "1.0.3")],
                                       predicate="https://example.invalid/other")}
        for label, output in cases.items():
            with self.subTest(case=label):
                npm, check = self.fix_setup(npm=FakeNpm(
                    extra={"dep": ("1.0.0", "sha512-d")}, audit=(0, output)))
                self.refused(2, npm=npm, check=check)
                self.assertFalse((self.root / "files").exists())

    def test_audit_signatures_invalid_or_missing_has_no_verdict(self):
        self.old_tree("1.2.2")
        self.lookups(continuity="same")
        for audit in (audit_json(verified=[(PKG, "1.2.3")], invalid=[{"name": "x"}]),
                      audit_json(verified=[(PKG, "1.2.3")], missing=[{"name": "x"}])):
            with self.subTest(audit=audit):
                self.refused(2, npm=FakeNpm(audit=(0, audit)),
                             fetch=FakeRegistry(ages={(PKG, "1.2.3"): 3}))
                self.assert_old_untouched()

    def test_audit_json_followed_by_npm_warnings_is_read(self):
        output = audit_json(verified=[("dep", "1.0.3")]) + "\nnpm warn config something odd\n"
        npm, check = self.fix_setup(npm=FakeNpm(extra={"dep": ("1.0.0", "sha512-d")},
                                                audit=(0, output)))
        installed = self.install(npm=npm, check=check)
        self.assertEqual([item["to"] for item in installed.fast_lane], ["1.0.3"])

    def test_plain_s2_install_runs_no_audit(self):
        npm = FakeNpm()
        installed = self.install(npm=npm)
        self.assertFalse(any(c[1] == "audit" for c in npm.commands))
        self.assertEqual((installed.tier, installed.fast_lane), ("s2", []))
        self.assertEqual(self.continuity_calls, [])


class TrustedPeriod(FastLaneBase):
    """S1: the top package may be younger than the waiting period (#48, 15.1)."""

    def s1_options(self, top_age=3):
        return {"fetch": FakeRegistry(ages={(PKG, "1.2.3"): top_age})}

    def s1_npm(self, **kwargs):
        kwargs.setdefault("etarget_unless_excluded", PKG)
        kwargs.setdefault("audit", (0, audit_json(verified=[(PKG, "1.2.3")])))
        return FakeNpm(**kwargs)

    def test_s1_top_package_with_same_provenance(self):
        self.lookups(continuity="same")
        self.old_tree("1.2.2")
        npm, check = self.s1_npm(), ScriptedCheck(lockcheck.Result(0, ["ok"]))
        installed = self.install(npm=npm, check=check, **self.s1_options())
        self.assertEqual(installed.tier, "s1")
        self.assertEqual(self.continuity_calls, [(PKG, "1.2.2", "1.2.3")])
        self.assertEqual(npm.seeds, [True])
        self.assertEqual(check.calls[0][1]["age_limits"], {("npm", PKG, "1.2.3"): 2})
        meta = json.loads((self.root / "files" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["tier"], "s1")
        self.assertTrue(any(c[1:3] == ["audit", "signatures"] for c in npm.commands))

    def test_s1_uses_release_age_exclude_for_the_top_package(self):
        self.lookups(continuity="same")
        self.old_tree("1.2.2")
        npm = self.s1_npm()
        self.install(npm=npm, **self.s1_options())
        resolution = next(c for c in npm.commands if c[1] == "install")
        self.assertIn("--min-release-age=7", resolution)
        self.assertIn(f"--min-release-age-exclude={PKG}", resolution)
        self.assertNotIn("--min-release-age=2", resolution)

    def test_s1_needs_previous_tree(self):
        self.lookups(continuity="same")
        exc = self.refused(2, npm=self.s1_npm(), **self.s1_options())
        self.assertIn("younger than 7 days", str(exc))
        self.assertEqual(self.continuity_calls, [])

    def test_s1_does_not_cover_dependencies(self):
        self.lookups(continuity="same")
        self.old_tree("1.2.2")
        young = lockcheck.Young(lockcheck.Entry("npm", "dep", "1.0.0"), stamp(3), 7, "2026-11-26")
        check = ScriptedCheck(lockcheck.Result(2, ["NO VERDICT -- dep is young"], [], [young], []))
        self.refused(2, npm=self.s1_npm(), check=check, **self.s1_options())
        self.assertEqual(check.calls[0][1]["age_limits"], {("npm", PKG, "1.2.3"): 2})
        self.assert_old_untouched()

    def test_s1_needs_an_npm_with_the_exclude_option(self):
        self.lookups(continuity="same")
        self.old_tree("1.2.2")
        npm = self.s1_npm(version="11.16.0")
        self.refused(2, npm=npm, **self.s1_options())
        self.assertFalse(any("--min-release-age-exclude=" + PKG in c for c in npm.commands))

    def test_s1_needs_the_same_repository(self):
        self.old_tree("1.2.2")
        for value in ("different", "missing", "failed", "none"):
            with self.subTest(continuity=value):
                self.lookups(continuity=value)
                npm = self.s1_npm()
                self.refused(2, npm=npm, **self.s1_options())
                self.assertFalse(any(a.startswith("--min-release-age-exclude")
                                     for c in npm.commands for a in c))
                self.assert_old_untouched()

    def test_old_top_package_needs_no_trusted_period(self):
        self.lookups(continuity="same")
        self.old_tree("1.2.2")
        installed = self.install(npm=FakeNpm(), **self.s1_options(top_age=30))
        self.assertEqual(installed.tier, "s2")
        self.assertEqual(self.continuity_calls, [])

    def test_old_metadata_of_other_package_gives_s2(self):
        self.lookups(continuity="same")
        variants = {"other package": {"package": "@scope/other"},
                    "before the tier field": {"with_tier": False},
                    "lockfile changed since": {"lock_matches": False}}
        for label, options in variants.items():
            with self.subTest(case=label):
                target = self.root / "files"
                if target.exists():
                    shutil.rmtree(target)
                self.old_tree("1.2.2", **options)
                npm = self.s1_npm()
                exc = self.refused(2, npm=npm, **self.s1_options())
                self.assertIn("younger than 7 days", str(exc))
                self.assertEqual(self.continuity_calls, [])
                self.assertEqual(npm.seeds, [False])


class JudgeTree(FastLaneBase):
    def judge(self, entries, advisories, check=None, **kwargs):
        opts = {"receipts_root": self.root, "kind": "npm", "user_overrides": {},
                "policy": fastlane.Policy(), "fetch": FakeRegistry(), "now": NOW,
                "check": check or ScriptedCheck(finding(*advisories))}
        opts.update(kwargs)
        return fastlane.judge_tree(entries, {}, **opts)

    def test_judge_tree_turns_any_exception_into_no_verdict(self):
        advisory = high_advisory()
        for exc in (KeyError("k"), TypeError("t"), ValueError("v")):
            with self.subTest(exception=type(exc).__name__):
                self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
                with mock.patch.object(fastlane, "gather", side_effect=exc):
                    verdict = self.judge([advisory.entry], [advisory])
                self.assertEqual(verdict.code, 2)
                self.assertEqual((verdict.decisions[0]["action"], verdict.decisions[0]["reason"]),
                                 ("no_verdict", "lookup_failed"))
                self.assertEqual(verdict.fixes, {})
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        for target in ("advisories_for", "kev_cves"):
            with self.subTest(lookup=target):
                with mock.patch.object(fastlane, target, side_effect=KeyError("shape")):
                    verdict = self.judge([advisory.entry], [advisory])
                self.assertEqual(verdict.code, 2)
                self.assertEqual(verdict.fixes, {})

    def test_two_instances_with_different_fixes_have_no_verdict(self):
        first = high_advisory(version="1.0.0", fixed="1.0.3")
        second = high_advisory(version="2.0.0", fixed="2.0.1", ident="GHSA-dddd-eeee-ffff")
        self.lookups(provenance={("dep", v): REPO for v in ("1.0.0", "1.0.3", "2.0.0", "2.0.1")})
        self.scan("dep", "1.0.3", "sha512-o")
        self.scan("dep", "2.0.1", "sha512-o")
        verdict = self.judge([first.entry, second.entry], [first, second])
        self.assertEqual(verdict.code, 2)
        self.assertEqual(verdict.fixes, {})
        self.assertTrue(any("several versions of dep need different fixes" in line
                            for line in verdict.lines))

    def test_unaffected_instance_of_the_same_name_has_no_verdict(self):
        affected = high_advisory(version="1.0.0")
        clean = lockcheck.Entry("npm", "dep", "2.0.0", integrity="sha512-e")
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", "sha512-o")
        verdict = self.judge([affected.entry, clean], [affected])
        self.assertEqual(verdict.code, 2)
        self.assertEqual(verdict.fixes, {})

    def test_judge_tree_returns_fix_and_receipt(self):
        advisory = high_advisory()
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", "sha512-o")
        verdict = self.judge([advisory.entry], [advisory])
        self.assertEqual(verdict.code, 0)
        version, found, decision = verdict.fixes["dep"]
        self.assertEqual((version, found.integrity, decision["tier"], decision["repo"]),
                         ("1.0.3", "sha512-o", "fast_lane", REPO))
        self.assertEqual(verdict.needs_scan, [])

    def test_judge_tree_keeps_a_finding_without_advisory(self):
        advisory = high_advisory()
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", "sha512-o")
        result = finding(advisory)
        result.blocking.append("other@1.0.0: locked integrity differs from the registry")
        verdict = self.judge([advisory.entry], [advisory], check=ScriptedCheck(result))
        self.assertEqual(verdict.code, 1)
        self.assertEqual((verdict.fixes, verdict.decisions), ({}, []))

    def test_judge_tree_young_entry_next_to_a_fix_waits(self):
        advisory = high_advisory()
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", "sha512-o")
        result = finding(advisory)
        result.young.append(lockcheck.Young(lockcheck.Entry("npm", "other", "1.0.0"),
                                            stamp(3), 7, "2026-11-26"))
        verdict = self.judge([advisory.entry], [advisory], check=ScriptedCheck(result))
        self.assertEqual(verdict.code, 2)
        self.assertEqual(verdict.fixes, {})

    def test_judge_tree_report_wins_over_no_verdict(self):
        reported = high_advisory()
        other = high_advisory(name="other", ident="GHSA-gggg-hhhh-iiii")
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing",
                                 ("other", "1.0.0"): REPO,
                                 ("other", "1.0.3"): lockcheck.LookupFailed("down", 500)})
        verdict = self.judge([reported.entry, other.entry], [reported, other])
        self.assertEqual(verdict.code, 1)

    def test_block_receipt_of_a_fix_is_a_finding(self):
        advisory = high_advisory()
        self.lookups(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        receipts.write_receipt(self.root, receipts.Receipt(
            kind="npm", package="dep", version="1.0.3", archive_sha256="cd" * 32,
            integrity="sha512-o", verdict="BLOCK", at="2026-11-22T00:00:00+00:00",
            agent_guard="0.5.2"))
        verdict = self.judge([advisory.entry], [advisory])
        self.assertEqual(verdict.code, 1)
        self.assertEqual(verdict.fixes, {})


class HelpTexts(unittest.TestCase):
    def help_of(self, mode):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "install_skill.py"),
                                 mode, "--help"], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return " ".join(result.stdout.split())

    def test_npm_options_describe_their_effect(self):
        text = self.help_of("mcp-npm")
        self.assertNotIn("Reserved", text)
        self.assertIn("--trusted-days", text)
        self.assertIn("--no-fast-lane", text)

    def test_pypi_options_describe_their_effect(self):
        text = self.help_of("mcp-pypi")
        self.assertNotIn("Reserved", text)
        self.assertIn("no trusted period", text)
        self.assertIn("Never rebuild the tree with a younger scanned security fix", text)

    def test_git_options_say_they_have_no_effect(self):
        text = self.help_of("mcp-git")
        self.assertNotIn("Reserved", text)
        self.assertIn("no effect for Git sources", text)


if __name__ == "__main__":
    unittest.main()
