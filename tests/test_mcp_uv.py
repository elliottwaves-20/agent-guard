"""Locked PyPI MCP installs (#48, A3): exact pin, checked uv.lock, no build.

uv is replaced by a fake runner that writes what the real tool would write:
`uv lock` a uv.lock, `uv sync` a .venv with the dist-info of the package. The
lockfile check is a stub. The installed wheel must be the scanned one.
"""
import datetime as dt
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
locked = importlib.import_module("_mcp_locked")
fastlane = importlib.import_module("_fastlane")
lockcheck = importlib.import_module("_lockcheck")
receipts = importlib.import_module("_mcp_receipts")
uv_mod = importlib.import_module("_mcp_uv")

PKG = "mcp-server-time"
WHEEL_SHA = "b" * 64
FILES = "https://files.pythonhosted.org/packages/xx"


def _package_block(pkg, version, wheels, sdist_sha, registry):
    dist = pkg.replace("-", "_").lower()
    wheel_lines = ", ".join(f'{{ url = "{FILES}/{n}", hash = "sha256:{h}" }}' for n, h in wheels)
    return (f'[[package]]\nname = "{pkg}"\nversion = "{version}"\n'
            f'source = {{ registry = "{registry}" }}\n'
            f'sdist = {{ url = "{FILES}/{dist}-{version}.tar.gz", hash = "sha256:{sdist_sha}" }}\n'
            f'wheels = [{wheel_lines}]\n')


def uv_lock(root, pkg, version, wheels=None, sdist_sha="a" * 64, registry="https://pypi.org/simple",
            extra=()):
    """extra: (name, version, wheels) of further locked registry packages."""
    dist = pkg.replace("-", "_").lower()
    if wheels is None:
        wheels = [(f"{dist}-{version}-py3-none-any.whl", WHEEL_SHA)]
    text = (f'version = 1\nrequires-python = ">=3.10"\n\n'
            f'[[package]]\nname = "{root}"\nversion = "0.0.0"\nsource = {{ virtual = "." }}\n'
            f'dependencies = [{{ name = "{pkg}" }}]\n\n'
            + _package_block(pkg, version, wheels, sdist_sha, registry))
    for other, other_version, other_wheels in extra:
        text += "\n" + _package_block(other, other_version, other_wheels, sdist_sha, registry)
    return text


class FakeUv:
    """Writes what uv would write. The pyproject decides: its override-dependencies replace
    the version of a transitive package (or drop it when uv backtracks around the override)."""

    def __init__(self, lock_rc=0, sync_rc=0, scripts=None, lock_version=None, wheels=None,
                 registry="https://pypi.org/simple", dist_version=None, lock_package=None,
                 extra=None, shas=None, override_wheels=None, backtrack=(), top_wheels=None,
                 override_versions=None):
        self.lock_rc = lock_rc
        self.sync_rc = sync_rc
        self.scripts = scripts
        self.lock_version = lock_version
        self.wheels = wheels
        self.registry = registry
        self.dist_version = dist_version
        self.lock_package = lock_package
        self.extra = dict(extra or {})  # name: version of further locked packages
        self.shas = dict(shas or {})  # (name, version): sha256 of the pure wheel
        self.override_wheels = dict(override_wheels or {})  # name: wheels after an override
        self.backtrack = set(backtrack)  # names uv drops instead of following the override
        self.top_wheels = list(top_wheels or [])  # wheels of the top package per lock run
        self.override_versions = dict(override_versions or {})  # name: version uv really locks
        self.commands = []
        self.pyprojects = []
        self.locks = 0

    def _pin(self, cwd):
        text = (Path(cwd) / "pyproject.toml").read_text(encoding="utf-8")
        line = next(ln for ln in text.splitlines() if ln.startswith("dependencies"))
        spec = line.split('"')[1]
        package, version = spec.split("==")
        root = next(ln for ln in text.splitlines() if ln.startswith("name")).split('"')[1]
        return root, package, version

    def _wheels(self, name, version):
        dist = name.replace("-", "_")
        return [(f"{dist}-{version}-py3-none-any.whl", self.shas.get((name, version), "e" * 64))]

    def _extra_entries(self, text):
        import tomllib
        packages = dict(self.extra)
        wheels = {}
        uv = tomllib.loads(text).get("tool", {}).get("uv", {})
        for spec in uv.get("override-dependencies", []):
            dep, _, wanted = spec.partition("==")
            if dep in self.backtrack:
                packages.pop(dep, None)
                continue
            packages[dep] = self.override_versions.get(dep, wanted)
            if dep in self.override_wheels:
                wheels[dep] = self.override_wheels[dep]
        return [(dep, ver, wheels.get(dep) or self._wheels(dep, ver))
                for dep, ver in packages.items()]

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        root, package, version = self._pin(cwd)
        norm = locked.normalize_pypi(package)
        if cmd[1] == "lock":
            text = (Path(cwd) / "pyproject.toml").read_text(encoding="utf-8")
            self.pyprojects.append(text)
            run, self.locks = self.locks, self.locks + 1
            if self.lock_rc:
                return self.lock_rc, "error: simulated"
            wheels = self.wheels
            if run < len(self.top_wheels):
                wheels = self.top_wheels[run]
            elif wheels is None and (norm, version) in self.shas:
                wheels = self._wheels(norm, version)
            (Path(cwd) / "uv.lock").write_text(
                uv_lock(root, self.lock_package or norm, self.lock_version or version,
                        wheels, registry=self.registry, extra=self._extra_entries(text)),
                encoding="utf-8")
            return 0, ""
        if cmd[1] == "sync":
            if self.sync_rc:
                return self.sync_rc, "error: simulated"
            dist = norm.replace("-", "_")
            info = (Path(cwd) / ".venv" / "Lib" / "site-packages"
                    / f"{dist}-{self.dist_version or version}.dist-info")
            info.mkdir(parents=True)
            scripts = self.scripts if self.scripts is not None else {norm: f"{dist}:main"}
            body = "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in scripts.items())
            (info / "entry_points.txt").write_text(body, encoding="utf-8")
            return 0, ""
        raise AssertionError(f"unexpected uv call {cmd}")


def stub_check(code):
    def check(entries, **_kwargs):
        check.entries = entries
        return lockcheck.Result(code, [f"stub result {code}"])
    check.entries = None
    return check


def which(name):
    return {"uv": "C:/uv/uv.exe"}.get(name)


def change_lock_after_sync(uv):
    def run(cmd, cwd):
        result = uv(cmd, cwd)
        if cmd[1] == "sync":
            lockfile = Path(cwd) / uv_mod.LOCKFILE
            lockfile.write_bytes(lockfile.read_bytes() + b"\n")
        return result
    return run


def receipt(package=PKG, version="1.2.3", sha=WHEEL_SHA):
    return receipts.Receipt(kind="pypi", package=package, version=version, archive_sha256=sha,
                            integrity="", verdict="SAFE", at="2026-11-22T00:00:00+00:00",
                            agent_guard="0.5.2", mode="full")


class PypiInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, uv=None, check=None, **kwargs):
        opts = {"name": "time", "package": PKG, "version": "1.2.3", "executable": None,
                "secrets": (), "root": self.root, "receipt": receipt(), "accepted": None,
                "run": uv if uv is not None else FakeUv(), "check": check or stub_check(0),
                "which": which}
        opts.update(kwargs)
        return uv_mod.pypi_install(**opts)

    def old_install(self):
        target = self.root / "time"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("old tree", encoding="utf-8")

    def assert_old_untouched(self):
        target = self.root / "time"
        self.assertEqual((target / "marker.txt").read_text(encoding="utf-8"), "old tree")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["time"])

    def test_lock_runs_without_builds_from_pypi_only(self):
        uv = FakeUv()
        self.install(uv=uv)
        lock = next(c for c in uv.commands if c[1] == "lock")
        self.assertIn("--no-build", lock)
        self.assertEqual(lock[lock.index("--default-index") + 1], "https://pypi.org/simple")

    def test_pyproject_pins_exactly_with_seven_day_window(self):
        self.install()
        lib = importlib.import_module("tomllib")
        data = lib.loads((self.root / "time" / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["dependencies"], [f"{PKG}==1.2.3"])
        self.assertEqual(data["project"]["name"], "mcp-time")
        self.assertEqual(data["tool"]["uv"], {"package": False, "exclude-newer": "7 days"})

    def test_pyproject_window_follows_the_setting(self):
        self.install(policy=fastlane.Policy(min_age_days=10))
        lib = importlib.import_module("tomllib")
        data = lib.loads((self.root / "time" / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["tool"]["uv"]["exclude-newer"], "10 days")

    def test_invalid_fast_lane_name_never_reaches_uv(self):
        invalid = f"dep&{chr(34)}%"
        stage = Path(self.tmp.name)
        for overrides, excludes in (({invalid: "1.0.3"}, {}),
                                    ({}, {invalid: "2026-11-22T12:00:00Z"})):
            with self.subTest(overrides=overrides, excludes=excludes):
                run = mock.Mock(return_value=(1, "unexpected uv call"))
                with self.assertRaisesRegex(locked.Refused, "invalid PyPI package name") as ctx:
                    uv_mod._lock(run, "uv", stage, name="time", package=PKG, version="1.2.3",
                                 overrides=overrides, excludes=excludes, min_age_days=7)
                self.assertEqual(ctx.exception.code, 2)
                run.assert_not_called()
                self.assertEqual(list(stage.iterdir()), [])

    def test_check_sees_the_registry_entries(self):
        check = stub_check(0)
        self.install(check=check)
        self.assertEqual([e.label for e in check.entries], [f"{PKG}@1.2.3"])

    def test_lockfile_finding_keeps_the_old_tree(self):
        self.old_install()
        uv = FakeUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, check=stub_check(1))
        self.assertEqual(ctx.exception.code, 1)
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assert_old_untouched()

    def test_lock_failure_keeps_the_old_tree(self):
        self.old_install()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=FakeUv(lock_rc=1))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_foreign_registry_has_no_verdict(self):
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=FakeUv(registry="https://evil.example/simple"))
        self.assertEqual(ctx.exception.code, 2)

    def test_sync_failure_restores_the_old_tree(self):
        self.old_install()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=FakeUv(sync_rc=1))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_sync_that_changes_the_lockfile_restores_the_old_pypi_tree(self):
        self.old_install()
        with self.assertRaisesRegex(locked.Refused, r"uv sync changed uv\.lock") as ctx:
            self.install(uv=change_lock_after_sync(FakeUv()))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_sync_is_locked_without_builds_in_the_target(self):
        uv = FakeUv()
        self.install(uv=uv)
        sync = next(c for c in uv.commands if c[1] == "sync")
        for flag in ("--locked", "--no-dev", "--no-build"):
            self.assertIn(flag, sync)

    def test_entry_starts_with_uv_run_locked(self):
        installed = self.install()
        target = self.root.resolve() / "time"
        self.assertEqual(installed.command, "C:/uv/uv.exe")
        self.assertEqual(installed.args, ["run", "--project", str(target), "--locked",
                                          "--no-dev", PKG])
        self.assertEqual(installed.tree, target)
        self.assertEqual(len(installed.lockfile_sha256), 64)
        meta = json.loads((target / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual((meta["kind"], meta["package"], meta["version"]), ("pypi", PKG, "1.2.3"))

    def test_entry_point_rules(self):
        two = {"alpha": "m:a", "beta": "m:b"}
        self.assertEqual(self.install(uv=FakeUv(scripts=two), executable="beta").args[-1], "beta")
        self.assertEqual(self.install(uv=FakeUv(scripts={"only": "m:a"})).args[-1], "only")
        self.assertEqual(self.install(uv=FakeUv(scripts={PKG: "m:a", "x": "m:b"})).args[-1], PKG)
        self.old_install_after_success()
        for uv, executable in ((FakeUv(scripts=two), None), (FakeUv(scripts=two), "gamma"),
                               (FakeUv(scripts={}), None)):
            with self.subTest(scripts=uv.scripts, executable=executable):
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, executable=executable)
                self.assertEqual(ctx.exception.code, 2)
                self.assert_old_untouched()

    def old_install_after_success(self):
        import shutil
        shutil.rmtree(self.root / "time")
        self.old_install()

    def test_installed_version_must_match_the_pin(self):
        self.old_install()
        with self.assertRaises(locked.Refused):
            self.install(uv=FakeUv(dist_version="9.9.9"))
        self.assert_old_untouched()

    def test_lock_with_another_top_level_version_is_refused(self):
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=FakeUv(lock_version="9.9.9"))
        self.assertEqual(ctx.exception.code, 2)

    def test_scanned_wheel_must_be_the_locked_one(self):
        uv = FakeUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, receipt=receipt(sha="c" * 64))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("scanned", str(ctx.exception))
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))

    def test_platform_or_several_wheels_have_no_verdict(self):
        cases = [[("mcp_server_time-1.2.3-cp312-cp312-win_amd64.whl", WHEEL_SHA)],
                 [("mcp_server_time-1.2.3-py3-none-any.whl", WHEEL_SHA),
                  ("mcp_server_time-1.2.3-cp312-cp312-win_amd64.whl", "d" * 64)],
                 []]
        for wheels in cases:
            with self.subTest(wheels=wheels):
                uv = FakeUv(wheels=wheels)
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertFalse(any(c[1] == "sync" for c in uv.commands))

    def test_mixed_case_package_name_matches(self):
        installed = self.install(package="Mcp_Server.Time", receipt=receipt(package=PKG))
        self.assertEqual(installed.args[-1], PKG)
        self.assertEqual(locked.default_name("pypi", "Mcp_Server.Time"), PKG)

    def test_receipt_for_another_package_is_refused(self):
        uv = FakeUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, receipt=receipt(package="other"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])

    def test_gitignore_excludes_venv(self):
        self.install()
        lines = (self.root / "time" / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".venv/", lines)

    def test_python_310_is_refused(self):
        uv = FakeUv()
        with mock.patch.object(locked.sys, "version_info", (3, 10, 12)):
            with self.assertRaises(locked.Refused) as ctx:
                self.install(uv=uv)
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])

    def test_invalid_input_is_refused_before_anything_runs(self):
        cases = [{"name": "a b"}, {"package": "x;y"}, {"version": ">=1.0"},
                 {"version": "1.0 "}, {"version": "1.0.0&calc"}, {"executable": "a b"},
                 {"secrets": ("lower",)}]
        for case in cases:
            with self.subTest(case=case):
                uv = FakeUv()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, **case)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(uv.commands, [])

    def test_missing_uv_is_refused(self):
        uv = FakeUv()
        with self.assertRaises(locked.Refused):
            self.install(uv=uv, which=lambda name: None)
        self.assertEqual(uv.commands, [])

    def test_update_replaces_the_old_tree(self):
        self.old_install()
        self.install()
        self.assertFalse((self.root / "time" / "marker.txt").exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["time"])

    def test_dry_run_writes_nothing(self):
        uv = FakeUv()
        with mock.patch("sys.stdout", new=io.StringIO()):
            installed = self.install(uv=uv, dry=True)
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())
        self.assertEqual(installed.command, "C:/uv/uv.exe")

    def test_dry_run_checks_the_resolved_lockfile_and_lists_each_entry(self):
        uv, check = FakeUv(extra={"anyio": "4.0.0"}), stub_check(0)
        out = io.StringIO()
        with mock.patch("sys.stdout", new=out):
            installed = self.install(uv=uv, check=check, dry=True)
        self.assertEqual(sorted(e.label for e in check.entries),
                         ["anyio@4.0.0", f"{PKG}@1.2.3"])
        self.assertIn(f"[DRY] clean: {PKG}@1.2.3", out.getvalue())
        self.assertIn("[DRY] clean: anyio@4.0.0", out.getvalue())
        self.assertTrue(any(c[1] == "lock" for c in uv.commands))
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())
        self.assertEqual(len(installed.lockfile_sha256), 64)

    def test_dry_run_with_a_finding_refuses_like_the_install(self):
        uv = FakeUv()
        out = io.StringIO()
        with mock.patch("sys.stdout", new=out), self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, check=stub_check(1), dry=True)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("stub result 1", out.getvalue())
        self.assertNotIn("[DRY] clean", out.getvalue())
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())

    def test_console_scripts_matches_normalised_names(self):
        venv = Path(self.tmp.name) / "venv"
        info = venv / "Lib" / "site-packages" / "Mcp_Server.Time-1.2.3.dist-info"
        info.mkdir(parents=True)
        (info / "entry_points.txt").write_text("[console_scripts]\nrun-it = m:main\n",
                                               encoding="utf-8")
        self.assertEqual(uv_mod.console_scripts(venv, PKG), {"run-it": "m:main"})

    def test_console_scripts_refuses_invalid_utf8(self):
        venv = Path(self.tmp.name) / "venv"
        info = venv / "Lib" / "site-packages" / "Mcp_Server.Time-1.2.3.dist-info"
        info.mkdir(parents=True)
        (info / "entry_points.txt").write_bytes(b"\xff")

        with self.assertRaises(locked.Refused) as caught:
            uv_mod.console_scripts(venv, PKG)

        self.assertEqual(caught.exception.code, 2)
        self.assertIn("entry_points.txt", str(caught.exception))


SHA = "a" * 40
GIT_URL = f"https://github.com/example/mcp@{SHA}"
GIT_PKG = "example-mcp"


def git_lock(root, sha=SHA, repo="https://github.com/example/mcp", query_extra=""):
    return (f'version = 1\nrequires-python = ">=3.10"\n\n'
            f'[[package]]\nname = "{root}"\nversion = "0.0.0"\nsource = {{ virtual = "." }}\n\n'
            f'[[package]]\nname = "{GIT_PKG}"\nversion = "0.1.0"\n'
            f'source = {{ git = "{repo}?{query_extra}rev={sha}#{sha}" }}\n'
            f'dependencies = [{{ name = "anyio" }}]\n\n'
            f'[[package]]\nname = "anyio"\nversion = "4.0.0"\n'
            f'source = {{ registry = "https://pypi.org/simple" }}\n'
            f'sdist = {{ url = "{FILES}/anyio-4.0.0.tar.gz", hash = "sha256:{"e" * 64}" }}\n'
            f'wheels = [{{ url = "{FILES}/anyio-4.0.0-py3-none-any.whl", hash = "sha256:{"f" * 64}" }}]\n')


def hashed(*pins):
    """`uv pip compile --generate-hashes` output for name==version pins."""
    return "".join(f"{pin} \\\n    --hash=sha256:{str(i) * 64}\n    # via -r build-requires.in\n"
                   for i, pin in enumerate(pins, 1))


class FakeGitUv:
    def __init__(self, compiled=None, lock_rc=0, lock_text=None, sync_rc=0, scripts=None,
                 version="uv 0.13.10 (e3e7c1eac 2026-11-24 x86_64-pc-windows-msvc)\n"):
        self.compiled = compiled if compiled is not None else hashed("setuptools==80.9.0")
        self.version = version
        self.lock_rc = lock_rc
        self.lock_text = lock_text
        self.sync_rc = sync_rc
        self.scripts = scripts
        self.commands = []

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        cwd = Path(cwd)
        if cmd[1:] == ["--version"]:
            return 0, self.version
        if cmd[1:3] == ["pip", "compile"]:
            self.requires = (cwd / cmd[3]).read_text(encoding="utf-8")
            out = cmd[cmd.index("-o") + 1]
            (cwd / out).write_text(self.compiled, encoding="utf-8")
            return 0, "Resolved 1 package"
        root = next(ln for ln in (cwd / "pyproject.toml").read_text(encoding="utf-8").splitlines()
                    if ln.startswith("name")).split('"')[1]
        if cmd[1] == "lock":
            if self.lock_rc:
                return self.lock_rc, "error: dynamic metadata needs a build"
            (cwd / "uv.lock").write_text(self.lock_text(root) if self.lock_text else git_lock(root),
                                         encoding="utf-8")
            return 0, ""
        if cmd[1] == "sync":
            if self.sync_rc:
                return self.sync_rc, "error: simulated"
            info = cwd / ".venv" / "Lib" / "site-packages" / "example_mcp-0.1.0.dist-info"
            info.mkdir(parents=True)
            scripts = self.scripts if self.scripts is not None else {"example-server": "ex:main"}
            body = "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in scripts.items())
            (info / "entry_points.txt").write_text(body, encoding="utf-8")
            return 0, ""
        raise AssertionError(f"unexpected uv call {cmd}")


def git_which(name):
    return {"uv": "C:/uv/uv.exe", "git": "C:/git/git.exe"}.get(name)


def git_receipt(package="example/mcp", version=SHA):
    return receipts.Receipt(kind="git", package=package, version=version,
                            archive_sha256="ab" * 32, integrity="", verdict="SAFE",
                            at="2026-11-22T00:00:00+00:00", agent_guard="0.5.2", mode="full")


class GitInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"
        self.fetched = []
        self.compared = []

    def tearDown(self):
        self.tmp.cleanup()

    def fetch_text(self, url):
        self.fetched.append(url)
        return '[project]\nname = "example-mcp"\n[build-system]\nrequires = ["hatchling>=1.20"]\n'

    def compare(self, status):
        def run(source, base, head):
            self.compared.append((source, base, head))
            return status
        return run

    def install(self, uv=None, check=None, status="behind", **kwargs):
        opts = {"name": "ex", "git_url": GIT_URL, "package": GIT_PKG, "executable": None,
                "module": None, "secrets": (), "root": self.root, "receipt": git_receipt(),
                "accepted": None, "scanned_dir": None,
                "run": uv if uv is not None else FakeGitUv(), "check": check or stub_check(0),
                "which": git_which, "fetch_text": self.fetch_text,
                "settled": lambda source, branch, head: ("c" * 40, None),
                "branch_head": lambda source: ("main", "d" * 40),
                "compare": self.compare(status),
                "root_names": lambda source, sha: ["pyproject.toml", "src"]}
        opts.update(kwargs)
        return uv_mod.git_install(**opts)

    def test_submodules_refuse_the_install_without_a_scanned_copy(self):
        """F1: an older receipt or a manual mcp-git call must not build a
        commit whose submodules uv would check out unscanned."""
        for name in (".gitmodules", ".GitModules"):
            with self.subTest(name=name):
                asked = []
                uv = FakeGitUv()

                def names(source, sha):
                    asked.append((source, sha))
                    return ["pyproject.toml", name]

                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, root_names=names)
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("submodule", str(ctx.exception))
                self.assertEqual(asked, [("example/mcp", SHA)])
                self.assertEqual(uv.commands, [])

    def test_submodules_in_the_scanned_copy_refuse_the_install(self):
        scanned = Path(self.tmp.name) / "scanned"
        scanned.mkdir()
        (scanned / "pyproject.toml").write_text('[project]\nname = "example-mcp"\n', encoding="utf-8")
        (scanned / ".gitmodules").write_text("", encoding="utf-8")
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, scanned_dir=scanned,
                         root_names=lambda *a: self.fail("the scanned copy is checked locally"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])

    def test_unlistable_scanned_copy_refuses_the_install(self):
        """The submodule check fails closed when the scanned copy cannot be listed."""
        scanned = Path(self.tmp.name) / "scanned"
        scanned.write_text("not a directory", encoding="utf-8")
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, scanned_dir=scanned,
                         root_names=lambda *a: self.fail("the scanned copy is checked locally"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("cannot list the scanned source", str(ctx.exception))
        self.assertEqual(uv.commands, [])

    def test_root_listing_fails_closed(self):
        for data in ({"message": "Not Found"}, [{"name": 1}], [{"name": "x"}] * 1000):
            with self.subTest(data=str(data)[:40]), \
                    mock.patch.object(uv_mod, "_github_json", return_value=data):
                with self.assertRaises(locked.Refused) as ctx:
                    uv_mod.github_root_names("example/mcp", SHA)
                self.assertEqual(ctx.exception.code, 2)
        with mock.patch.object(uv_mod, "_github_json",
                          return_value=[{"name": "a", "type": "file"}]) as get:
            self.assertEqual(uv_mod.github_root_names("example/mcp", SHA), ["a"])
        self.assertEqual(get.call_args.args[0],
                         f"https://api.github.com/repos/example/mcp/contents?ref={SHA}")

    def old_install(self):
        target = self.root / "ex"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("old tree", encoding="utf-8")

    def assert_old_untouched(self):
        self.assertEqual((self.root / "ex" / "marker.txt").read_text(encoding="utf-8"), "old tree")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["ex"])

    def test_clean_install_locks_the_scanned_commit(self):
        uv = FakeGitUv()
        installed = self.install(uv=uv)
        target = self.root.resolve() / "ex"
        self.assertEqual(installed.args, ["run", "--project", str(target), "--locked",
                                          "--no-dev", "example-server"])
        self.assertEqual((installed.kind, installed.requested), ("git", SHA))
        lib = importlib.import_module("tomllib")
        data = lib.loads((target / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["dependencies"],
                         [f"{GIT_PKG} @ git+https://github.com/example/mcp@{SHA}"])
        lock = next(c for c in uv.commands if c[1] == "lock")
        self.assertIn("--no-build", lock)
        self.assertEqual(self.compared, [("example/mcp", "c" * 40, SHA)])

    def test_only_github_full_sha_sources(self):
        for url in ("https://github.com/example/mcp@v1.0.0", "https://github.com/example/mcp@abc1234",
                    f"https://gitlab.com/example/mcp@{SHA}", f"http://github.com/example/mcp@{SHA}",
                    f"https://github.com/example/mcp@{SHA}#subdirectory=../x",
                    f"https://github.com/example/mcp@{SHA}#subdirectory=/abs"):
            with self.subTest(url=url):
                uv = FakeGitUv()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, git_url=url)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(uv.commands, [])

    def test_git_must_be_on_path(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, which=lambda n: None if n == "git" else git_which(n))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])
        self.assertEqual(self.compared, [])

    def test_commit_younger_than_settled_state_waits(self):
        for status in ("ahead", "diverged"):
            with self.subTest(status=status):
                uv = FakeGitUv()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, status=status)
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("7 days", str(ctx.exception))
                self.assertEqual(uv.commands, [])

    def test_git_commit_check_uses_the_configured_age(self):
        uv = FakeGitUv()
        ages = []

        def settled(source, branch, head, *, days):
            ages.append(days)
            return "c" * 40, None

        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, status="ahead", settled=settled,
                         policy=fastlane.Policy(min_age_days=10))
        self.assertEqual(ages, [10])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("10 days", str(ctx.exception))
        self.assertEqual(uv.commands, [])

    def test_identical_commit_is_settled(self):
        self.install(status="identical")

    def test_settled_lookup_failure_has_no_verdict(self):
        stage_error = importlib.import_module("_staging").StageError

        def broken(source, branch, head):
            raise stage_error("activity unavailable")
        with self.assertRaises(locked.Refused) as ctx:
            self.install(settled=broken)
        self.assertEqual(ctx.exception.code, 2)

    def test_build_constraints_are_checked_and_written(self):
        uv = FakeGitUv(compiled=hashed("hatchling==1.27.0", "pathspec==0.12.1"))
        checks = []

        def check(entries, **_kw):
            checks.append([(e.label, e.hashes, e.all_files) for e in entries])
            return lockcheck.Result(0, ["ok"])
        self.install(uv=uv, check=check)
        self.assertEqual(uv.requires.splitlines(), ["hatchling>=1.20"])
        self.assertEqual(checks[0], [("hatchling@1.27.0", ("1" * 64,), False),
                                     ("pathspec@0.12.1", ("2" * 64,), False)])
        compile_cmd = next(c for c in uv.commands if c[1:3] == ["pip", "compile"])
        for flag in ("--no-build", "--generate-hashes", "--exclude-newer", "7 days",
                     "--default-index"):
            self.assertIn(flag, compile_cmd)
        lib = importlib.import_module("tomllib")
        data = lib.loads((self.root / "ex" / "pyproject.toml").read_text(encoding="utf-8"))
        settings = data["tool"]["uv"]
        self.assertEqual(settings["build-constraint-dependencies"],
                         [{"requirement": "hatchling==1.27.0", "hashes": ["sha256:" + "1" * 64]},
                          {"requirement": "pathspec==0.12.1", "hashes": ["sha256:" + "2" * 64]}])
        self.assertIs(settings["require-build-hashes"], True)
        self.assertEqual(settings["preview-features"], ["build-dependency-hashes"])

    def test_unhashed_build_tools_have_no_verdict(self):
        uv = FakeGitUv(compiled="setuptools==80.9.0\n")
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("no SHA-256 hash", str(ctx.exception))
        self.assertFalse(any(c[1] == "lock" for c in uv.commands))

    def test_uv_without_build_hashes_is_refused_before_any_build(self):
        for version in ("uv 0.12.9 (abc 2026-10-01)\n", "uv 0.9.30\n", "not uv\n"):
            with self.subTest(version=version):
                uv = FakeGitUv(version=version)
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(uv.commands, [["C:/uv/uv.exe", "--version"]])
        self.install(uv=FakeGitUv(version="uv 0.13.0\n"))

    def test_git_build_constraints_follow_the_setting(self):
        uv = FakeGitUv()
        checks = []

        def check(entries, *, min_age_days, **kwargs):
            checks.append(([entry.label for entry in entries], min_age_days))
            return lockcheck.Result(0, ["ok"])

        self.install(uv=uv, check=check, policy=fastlane.Policy(min_age_days=10),
                     settled=lambda source, branch, head, **kwargs: ("c" * 40, None))
        compile_cmd = next(c for c in uv.commands if c[1:3] == ["pip", "compile"])
        self.assertEqual(compile_cmd[compile_cmd.index("--exclude-newer") + 1], "10 days")
        self.assertEqual(checks, [(["setuptools@80.9.0"], 10), (["anyio@4.0.0"], 10)])
        lib = importlib.import_module("tomllib")
        data = lib.loads((self.root / "ex" / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["tool"]["uv"]["exclude-newer"], "10 days")

    def test_build_constraint_finding_blocks(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, check=stub_check(1))
        self.assertEqual(ctx.exception.code, 1)
        self.assertFalse(any(c[1] == "lock" for c in uv.commands))

    def test_registry_check_preserves_exit_code_and_does_not_replace_git_tree(self):
        self.old_install()
        for code in (1, 2):
            with self.subTest(code=code):
                uv = FakeGitUv()
                check = mock.Mock(side_effect=[lockcheck.Result(0, []), lockcheck.Result(code, [])])
                with self.assertRaisesRegex(locked.Refused, "lockfile check for") as ctx:
                    self.install(uv=uv, check=check)
                self.assertEqual(ctx.exception.code, code)
                registry_entries = check.call_args.args[0]
                self.assertEqual([entry.label for entry in registry_entries], ["anyio@4.0.0"])
                self.assertFalse(any(c[1] == "sync" for c in uv.commands))
                self.assert_old_untouched()
                self.assertEqual(sorted(p.name for p in (self.root / "ex").iterdir()),
                                 ["marker.txt"])

    def test_sync_that_changes_the_lockfile_restores_the_old_git_tree(self):
        self.old_install()
        with self.assertRaisesRegex(locked.Refused, r"uv sync changed uv\.lock") as ctx:
            self.install(uv=change_lock_after_sync(FakeGitUv()))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_default_build_backend_without_build_system(self):
        self.assertEqual(uv_mod.build_requires('[project]\nname = "x"\n'), ["setuptools>=40.8.0"])
        self.assertEqual(uv_mod.build_requires('[build-system]\nrequires = ["flit_core>=3.4,<4"]\n'),
                         ["flit_core>=3.4,<4"])

    def test_build_requirement_cannot_smuggle_options(self):
        for text in ('[build-system]\nrequires = ["--index-url https://evil.example/simple"]\n',
                     '[build-system]\nrequires = ["evil @ https://evil.example/x.whl"]\n',
                     '[build-system]\nrequires = ["a\\nb"]\n',
                     '[build-system]\nrequires = "setuptools"\n'):
            with self.subTest(text=text):
                with self.assertRaises(locked.Refused) as ctx:
                    uv_mod.build_requires(text)
                self.assertEqual(ctx.exception.code, 2)

    def test_dynamic_metadata_has_no_verdict(self):
        self.old_install()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=FakeGitUv(lock_rc=1))
        self.assertEqual(ctx.exception.code, 2)
        self.assert_old_untouched()

    def test_foreign_git_entry_has_no_verdict(self):
        cases = [lambda root: git_lock(root, sha="b" * 40),
                 lambda root: git_lock(root, repo="https://github.com/evil/mcp"),
                 lambda root: git_lock(root, query_extra="subdirectory=x&")]
        for lock_text in cases:
            with self.subTest():
                uv = FakeGitUv(lock_text=lock_text)
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertFalse(any(c[1] == "sync" for c in uv.commands))

    def test_sync_names_every_registry_package_for_no_build(self):
        uv = FakeGitUv()
        self.install(uv=uv)
        sync = next(c for c in uv.commands if c[1] == "sync")
        self.assertEqual(sync[:6], ["C:/uv/uv.exe", "sync", "--locked", "--no-dev",
                                    "--no-cache", "--no-build-package"])
        pairs = [sync[i + 1] for i, a in enumerate(sync) if a == "--no-build-package"]
        self.assertEqual(pairs, ["anyio"])
        self.assertNotIn("--no-build", sync)

    def test_sync_failure_restores_the_old_tree(self):
        self.old_install()
        with self.assertRaises(locked.Refused):
            self.install(uv=FakeGitUv(sync_rc=1))
        self.assert_old_untouched()

    def test_module_start(self):
        installed = self.install(module="example.server")
        self.assertEqual(installed.args[-4:], ["--no-dev", "python", "-m", "example.server"])

    def test_executable_and_module_exclude_each_other(self):
        with self.assertRaises(locked.Refused):
            self.install(module="m", executable="e")

    def test_scanned_dir_is_preferred_over_download(self):
        scanned = Path(self.tmp.name) / "scanned"
        scanned.mkdir()
        (scanned / "pyproject.toml").write_text('[project]\nname = "example-mcp"\n', encoding="utf-8")
        uv = FakeGitUv()
        self.install(uv=uv, scanned_dir=scanned)
        self.assertEqual(self.fetched, [])
        self.assertEqual(uv.requires.splitlines(), ["setuptools>=40.8.0"])

    def test_download_uses_the_scanned_commit_and_subdirectory(self):
        url = f"https://github.com/example/mcp@{SHA}#subdirectory=servers/ex"
        uv = FakeGitUv(lock_text=lambda root: git_lock(root, query_extra="subdirectory=servers/ex&"))
        self.install(uv=uv, git_url=url, receipt=git_receipt(package="example/mcp"))
        self.assertEqual(self.fetched, [f"https://raw.githubusercontent.com/example/mcp/{SHA}/"
                                        "servers/ex/pyproject.toml"])

    def test_git_records_the_checked_url_with_subdirectory(self):
        url = f"{GIT_URL}#subdirectory=servers/ex"
        uv = FakeGitUv(lock_text=lambda root: git_lock(root, query_extra="subdirectory=servers/ex&"))
        installed = self.install(uv=uv, git_url=url)
        self.assertEqual(installed.source, url)

    def test_whole_repository_scan_covers_a_subdirectory(self):
        url = f"https://github.com/example/mcp@{SHA}#subdirectory=servers/ex"
        uv = FakeGitUv(lock_text=lambda root: git_lock(root, query_extra="subdirectory=servers/ex&"))
        for scanned in ("example/mcp", "Example/MCP"):
            with self.subTest(scanned=scanned):
                self.install(uv=uv, git_url=url, receipt=git_receipt(package=scanned))

    def test_narrower_or_other_scan_does_not_cover_the_install(self):
        # F1: uv builds from the whole checkout, so even a scan of the exact
        # subdirectory or a parent does not cover the build.
        sub = f"https://github.com/example/mcp@{SHA}#subdirectory=servers/ex"
        cases = [(GIT_URL, "example/mcp#servers"),
                 (sub, "example/mcp#servers/other"),
                 (sub, "example/mcp#servers/ex"),
                 (sub, "Example/MCP#servers"),
                 (sub, "example/other"),
                 (f"https://github.com/example/mcp@{SHA}#subdirectory=servers",
                  "example/mcp#servers/ex")]
        for url, scanned in cases:
            with self.subTest(url=url, scanned=scanned):
                uv = FakeGitUv()
                with self.assertRaises(locked.Refused) as ctx:
                    self.install(uv=uv, git_url=url, receipt=git_receipt(package=scanned))
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(uv.commands, [])

    def test_receipt_must_be_for_this_commit(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, receipt=git_receipt(version="b" * 40))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])

    def test_dry_run_writes_nothing(self):
        uv = FakeGitUv()
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.install(uv=uv, dry=True)
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())

    def test_dry_run_checks_commit_and_lockfile_and_lists_each_entry(self):
        uv, check = FakeGitUv(), stub_check(0)
        out = io.StringIO()
        with mock.patch("sys.stdout", new=out):
            installed = self.install(uv=uv, check=check, dry=True)
        self.assertTrue(self.compared)  # the commit age is checked, as on install
        self.assertIn("anyio@4.0.0", [e.label for e in check.entries])
        self.assertIn("[DRY] clean: anyio@4.0.0", out.getvalue())
        self.assertTrue(any(c[1] == "lock" for c in uv.commands))
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())
        self.assertEqual(len(installed.lockfile_sha256), 64)

    def test_dry_run_with_a_finding_refuses_like_the_install(self):
        uv = FakeGitUv()
        out = io.StringIO()
        with mock.patch("sys.stdout", new=out), self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, check=stub_check(1), dry=True)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("stub result 1", out.getvalue())
        self.assertNotIn("[DRY] clean", out.getvalue())
        self.assertFalse(any(c[1] == "sync" for c in uv.commands))
        self.assertFalse(self.root.exists())

    def test_dry_run_refuses_submodules_like_the_install(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, dry=True,
                         root_names=lambda source, sha: ["pyproject.toml", ".gitmodules"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertFalse(self.root.exists())


class GitCli(unittest.TestCase):
    def test_git_notes_fast_lane_options(self):
        install_skill = importlib.import_module("install_skill")
        argv = ["install_skill.py", "mcp-git", "--name", "ex", "--git-url", GIT_URL,
                "--package", GIT_PKG]
        for options in ([], ["--trusted-days", "2"], ["--no-fast-lane"]):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                config = {"mcp": {"install_dir": tmp}}
                stderr = io.StringIO()
                with (mock.patch.object(sys, "argv", argv + options),
                      mock.patch.object(install_skill._skillspector, "USER_CONFIG", config),
                      redirect_stderr(stderr), redirect_stdout(io.StringIO()),
                      self.assertRaises(SystemExit) as ctx):
                    install_skill.main()
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("scan first", stderr.getvalue())
                self.assertEqual("note: no effect for Git sources" in stderr.getvalue(),
                                 bool(options))


class PypiCli(unittest.TestCase):
    def test_missing_receipt_runs_nothing(self):
        import argparse
        install_skill = importlib.import_module("install_skill")
        uv = FakeUv()
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(package=PKG, version="1.2.3", name=None, executable=None,
                                      secret=[], accept=None, tools=None, dry_run=False)
            with self.assertRaises(locked.Refused) as ctx:
                install_skill.cmd_mcp_pypi(args, config={"mcp": {"install_dir": tmp}}, env={},
                                           platform="win32", run=uv, which=which,
                                           check=stub_check(0),
                                           deliver=lambda *a, **k: self.fail("delivered"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("scan first", str(ctx.exception))
        self.assertEqual(uv.commands, [])


NOW = dt.datetime(2026, 11, 22, 12, 0, tzinfo=dt.timezone.utc)
REPO = "github.com/o/r"
OLD_SHA = "e" * 64  # pure wheel of the vulnerable dependency
FIX_SHA = "f" * 64  # pure wheel of the scanned fix
TOP_FIX_SHA = "9" * 64  # pure wheel of the fixed top-level package
GHSA = "GHSA-aaaa-bbbb-cccc"


def stamp(days):
    return (NOW - dt.timedelta(days=days)).isoformat().replace("+00:00", "Z")


class FakePyPI:
    """Answers the PyPI JSON of any release (no network); every release is old unless listed."""

    def __init__(self, ages=None, default_days=100):
        self.ages = dict(ages or {})  # (name, version): days since the upload
        self.default_days = default_days
        self.requests = []

    def __call__(self, url, payload=None):
        prefix = "https://pypi.org/pypi/"
        if not url.startswith(prefix) or not url.endswith("/json"):
            raise AssertionError(f"unexpected request: {url}")
        self.requests.append(url)
        name, version = url[len(prefix):-len("/json")].split("/")
        days = self.ages.get((name, version), self.default_days)
        return {"urls": [{"filename": f"{name}-{version}-py3-none-any.whl",
                          "upload_time_iso_8601": stamp(days)}]}, None


class ScriptedCheck:
    """Returns the scripted results one by one (the last one repeats) and records calls."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, entries, **kwargs):
        self.calls.append((list(entries), kwargs))
        return self.results[min(len(self.calls) - 1, len(self.results) - 1)]


def locked_files(name, version, sha=OLD_SHA):
    dist = name.replace("-", "_")
    return ((f"{dist}-{version}.tar.gz", "a" * 64), (f"{dist}-{version}-py3-none-any.whl", sha))


def pypi_advisory(name="dep", version="1.0.0", fixed="1.0.3", ident=GHSA, severity="high",
                  files=None):
    entry = lockcheck.Entry("PyPI", name, version,
                            files=files if files is not None else locked_files(name, version))
    interval = {"lower": None, "lower_inclusive": True, "upper": fixed,
                "upper_inclusive": False, "fixed": fixed}
    return lockcheck.Advisory(entry, ident, "github-reviewed", aliases=("CVE-2026-0001",),
                              severity=severity, affected=(interval,))


def finding(*advisories, failures=()):
    lines = [f"[BLOCK] lockfile finding: {a.id}" for a in advisories]
    return lockcheck.Result(1, lines, list(advisories), [], list(failures))


class PypiFastLaneBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"
        self.installed_files = []
        self.stderr = ""

    def tearDown(self):
        self.tmp.cleanup()

    def lookups(self, provenance=None, kev=frozenset(), files=None):
        """Fixed answers for KEV, fix advisories, provenance and files (no network)."""
        table = dict(provenance if provenance is not None else {
            ("dep", "1.0.0"): REPO, ("dep", "1.0.3"): REPO})
        listed = dict(files or {})

        def answer(key):
            value = table[key]
            if isinstance(value, Exception):
                raise value
            return value

        def pypi_provenance(name, version, installed, fetch):
            self.installed_files.append((name, version, tuple(installed)))
            return answer((name, version))

        def pypi_files(path, fetch):
            name, version = path.split("/")
            default = {f"{name.replace('-', '_')}-{version}-py3-none-any.whl": FIX_SHA}
            return dict(listed.get((name, version), default))

        def file_provenance(path, filename, digest, fetch):
            name, version = path.split("/")
            return answer((name, version))

        for target, replacement in (("kev_cves", lambda fetch: kev),
                                    ("advisories_for", lambda entries, fetch=None: ([], [])),
                                    ("pypi_provenance", pypi_provenance),
                                    ("_pypi_files", pypi_files),
                                    ("_pypi_file_provenance", file_provenance)):
            patcher = mock.patch.object(fastlane, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, name, version, sha, verdict="SAFE"):
        receipts.write_receipt(self.root, receipts.Receipt(
            kind="pypi", package=name, version=version, archive_sha256=sha, integrity="",
            verdict=verdict, at="2026-11-22T00:00:00+00:00", agent_guard="0.5.2",
            mode="full"))

    def install(self, uv=None, check=None, **kwargs):
        opts = {"name": "time", "package": PKG, "version": "1.2.3", "executable": None,
                "secrets": (), "root": self.root, "receipt": receipt(), "accepted": None,
                "run": uv if uv is not None else FakeUv(), "check": check or stub_check(0),
                "which": which, "fetch": FakePyPI(), "now": NOW}
        opts.update(kwargs)
        buffer = io.StringIO()
        with mock.patch.object(sys, "stderr", buffer):
            try:
                return uv_mod.pypi_install(**opts)
            finally:
                self.stderr = buffer.getvalue()

    def refused(self, code, **kwargs):
        with self.assertRaises(locked.Refused) as ctx:
            self.install(**kwargs)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))
        return ctx.exception

    def old_install(self):
        target = self.root / "time"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("old tree", encoding="utf-8")

    def assert_old_untouched(self):
        target = self.root / "time"
        self.assertEqual((target / "marker.txt").read_text(encoding="utf-8"), "old tree")
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.name != ".receipts"),
                         ["time"])

    def uv_table(self, index):
        import tomllib
        return tomllib.loads(self.uv.pyprojects[index])["tool"]["uv"]

    def locks_of(self, uv):
        return [c for c in uv.commands if c[1] == "lock"]

    def syncs_of(self, uv):
        return [c for c in uv.commands if c[1] == "sync"]


class PypiFastLane(PypiFastLaneBase):
    """Security fixes that are younger than the waiting period in PyPI trees (#48, 15.2)."""

    def fix_setup(self, provenance=None, scanned=True, files=None, **uv_options):
        self.lookups(provenance=provenance, files=files)
        if scanned:
            self.scan("dep", "1.0.3", FIX_SHA)
        uv_options.setdefault("extra", {"dep": "1.0.0"})
        uv_options.setdefault("shas", {("dep", "1.0.3"): FIX_SHA})
        self.uv = FakeUv(**uv_options)
        check = ScriptedCheck(finding(pypi_advisory()), lockcheck.Result(0, ["ok"]))
        return self.uv, check

    def test_pypi_fast_lane_installs_scanned_pure_wheel(self):
        uv, check = self.fix_setup()
        installed = self.install(uv=uv, check=check)
        expected = [{"package": "dep", "from": "1.0.0", "to": "1.0.3", "advisories": [GHSA],
                     "repo": REPO, "receipt_sha256": FIX_SHA, "tier": "fast_lane"}]
        self.assertEqual(installed.fast_lane, expected)
        self.assertEqual(installed.overrides, {"dep": "1.0.3"})
        self.assertEqual(installed.override_reason, f"agent-guard fast lane: {GHSA}")
        self.assertEqual(installed.tier, "s2")
        meta = json.loads((self.root / "time" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["fast_lane"], expected)
        self.assertEqual(meta["overrides"], {"dep": "1.0.3"})
        self.assertEqual(meta["override_reason"], f"agent-guard fast lane: {GHSA}")
        self.assertEqual(len(self.locks_of(uv)), 2)
        self.assertEqual(len(self.syncs_of(uv)), 1)
        self.assertEqual(check.calls[1][1]["age_limits"], {("PyPI", "dep", "1.0.3"): 0})
        self.assertIn(f"fast lane: dep 1.0.0 -> 1.0.3 ({GHSA}, provenance {REPO}, "
                      f"receipt {FIX_SHA})", self.stderr)
        self.assertEqual(installed.args[-1], PKG)

    def test_pypi_rebuild_pyproject_has_override_and_exclude_newer_package(self):
        uv, check = self.fix_setup()
        self.install(uv=uv, check=check)
        self.assertEqual(self.uv_table(0), {"package": False, "exclude-newer": "7 days"})
        self.assertEqual(self.uv_table(1), {
            "package": False, "exclude-newer": "7 days",
            "override-dependencies": ["dep==1.0.3"],
            "exclude-newer-package": {"dep": "2026-11-22T12:00:00Z"}})

    def test_pypi_fix_without_pure_wheel_reports(self):
        self.old_install()
        platform_only = {("dep", "1.0.3"): {"dep-1.0.3-cp312-cp312-win_amd64.whl": FIX_SHA}}
        uv, check = self.fix_setup(files=platform_only)
        exc = self.refused(1, uv=uv, check=check)
        self.assertIn("no_pure_wheel", str(exc) + self.stderr)
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_only_sdist_reports(self):
        self.old_install()
        uv, check = self.fix_setup(files={("dep", "1.0.3"): {"dep-1.0.3.tar.gz": "a" * 64}})
        self.refused(1, uv=uv, check=check)
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_with_platform_wheels_has_no_verdict(self):
        self.old_install()
        wheels = [("dep-1.0.3-py3-none-any.whl", FIX_SHA),
                  ("dep-1.0.3-cp312-cp312-win_amd64.whl", "d" * 64)]
        uv, check = self.fix_setup(override_wheels={"dep": wheels})
        exc = self.refused(2, uv=uv, check=check)
        self.assertIn("exactly one pure wheel", str(exc))
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_wheel_must_be_the_scanned_one(self):
        self.old_install()
        uv, check = self.fix_setup(shas={("dep", "1.0.3"): "c" * 64})
        exc = self.refused(2, uv=uv, check=check)
        self.assertIn("scanned", str(exc))
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_missing_from_final_lock_has_no_verdict(self):
        self.old_install()
        uv, check = self.fix_setup(backtrack={"dep"})
        exc = self.refused(2, uv=uv, check=check)
        self.assertIn("dep==1.0.3", str(exc))
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_at_another_version_in_final_lock_has_no_verdict(self):
        self.old_install()
        uv, check = self.fix_setup(override_versions={"dep": "1.0.2"})
        self.refused(2, uv=uv, check=check)
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_needs_scan_lists_pypi_commands(self):
        self.old_install()
        uv, check = self.fix_setup(scanned=False)
        exc = self.refused(2, uv=uv, check=check)
        self.assertIsInstance(exc, locked.NeedsScan)
        self.assertEqual(exc.items, [{"kind": "pypi", "package": "dep", "version": "1.0.3"}])
        self.assertIn("python scripts/scan_url.py https://pypi.org/project/dep/1.0.3", str(exc))
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assert_old_untouched()

    def test_pypi_block_receipt_of_a_fix_is_a_finding(self):
        uv, check = self.fix_setup(scanned=False)
        self.scan("dep", "1.0.3", FIX_SHA, verdict="BLOCK")
        self.refused(1, uv=uv, check=check)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_missing_provenance_reports_with_override_hint(self):
        uv, check = self.fix_setup(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing"})
        exc = self.refused(1, uv=uv, check=check)
        self.assertIn("--override dep=1.0.3", str(exc) + self.stderr)
        self.assertIn("--override-reason", str(exc) + self.stderr)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_provenance_lookup_failure_has_no_verdict(self):
        failed = lockcheck.LookupFailed("index down", 500)
        uv, check = self.fix_setup(provenance={("dep", "1.0.0"): REPO, ("dep", "1.0.3"): failed})
        self.refused(2, uv=uv, check=check)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_no_fast_lane_option_reports(self):
        uv, check = self.fix_setup(scanned=False)
        self.refused(1, uv=uv, check=check, policy=fastlane.policy(None, None, True))
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_lookup_failure_next_to_fixable_finding_blocks_rebuild(self):
        uv, _ = self.fix_setup()
        check = ScriptedCheck(finding(pypi_advisory(), failures=["GitHub reviewed: unreadable"]))
        self.refused(2, uv=uv, check=check)
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(self.syncs_of(uv), [])

    def test_pypi_kev_unavailable_blocks_fast_lane(self):
        uv, check = self.fix_setup()
        self.lookups(kev=None)
        self.refused(2, uv=uv, check=check)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_young_dependency_of_the_rebuild_waits(self):
        self.old_install()
        uv, _ = self.fix_setup()
        young = lockcheck.Young(lockcheck.Entry("PyPI", "newdep", "2.0.0"), stamp(1), 7,
                                "2026-11-28")
        check = ScriptedCheck(finding(pypi_advisory()),
                              lockcheck.Result(2, ["NO VERDICT -- newdep young"], [], [young], []))
        self.refused(2, uv=uv, check=check)
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_rebuild_checks_top_wheel(self):
        self.old_install()
        top = "mcp_server_time-1.2.3-py3-none-any.whl"
        uv, check = self.fix_setup(top_wheels=[[(top, WHEEL_SHA)], [(top, "c" * 64)]])
        exc = self.refused(2, uv=uv, check=check)
        self.assertIn("scanned", str(exc))
        self.assertEqual(self.syncs_of(uv), [])
        self.assert_old_untouched()

    def test_pypi_fix_of_top_package_pins_the_fix_version(self):
        self.lookups(provenance={(PKG, "1.2.3"): REPO, (PKG, "1.2.4"): REPO})
        self.scan(PKG, "1.2.4", TOP_FIX_SHA)
        self.uv = uv = FakeUv(shas={(PKG, "1.2.4"): TOP_FIX_SHA})
        advisory = pypi_advisory(name=PKG, version="1.2.3", fixed="1.2.4",
                                 files=locked_files(PKG, "1.2.3", WHEEL_SHA))
        check = ScriptedCheck(finding(advisory), lockcheck.Result(0, ["ok"]))
        installed = self.install(uv=uv, check=check)
        data = self.uv_table(1)
        self.assertEqual(tomllib_dependencies(self.uv.pyprojects[1]), [f"{PKG}==1.2.4"])
        self.assertNotIn("override-dependencies", data)
        self.assertEqual(data["exclude-newer-package"], {PKG: "2026-11-22T12:00:00Z"})
        self.assertEqual(installed.requested, "1.2.4")
        self.assertEqual((installed.overrides, installed.override_reason), ({}, None))
        meta = json.loads((self.root / "time" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual((meta["version"], meta["overrides"]), ("1.2.4", {}))
        self.assertEqual((installed.fast_lane[0]["from"], installed.fast_lane[0]["to"]),
                         ("1.2.3", "1.2.4"))
        self.assertEqual(installed.fast_lane[0]["receipt_sha256"], TOP_FIX_SHA)
        self.assertEqual(check.calls[1][1]["age_limits"], {("PyPI", PKG, "1.2.4"): 0})
        self.assertEqual(installed.args[-1], PKG)

    def test_pypi_fix_of_top_package_must_be_the_installed_version(self):
        self.lookups(provenance={(PKG, "1.2.3"): REPO, (PKG, "1.2.4"): REPO})
        self.scan(PKG, "1.2.4", TOP_FIX_SHA)
        advisory = pypi_advisory(name=PKG, version="1.2.3", fixed="1.2.4",
                                 files=locked_files(PKG, "1.2.3", WHEEL_SHA))
        check = ScriptedCheck(finding(advisory), lockcheck.Result(0, ["ok"]))
        uv = FakeUv(shas={(PKG, "1.2.4"): TOP_FIX_SHA}, dist_version="1.2.3")
        self.old_install()
        self.refused(2, uv=uv, check=check)
        self.assert_old_untouched()

    def test_pypi_top_fix_wheel_must_be_the_scanned_one(self):
        self.lookups(provenance={(PKG, "1.2.3"): REPO, (PKG, "1.2.4"): REPO})
        self.scan(PKG, "1.2.4", TOP_FIX_SHA)
        advisory = pypi_advisory(name=PKG, version="1.2.3", fixed="1.2.4",
                                 files=locked_files(PKG, "1.2.3", WHEEL_SHA))
        check = ScriptedCheck(finding(advisory), lockcheck.Result(0, ["ok"]))
        uv = FakeUv(shas={(PKG, "1.2.4"): "c" * 64})
        exc = self.refused(2, uv=uv, check=check)
        self.assertIn("scanned", str(exc))
        self.assertEqual(self.syncs_of(uv), [])


def tomllib_dependencies(pyproject_text):
    return importlib.import_module("tomllib").loads(pyproject_text)["project"]["dependencies"]


class PypiTiers(PypiFastLaneBase):
    """PyPI has no trusted period (S1): the top package waits like every other entry."""

    def test_pypi_has_no_trusted_period(self):
        self.old_install()
        young = lockcheck.Young(lockcheck.Entry("PyPI", PKG, "1.2.3"), stamp(3), 7, "2026-11-26")
        check = ScriptedCheck(lockcheck.Result(2, ["NO VERDICT -- top package young"], [],
                                               [young], []))
        self.uv = uv = FakeUv()
        with mock.patch.object(fastlane, "continuity", side_effect=AssertionError("S1 asked")):
            self.refused(2, uv=uv, check=check, fetch=FakePyPI(ages={(PKG, "1.2.3"): 3}))
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(self.uv_table(0), {"package": False, "exclude-newer": "7 days"})
        self.assertEqual(check.calls[0][1]["age_limits"], None)
        self.assert_old_untouched()

    def test_pypi_plain_install_is_s2_without_fast_lane(self):
        installed = self.install()
        self.assertEqual((installed.tier, installed.fast_lane, installed.overrides),
                         ("s2", [], {}))


class PypiUserOverrides(PypiFastLaneBase):
    def override_setup(self, provenance, name="dep", fix_name=None):
        fix_name = fix_name or name
        self.lookups(provenance=provenance)
        self.scan(fix_name, "1.0.3", FIX_SHA)
        self.uv = FakeUv(extra={fix_name: "1.0.0"}, shas={(fix_name, "1.0.3"): FIX_SHA})
        check = ScriptedCheck(finding(pypi_advisory(name=fix_name)), lockcheck.Result(0, ["ok"]))
        options = {"fetch": FakePyPI(ages={(fix_name, "1.0.3"): 3})}
        return self.uv, check, options

    def test_pypi_user_override_rules(self):
        for label, options in {
                "no reason": {"overrides": {"dep": "1.0.3"}},
                "blank reason": {"overrides": {"dep": "1.0.3"}, "override_reason": "  "},
                "range": {"overrides": {"dep": ">=1.0"}, "override_reason": "r"},
                "local version": {"overrides": {"dep": "1.0.3+local"}, "override_reason": "r"},
                "bad name": {"overrides": {"d;ep": "1.0.3"}, "override_reason": "r"},
                "name twice": {"overrides": {"dep": "1.0.3", "Dep": "1.0.3"},
                               "override_reason": "r"}}.items():
            with self.subTest(case=label):
                uv = FakeUv()
                self.refused(2, uv=uv, **options)
                self.assertEqual(uv.commands, [])
        uv, check, options = self.override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "missing"})
        installed = self.install(uv=uv, check=check, overrides={"dep": "1.0.3"},
                                 override_reason="own reason", **options)
        self.assertEqual([item["tier"] for item in installed.fast_lane], ["override"])
        self.assertEqual(installed.overrides, {"dep": "1.0.3"})
        self.assertEqual(installed.override_reason, f"own reason; agent-guard fast lane: {GHSA}")
        meta = json.loads((self.root / "time" / locked.METADATA).read_text(encoding="utf-8"))
        self.assertEqual(meta["overrides"], {"dep": "1.0.3"})
        self.assertEqual(meta["override_reason"], f"own reason; agent-guard fast lane: {GHSA}")
        self.assertNotIn("override-dependencies", self.uv_table(0))
        self.assertEqual(self.uv_table(1)["override-dependencies"], ["dep==1.0.3"])

    def test_pypi_override_does_not_help_a_failed_lookup(self):
        failed = lockcheck.LookupFailed("index down", 500)
        uv, check, options = self.override_setup({("dep", "1.0.0"): REPO, ("dep", "1.0.3"): failed})
        self.refused(2, uv=uv, check=check, overrides={"dep": "1.0.3"}, override_reason="r",
                     **options)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_override_does_not_help_a_changed_repo(self):
        uv, check, options = self.override_setup(
            {("dep", "1.0.0"): REPO, ("dep", "1.0.3"): "github.com/x/y"})
        self.refused(1, uv=uv, check=check, overrides={"dep": "1.0.3"}, override_reason="r",
                     **options)
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_pending_override_without_advisory_waits(self):
        uv = FakeUv()
        exc = self.refused(2, uv=uv, overrides={"dep": "1.0.3"}, override_reason="r",
                           fetch=FakePyPI(ages={("dep", "1.0.3"): 3}))
        self.assertIn("younger than 7 days", str(exc))
        self.assertIn("2026-11-26", str(exc))
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(self.syncs_of(uv), [])

    def test_pypi_old_override_is_applied_at_once(self):
        uv = FakeUv(extra={"dep": "1.0.0"})
        installed = self.install(uv=uv, overrides={"dep": "1.0.3"}, override_reason="pinned",
                                 fetch=FakePyPI(ages={("dep", "1.0.3"): 30}))
        self.assertEqual(len(self.locks_of(uv)), 1)
        self.assertEqual(installed.overrides, {"dep": "1.0.3"})
        self.assertEqual(installed.override_reason, "pinned")
        self.assertEqual(installed.fast_lane, [])
        import tomllib
        table = tomllib.loads(uv.pyprojects[0])["tool"]["uv"]
        self.assertEqual(table["override-dependencies"], ["dep==1.0.3"])
        self.assertNotIn("exclude-newer-package", table)

    def test_pypi_override_lookup_failure_has_no_verdict(self):
        def broken(url, payload=None):
            raise lockcheck.LookupFailed("index down", 500)

        uv = FakeUv()
        self.refused(2, uv=uv, overrides={"dep": "1.0.3"}, override_reason="r", fetch=broken)
        self.assertEqual(uv.commands, [])

    def test_pypi_conflicting_override_is_refused(self):
        self.lookups(provenance={("dep", "1.0.1"): REPO, ("dep", "1.0.3"): REPO})
        self.scan("dep", "1.0.3", FIX_SHA)
        uv = FakeUv(extra={"dep": "1.0.1"})
        check = ScriptedCheck(finding(pypi_advisory(version="1.0.1")))
        self.refused(2, uv=uv, check=check, overrides={"dep": "1.0.1"},
                     override_reason="pinned for compatibility")
        self.assertEqual(len(self.locks_of(uv)), 1)

    def test_pypi_override_name_is_normalised(self):
        uv, check, options = self.override_setup(
            {("foo-bar", "1.0.0"): REPO, ("foo-bar", "1.0.3"): "missing"}, name="foo-bar")
        installed = self.install(uv=uv, check=check, overrides={"Foo_Bar": "1.0.3"},
                                 override_reason="own reason", **options)
        self.assertEqual([item["tier"] for item in installed.fast_lane], ["override"])
        self.assertEqual(installed.overrides, {"foo-bar": "1.0.3"})
        self.assertEqual(self.uv_table(1)["override-dependencies"], ["foo-bar==1.0.3"])


class PypiJudgeTree(PypiFastLaneBase):
    def judge(self, advisory, overrides=None, entries=None, **kwargs):
        opts = {"receipts_root": self.root, "kind": "pypi", "user_overrides": overrides or {},
                "policy": fastlane.Policy(), "fetch": FakePyPI(), "now": NOW,
                "check": ScriptedCheck(finding(advisory))}
        opts.update(kwargs)
        return fastlane.judge_tree(entries or [advisory.entry], {}, **opts)

    def test_pypi_override_name_is_normalised_in_judge_tree(self):
        advisory = pypi_advisory(name="foo-bar")
        self.lookups(provenance={("foo-bar", "1.0.0"): REPO, ("foo-bar", "1.0.3"): "missing"})
        self.scan("foo-bar", "1.0.3", FIX_SHA)
        for spelling in ("Foo_Bar", "foo.bar", "FOO-BAR", "foo-bar"):
            with self.subTest(spelling=spelling):
                verdict = self.judge(advisory, {spelling: "1.0.3"})
                self.assertEqual(verdict.code, 0)
                self.assertEqual((verdict.decisions[0]["action"], verdict.decisions[0]["tier"]),
                                 ("install", "override"))
                self.assertEqual(verdict.fixes["foo-bar"][0], "1.0.3")
        verdict = self.judge(advisory, {"other": "1.0.3"})
        self.assertEqual(verdict.code, 1)
        self.assertEqual(verdict.decisions[0]["reason"], "provenance_missing")

    def test_pypi_two_overrides_for_one_name_have_no_verdict(self):
        advisory = pypi_advisory(name="foo-bar")
        self.lookups(provenance={("foo-bar", "1.0.0"): REPO, ("foo-bar", "1.0.3"): "missing"})
        with self.assertRaises(locked.Refused) as ctx:
            self.judge(advisory, {"Foo_Bar": "1.0.3", "foo-bar": "1.0.4"})
        self.assertEqual(ctx.exception.code, 2)

    def test_pypi_gather_gets_all_locked_files(self):
        files = (("dep-1.0.0.tar.gz", "a" * 64), ("dep-1.0.0-py3-none-any.whl", OLD_SHA),
                 ("dep-1.0.0-cp312-cp312-win_amd64.whl", "d" * 64))
        advisory = pypi_advisory(files=files)
        self.lookups()
        self.scan("dep", "1.0.3", FIX_SHA)
        verdict = self.judge(advisory)
        self.assertEqual(verdict.code, 0)
        self.assertEqual(self.installed_files, [("dep", "1.0.0", files)])

    def test_pypi_judge_tree_returns_fix_receipt_and_repo(self):
        advisory = pypi_advisory()
        self.lookups()
        self.scan("dep", "1.0.3", FIX_SHA)
        verdict = self.judge(advisory)
        version, found, decision = verdict.fixes["dep"]
        self.assertEqual((version, found.archive_sha256, decision["tier"], decision["repo"]),
                         ("1.0.3", FIX_SHA, "fast_lane", REPO))
        self.assertEqual(verdict.needs_scan, [])


class PypiOverrideCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **values):
        import argparse
        opts = {"package": PKG, "version": "1.2.3", "name": None, "executable": None,
                "override": [], "override_reason": None, "secret": [], "accept": None,
                "tools": None, "dry_run": False}
        opts.update(values)
        return argparse.Namespace(**opts)

    def call(self, args, uv, **kwargs):
        install_skill = importlib.import_module("install_skill")
        config = {"mcp": {"install_dir": str(self.base / "mcp")}}
        return install_skill.cmd_mcp_pypi(
            args, config=config, env={}, platform="win32", run=uv, which=which,
            check=stub_check(0), deliver=kwargs.pop("deliver", lambda *a, **k: None), **kwargs)

    def test_bad_override_syntax_is_refused(self):
        for override in (["dep"], ["=1.0.0"]):
            with self.subTest(override=override):
                uv = FakeUv()
                with self.assertRaises(locked.Refused) as ctx:
                    self.call(self.args(override=override, override_reason="r"), uv)
                self.assertEqual(ctx.exception.code, 2)
                self.assertEqual(uv.commands, [])

    def test_override_needs_a_reason(self):
        receipts.write_receipt(self.base / "mcp", receipt())
        uv = FakeUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.call(self.args(override=["dep=1.0.3"]), uv, fetch=FakePyPI())
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--override-reason", str(ctx.exception))
        self.assertEqual(uv.commands, [])

    def test_override_reaches_the_installer_and_the_handoff(self):
        receipts.write_receipt(self.base / "mcp", receipt())
        delivered = []
        uv = FakeUv(extra={"dep": "1.0.0"})
        installed = self.call(self.args(override=["Dep=1.0.3"], override_reason="advisory"), uv,
                              fetch=FakePyPI(),
                              deliver=lambda *a, **k: delivered.append((a, k)))
        self.assertEqual((installed.overrides, installed.override_reason),
                         ({"dep": "1.0.3"}, "advisory"))
        self.assertEqual(len(delivered), 1)

    def invoke_cli(self, mode, *options):
        env = dict(os.environ)
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        env["LOCALAPPDATA"] = str(self.base)
        env["XDG_DATA_HOME"] = str(self.base)
        for var in locked.ONEDRIVE_VARS:
            env.pop(var, None)
        import subprocess
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "install_skill.py"), mode, *options],
            capture_output=True, text=True, env=env, timeout=120)

    def test_json_lists_the_pypi_scan_command(self):
        result = self.invoke_cli("mcp-pypi", "--package", PKG, "--version", "1.2.3", "--json")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status["needs_scan"],
                         [{"kind": "pypi", "package": PKG, "version": "1.2.3"}])
        self.assertEqual((status["code"], status["fast_lane"], status["tier"]), (2, [], ""))
        self.assertIn(f"python scripts/scan_url.py https://pypi.org/project/{PKG}/1.2.3", status["message"])

    def test_help_describes_the_override_and_fast_lane_options(self):
        result = self.invoke_cli("mcp-pypi", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = " ".join(result.stdout.split())
        self.assertIn("--override NAME=VERSION", text)
        self.assertIn("--override-reason TEXT", text)
        self.assertIn("younger scanned security fix", text)
        self.assertIn("no trusted period", text)


PROBE = "agent-guard-s3-probe"
PROBE_BACKEND = '''from setuptools import build_meta as _meta


def get_requires_for_build_wheel(config_settings=None):
    return %r


build_wheel = _meta.build_wheel
build_sdist = _meta.build_sdist
prepare_metadata_for_build_wheel = _meta.prepare_metadata_for_build_wheel
'''


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1"
                     and uv_mod._exe.which("uv") and uv_mod._exe.which("git"),
                     "set AGENT_GUARD_INTEGRATION=1 with uv and git on PATH to build with real uv")
class GitBuildHashesLive(unittest.TestCase):
    """Unchecked backend build requirements: real uv, real PyPI, a local Git commit whose
    in-tree backend asks for one more build tool. The settings and the sync
    command come from _mcp_uv itself; only the Git URL is local, because
    git_install accepts GitHub sources only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.uv = uv_mod._exe.which("uv")
        self.run = locked.run_tool

    def tearDown(self):
        # No `uv cache clean`: it waits for the cache lock that any running
        # `uv run` server holds. The probe wheel left in the uv cache is keyed
        # by the temporary repository URL and never used again.
        self.tmp.cleanup()

    def probe_commit(self, extra_requires):
        import subprocess
        repo = self.base / "probe"
        (repo / "_be").mkdir(parents=True)
        (repo / "src" / "s3probe").mkdir(parents=True)
        (repo / "pyproject.toml").write_text(
            f'[project]\nname = "{PROBE}"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n'
            '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "be"\n'
            'backend-path = ["_be"]\n', encoding="utf-8")
        (repo / "_be" / "be.py").write_text(PROBE_BACKEND % (extra_requires,), encoding="utf-8")
        (repo / "src" / "s3probe" / "__init__.py").write_text("", encoding="utf-8")
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
               "-c", "core.autocrlf=false"]
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "probe"]):
            subprocess.run([*git, *cmd], cwd=repo, check=True, capture_output=True)
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                             capture_output=True, text=True).stdout.strip()
        return f"{PROBE} @ git+{repo.as_uri()}@{sha}"

    def tree(self, label, dependency, settings):
        stage = self.base / label
        stage.mkdir()
        (stage / "pyproject.toml").write_text(uv_mod._pyproject("s3", dependency, 7, settings),
                                              encoding="utf-8")
        code, out = self.run([self.uv, "lock", "--no-build", "--default-index", uv_mod.INDEX],
                             stage)
        self.assertEqual(code, 0, out)
        return stage

    def build_tools(self):
        stage = self.base / "tools"
        stage.mkdir()
        with redirect_stdout(io.StringIO()):
            return uv_mod.build_constraints(["setuptools"], stage, self.run, self.uv,
                                            lockcheck.check, 7)

    def test_unchecked_backend_request_is_refused_even_after_an_earlier_build(self):
        dependency = self.probe_commit(["six"])
        tools = self.build_tools()
        # An earlier build without the hash rule leaves a built wheel in the
        # uv cache; uv does not check cached wheels again.
        loose = self.tree("loose", dependency, 'build-constraint-dependencies = '
                                               f'["setuptools=={tools[0].version}"]\n')
        code, out = self.run([self.uv, "sync", "--locked", "--no-dev"], loose)
        self.assertEqual(code, 0, out)
        strict = self.tree("strict", dependency, uv_mod.git_uv_settings(tools))
        code, out = self.run(uv_mod.git_sync_command(self.uv, []), strict)
        self.assertNotEqual(code, 0, out)
        self.assertIn("no trusted hash was provided for", out)
        refused = uv_mod.git_sync_failure(PROBE, out)
        self.assertEqual(refused.code, 2)
        self.assertIn("six", str(refused))
        self.assertIn("not installed", str(refused))

    def test_pinned_and_hashed_build_tools_build_the_package(self):
        dependency = self.probe_commit([])
        tools = self.build_tools()
        self.assertTrue(all(len(e.hashes) >= 1 for e in tools), tools)
        strict = self.tree("strict", dependency, uv_mod.git_uv_settings(tools))
        code, out = self.run(uv_mod.git_sync_command(self.uv, []), strict)
        self.assertEqual(code, 0, out)
        self.assertNotIn("Hash-checking", out)

    def test_installed_uv_is_new_enough(self):
        uv_mod.require_build_hash_uv(self.run, self.uv, self.base)


if __name__ == "__main__":
    unittest.main()
