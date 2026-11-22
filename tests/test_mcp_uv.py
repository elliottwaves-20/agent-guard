"""Locked PyPI MCP installs (#48, A3): exact pin, checked uv.lock, no build.

uv is replaced by a fake runner that writes what the real tool would write:
`uv lock` a uv.lock, `uv sync` a .venv with the dist-info of the package. The
lockfile check is a stub. The installed wheel must be the scanned one.
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
lockcheck = importlib.import_module("_lockcheck")
receipts = importlib.import_module("_mcp_receipts")
uv_mod = importlib.import_module("_mcp_uv")

PKG = "mcp-server-time"
WHEEL_SHA = "b" * 64
FILES = "https://files.pythonhosted.org/packages/xx"


def uv_lock(root, pkg, version, wheels=None, sdist_sha="a" * 64, registry="https://pypi.org/simple"):
    dist = pkg.replace("-", "_").lower()
    if wheels is None:
        wheels = [(f"{dist}-{version}-py3-none-any.whl", WHEEL_SHA)]
    wheel_lines = ", ".join(f'{{ url = "{FILES}/{n}", hash = "sha256:{h}" }}' for n, h in wheels)
    return (f'version = 1\nrequires-python = ">=3.10"\n\n'
            f'[[package]]\nname = "{root}"\nversion = "0.0.0"\nsource = {{ virtual = "." }}\n'
            f'dependencies = [{{ name = "{pkg}" }}]\n\n'
            f'[[package]]\nname = "{pkg}"\nversion = "{version}"\n'
            f'source = {{ registry = "{registry}" }}\n'
            f'sdist = {{ url = "{FILES}/{dist}-{version}.tar.gz", hash = "sha256:{sdist_sha}" }}\n'
            f'wheels = [{wheel_lines}]\n')


class FakeUv:
    def __init__(self, lock_rc=0, sync_rc=0, scripts=None, lock_version=None, wheels=None,
                 registry="https://pypi.org/simple", dist_version=None, lock_package=None):
        self.lock_rc = lock_rc
        self.sync_rc = sync_rc
        self.scripts = scripts
        self.lock_version = lock_version
        self.wheels = wheels
        self.registry = registry
        self.dist_version = dist_version
        self.lock_package = lock_package
        self.commands = []

    def _pin(self, cwd):
        text = (Path(cwd) / "pyproject.toml").read_text(encoding="utf-8")
        line = next(ln for ln in text.splitlines() if ln.startswith("dependencies"))
        spec = line.split('"')[1]
        package, version = spec.split("==")
        root = next(ln for ln in text.splitlines() if ln.startswith("name")).split('"')[1]
        return root, package, version

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        root, package, version = self._pin(cwd)
        norm = locked.normalize_pypi(package)
        if cmd[1] == "lock":
            if self.lock_rc:
                return self.lock_rc, "error: simulated"
            (Path(cwd) / "uv.lock").write_text(
                uv_lock(root, self.lock_package or norm, self.lock_version or version,
                        self.wheels, registry=self.registry), encoding="utf-8")
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


def receipt(package=PKG, version="1.2.3", sha=WHEEL_SHA):
    return receipts.Receipt(kind="pypi", package=package, version=version, archive_sha256=sha,
                            integrity="", verdict="SAFE", at="2026-11-22T00:00:00+00:00",
                            agent_guard="0.5.2")


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
        installed = self.install(uv=uv, dry=True)
        self.assertEqual(uv.commands, [])
        self.assertFalse(self.root.exists())
        self.assertEqual(installed.command, "C:/uv/uv.exe")

    def test_console_scripts_matches_normalised_names(self):
        venv = Path(self.tmp.name) / "venv"
        info = venv / "Lib" / "site-packages" / "Mcp_Server.Time-1.2.3.dist-info"
        info.mkdir(parents=True)
        (info / "entry_points.txt").write_text("[console_scripts]\nrun-it = m:main\n",
                                               encoding="utf-8")
        self.assertEqual(uv_mod.console_scripts(venv, PKG), {"run-it": "m:main"})


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


class FakeGitUv:
    def __init__(self, compiled="setuptools==80.9.0\n    # via -r build-requires.in\n",
                 lock_rc=0, lock_text=None, sync_rc=0, scripts=None):
        self.compiled = compiled
        self.lock_rc = lock_rc
        self.lock_text = lock_text
        self.sync_rc = sync_rc
        self.scripts = scripts
        self.commands = []

    def __call__(self, cmd, cwd):
        self.commands.append(list(cmd))
        cwd = Path(cwd)
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
                            at="2026-11-22T00:00:00+00:00", agent_guard="0.5.2")


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
                "compare": self.compare(status)}
        opts.update(kwargs)
        return uv_mod.git_install(**opts)

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
        uv = FakeGitUv(compiled="hatchling==1.27.0\npathspec==0.12.1\n")
        checks = []

        def check(entries, **_kw):
            checks.append([(e.label, e.all_files) for e in entries])
            return lockcheck.Result(0, ["ok"])
        self.install(uv=uv, check=check)
        self.assertEqual(uv.requires.splitlines(), ["hatchling>=1.20"])
        self.assertEqual(checks[0], [("hatchling@1.27.0", True), ("pathspec@0.12.1", True)])
        compile_cmd = next(c for c in uv.commands if c[1:3] == ["pip", "compile"])
        for flag in ("--no-build", "--exclude-newer", "7 days", "--default-index"):
            self.assertIn(flag, compile_cmd)
        lib = importlib.import_module("tomllib")
        data = lib.loads((self.root / "ex" / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["tool"]["uv"]["build-constraint-dependencies"],
                         ["hatchling==1.27.0", "pathspec==0.12.1"])

    def test_build_constraint_finding_blocks(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, check=stub_check(1))
        self.assertEqual(ctx.exception.code, 1)
        self.assertFalse(any(c[1] == "lock" for c in uv.commands))

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
        self.assertEqual(sync[:5], ["C:/uv/uv.exe", "sync", "--locked", "--no-dev",
                                    "--no-build-package"])
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
        self.install(uv=uv, git_url=url, receipt=git_receipt(package="example/mcp#servers/ex"))
        self.assertEqual(self.fetched, [f"https://raw.githubusercontent.com/example/mcp/{SHA}/"
                                        "servers/ex/pyproject.toml"])

    def test_receipt_must_be_for_this_commit(self):
        uv = FakeGitUv()
        with self.assertRaises(locked.Refused) as ctx:
            self.install(uv=uv, receipt=git_receipt(version="b" * 40))
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(uv.commands, [])

    def test_dry_run_writes_nothing(self):
        uv = FakeGitUv()
        self.install(uv=uv, dry=True)
        self.assertEqual(uv.commands, [])
        self.assertEqual(self.compared, [])
        self.assertFalse(self.root.exists())


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


if __name__ == "__main__":
    unittest.main()
