"""After a scan, scan_url.py records the verdict and offers only locked installs (#48, A6/K1).

A receipt binds the verdict to the exact archive that was scanned (npm tarball
with its integrity, the pure PyPI wheel that uv installs, the GitHub ZIP). No
offer and no accepted `mcp` command starts an ad-hoc runner such as npx.
"""
import base64
import contextlib
import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
scan_url = importlib.import_module("scan_url")
scan_mcp = importlib.import_module("scan_mcp")
resolver = importlib.import_module("_url_resolver")
receipts = importlib.import_module("_mcp_receipts")
locked = importlib.import_module("_mcp_locked")

ADHOC = ("npx", "uvx", "bunx", "dlx", "pipx run", "uv tool run", "uv run --with")


def tarball(name="package/index.js"):
    buf = io.BytesIO()
    import tarfile
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"// server\n"
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel():
    buf = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/__init__.py", "print(1)\n")
    return buf.getvalue()


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class Offers(unittest.TestCase):
    def output(self, fn, *args, **kwargs):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(scan_url, "interactive", lambda: False):
            fn(*args, **kwargs)
        return out.getvalue()

    def test_npm_offer_is_locked_install(self):
        text = self.output(scan_url.offer_locked_mcp_install, "npm", "@s/x", "1.2.3", True)
        self.assertIn("python scripts/install_skill.py mcp-npm --package @s/x --version 1.2.3",
                      text)

    def test_pypi_offer_is_locked_install(self):
        text = self.output(scan_url.offer_locked_mcp_install, "pypi", "mcp-server-time",
                           "2025.9.25", False)
        self.assertIn("python scripts/install_skill.py mcp-pypi --package mcp-server-time "
                      "--version 2025.9.25", text)

    def test_git_offer_keeps_mcp_git(self):
        with tempfile.TemporaryDirectory() as src:
            (Path(src) / "pyproject.toml").write_text(
                '[project]\nname = "example-mcp"\n[project.scripts]\nex = "e:main"\n',
                encoding="utf-8")
            source = resolver.ResolvedSource(kind="github", source_path=Path(src),
                                             install_hint="https://github.com/o/r@" + "a" * 40)
            text = self.output(scan_url.offer_git_mcp_install, source, True)
        self.assertIn("install_skill.py mcp-git", text)

    def test_no_offer_mentions_adhoc_runners(self):
        texts = [self.output(scan_url.offer_locked_mcp_install, kind, "pkg", "1.0.0", dry)
                 for kind in ("npm", "pypi") for dry in (True, False)]
        for text in texts:
            for word in ADHOC:
                self.assertNotIn(word, text)

    def test_interactive_offer_runs_the_locked_installer_and_reports_refusal(self):
        calls = []

        def refuse(args, **kwargs):
            calls.append(args)
            raise locked.Refused(2, "no receipt")
        out = io.StringIO()
        with patch.object(scan_url, "interactive", lambda: True), \
                patch.object(scan_url, "confirm_install", lambda prompt: True), \
                patch.object(scan_url, "choose_install_tools", lambda: ["codex"]), \
                patch.object(scan_url, "cmd_mcp_npm", refuse), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            scan_url.offer_locked_mcp_install("npm", "@s/x", "1.2.3", False)
        self.assertEqual((calls[0].package, calls[0].version, calls[0].tools),
                         ("@s/x", "1.2.3", ["codex"]))
        self.assertIn("no receipt", out.getvalue())


class Receipts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def scan_npm(self, static_rc, meta=None):
        def fetch(spec, dest, meta_out=None, **_kw):
            if meta_out is not None and meta is not None:
                meta_out.update(meta)
            return "@s/x@1.2.3"
        source = resolver.ResolvedSource(kind="npm", install_hint="@s/x@1.2.3", label="npm")
        with patch.object(scan_url, "fetch_npm", side_effect=lambda s, d, meta=None: fetch(s, d, meta)), \
                patch.object(scan_url, "run_mcp_static", return_value=static_rc), \
                patch.object(scan_url._dynamic, "run", return_value=0), \
                patch.object(scan_url, "receipt_root", lambda: self.root), \
                patch.object(scan_url, "offer_locked_mcp_install") as offer, \
                contextlib.redirect_stdout(io.StringIO()):
            rc = scan_url.scan_resolved(source, "auto", dry_run=True)
        return rc, offer

    def test_safe_and_block_write_receipts_no_verdict_does_not(self):
        meta = {"archive_sha256": "ab" * 32, "integrity": "sha512-x"}
        for static_rc, verdict in ((0, "SAFE"), (1, "BLOCK"), (2, None)):
            with self.subTest(rc=static_rc):
                for p in (self.root / ".receipts").glob("*") if (self.root / ".receipts").is_dir() else []:
                    p.unlink()
                rc, offer = self.scan_npm(static_rc, meta)
                self.assertEqual(rc, static_rc)
                path = receipts.receipt_path(self.root, "npm", "@s/x", "1.2.3")
                if verdict is None:
                    self.assertFalse(path.exists())
                else:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual((data["verdict"], data["integrity"], data["archive_sha256"]),
                                     (verdict, "sha512-x", "ab" * 32))
                self.assertEqual(offer.called, static_rc == 0)

    def test_unknown_archive_hash_writes_no_receipt(self):
        rc, _offer = self.scan_npm(0, meta=None)
        self.assertEqual(rc, 0)
        self.assertFalse((self.root / ".receipts").exists())

    def test_broken_mcp_settings_keep_the_scan_result(self):
        source = resolver.ResolvedSource(kind="npm", install_hint="@s/x@1.2.3", label="npm")

        def broken():
            raise locked.Refused(2, "[mcp] install_dir must be an absolute path")
        out = io.StringIO()
        with patch.object(scan_url, "fetch_npm",
                          side_effect=lambda s, d, meta=None: meta.update(
                              {"archive_sha256": "ab" * 32, "integrity": "sha512-x"})
                          or "@s/x@1.2.3"), \
                patch.object(scan_url, "run_mcp_static", return_value=0), \
                patch.object(scan_url._dynamic, "run", return_value=0), \
                patch.object(scan_url, "receipt_root", broken), \
                patch.object(scan_url, "offer_locked_mcp_install"), \
                contextlib.redirect_stdout(out):
            self.assertEqual(scan_url.scan_resolved(source, "auto", dry_run=True), 0)
        self.assertIn("install_dir", out.getvalue())

    def test_git_scan_writes_a_receipt_for_the_repository_commit(self):
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as src:
            source = resolver.ResolvedSource(kind="github", source_path=Path(src),
                                             install_hint=f"https://github.com/O/r@{sha}",
                                             archive_sha256="cd" * 32)
            with patch.object(scan_url, "run_mcp_static", return_value=0), \
                    patch.object(scan_url, "receipt_root", lambda: self.root), \
                    patch.object(scan_url, "offer_git_mcp_install"), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scan_url.scan_resolved(source, "mcp-source", dry_run=True), 0)
        receipt, _ = receipts.require_receipt(self.root, "git", "o/r", sha, None)
        self.assertEqual(receipt.archive_sha256, "cd" * 32)

    def test_git_subdirectory_offer_matches_receipt_and_reads_scanned_project(self):
        from tests.test_mcp_uv import FakeGitUv, SHA, git_lock, git_which, stub_check
        from _mcp_uv import git_scan_ids, parse_git_url

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("repo/server/pyproject.toml",
                        '[project]\nname = "example-mcp"\n'
                        '[project.scripts]\nexample-server = "ex:main"\n'
                        '[build-system]\nrequires = ["setuptools>=70"]\n')
        with tempfile.TemporaryDirectory() as src:
            url = f"https://github.com/example/mcp/tree/{SHA}/server"
            with patch.object(resolver, "http_bytes", return_value=archive.getvalue()):
                source = resolver.resolve_github(url, Path(src))
            output = io.StringIO()
            with patch.object(scan_url, "run_mcp_static", return_value=0), \
                    patch.object(scan_url, "receipt_root", return_value=self.root), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(scan_url.scan_resolved(source, "mcp-source", dry_run=True), 0)
            git_url = output.getvalue().partition("--git-url ")[2].split()[0]
            owner, repo, sha, subdir = parse_git_url(git_url)
            self.assertEqual(subdir, "server")
            identity = git_scan_ids(f"{owner}/{repo}", subdir)[0]
            receipts.require_receipt(self.root, "git", identity, sha, None)

            uv = FakeGitUv(lock_text=lambda name: git_lock(name, query_extra="subdirectory=server&"))
            install_git = scan_url.install_mcp_git

            def install(*args, **kwargs):
                return install_git(
                    *args, **kwargs, config={"mcp": {"install_dir": str(self.root)}},
                    run=uv, which=git_which, check=stub_check(0), deliver=lambda *a, **kw: None,
                    settled=lambda *a: ("c" * 40, None), branch_head=lambda *a: ("main", "d" * 40),
                    compare=lambda *a: "behind")

            with patch.object(scan_url, "interactive", return_value=True), \
                    patch.object(scan_url, "confirm_install", return_value=True), \
                    patch.object(scan_url, "choose_install_tools", return_value=["codex"]), \
                    patch.object(scan_url, "install_mcp_git", side_effect=install), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                scan_url.offer_git_mcp_install(source, dry_run=False)
            self.assertEqual(uv.requires.strip(), "setuptools>=70")
            self.assertTrue((self.root / "example-mcp" / "uv.lock").is_file())


class Fetch(unittest.TestCase):
    def test_receipt_carries_tarball_integrity_and_sha256(self):
        data = tarball()
        meta_json = {"versions": {"1.2.3": {"dist": {
            "tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz", "integrity": sri(data)}}}}
        meta = {}
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(scan_mcp, "http_json", lambda url: meta_json), \
                patch.object(scan_mcp, "http_bytes", lambda url: data), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scan_mcp.fetch_npm("x@1.2.3", Path(dest), meta=meta), "x@1.2.3")
        self.assertEqual(meta["archive_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta["integrity"], sri(data))

    def test_tarball_that_does_not_match_its_integrity_is_refused(self):
        data = tarball()
        meta_json = {"versions": {"1.2.3": {"dist": {
            "tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz", "integrity": sri(b"other")}}}}
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(scan_mcp, "http_json", lambda url: meta_json), \
                patch.object(scan_mcp, "http_bytes", lambda url: data), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                scan_mcp.fetch_npm("x@1.2.3", Path(dest), meta={})
        self.assertEqual(ctx.exception.code, 2)

    def pypi_meta(self, files):
        return {"info": {"version": "1.0.0"}, "releases": {"1.0.0": files}}

    def test_pypi_scan_prefers_the_pure_wheel_uv_installs(self):
        data = wheel()
        files = [{"packagetype": "sdist", "url": "https://files/demo-1.0.0.tar.gz",
                  "filename": "demo-1.0.0.tar.gz", "digests": {"sha256": "0" * 64}},
                 {"packagetype": "bdist_wheel", "url": "https://files/demo-1.0.0-py3-none-any.whl",
                  "filename": "demo-1.0.0-py3-none-any.whl",
                  "digests": {"sha256": hashlib.sha256(data).hexdigest()}}]
        meta, fetched = {}, []
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(scan_mcp, "http_json", lambda url: self.pypi_meta(files)), \
                patch.object(scan_mcp, "http_bytes", lambda url: fetched.append(url) or data), \
                contextlib.redirect_stdout(io.StringIO()):
            scan_mcp.fetch_pypi("demo==1.0.0", Path(dest), meta=meta, wheel=True)
            self.assertTrue((Path(dest) / "demo" / "__init__.py").is_file())
        self.assertEqual(fetched, ["https://files/demo-1.0.0-py3-none-any.whl"])
        self.assertEqual(meta["archive_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(meta["filename"], "demo-1.0.0-py3-none-any.whl")

    def test_pypi_wheel_with_another_digest_is_refused(self):
        data = wheel()
        files = [{"packagetype": "bdist_wheel", "url": "https://files/demo-1.0.0-py3-none-any.whl",
                  "filename": "demo-1.0.0-py3-none-any.whl", "digests": {"sha256": "1" * 64}}]
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(scan_mcp, "http_json", lambda url: self.pypi_meta(files)), \
                patch.object(scan_mcp, "http_bytes", lambda url: data), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                scan_mcp.fetch_pypi("demo==1.0.0", Path(dest), meta={}, wheel=True)
        self.assertEqual(ctx.exception.code, 2)

    def test_pypi_without_a_single_pure_wheel_scans_the_sdist(self):
        data = tarball("demo-1.0.0/setup.py")
        files = [{"packagetype": "sdist", "url": "https://files/demo-1.0.0.tar.gz",
                  "filename": "demo-1.0.0.tar.gz", "digests": {"sha256": hashlib.sha256(data).hexdigest()}},
                 {"packagetype": "bdist_wheel", "url": "https://files/w.whl",
                  "filename": "demo-1.0.0-cp312-cp312-win_amd64.whl", "digests": {"sha256": "2" * 64}}]
        meta, fetched = {}, []
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(scan_mcp, "http_json", lambda url: self.pypi_meta(files)), \
                patch.object(scan_mcp, "http_bytes", lambda url: fetched.append(url) or data), \
                contextlib.redirect_stdout(io.StringIO()):
            scan_mcp.fetch_pypi("demo==1.0.0", Path(dest), meta=meta, wheel=True)
        self.assertEqual(fetched, ["https://files/demo-1.0.0.tar.gz"])
        self.assertEqual(meta["filename"], "demo-1.0.0.tar.gz")

    def test_github_archive_hash_is_recorded(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("r-" + "a" * 40 + "/pyproject.toml", '[project]\nname = "x"\n')
        data = buf.getvalue()
        with tempfile.TemporaryDirectory() as dest, \
                patch.object(resolver, "github_default_sha", lambda o, r: "a" * 40), \
                patch.object(resolver, "http_bytes", lambda url: data):
            source = resolver.resolve_github("https://github.com/o/r", Path(dest))
        self.assertEqual(source.archive_sha256, hashlib.sha256(data).hexdigest())


class AdhocLaunchers(unittest.TestCase):
    def run_mcp(self, *args):
        env = dict(os.environ)
        env["AGENT_GUARD_NO_USER_CONFIG"] = "1"
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "install_skill.py"), "mcp",
                               "--name", "x", *args], capture_output=True, text=True, env=env,
                              timeout=120)

    def test_mcp_refuses_adhoc_launchers(self):
        for args in (["--command", "npx", "--dry-run", "--args", "-y", "pkg@1.0.0"],
                     ["--command", "C:/node/NPX.CMD", "--dry-run", "--arg=pkg"],
                     ["--command", "uv", "--dry-run", "--args", "tool", "run", "pkg"]):
            with self.subTest(args=args):
                result = self.run_mcp(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("mcp-npm", result.stderr)

    def test_audit_still_reads_npx_entries(self):
        self.assertEqual(scan_url.package_page_from_command("npx -y pkg@1.0.0"),
                         ("npm", "https://www.npmjs.com/package/pkg@1.0.0"))


if __name__ == "__main__":
    unittest.main()
