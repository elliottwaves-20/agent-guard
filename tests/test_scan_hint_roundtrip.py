"""The scan command a locked installer prints is one scan_url.py accepts (#48, K1).

Seam test with both real sides: the installer's refusal text names a command;
that exact command line goes through scan_url.py's own argument parser, URL
resolver, fetcher, static scan and receipt writer; the installer's own receipt
reader then finds the receipt. Only the network is replaced (registry JSON and
archive bytes); `NetworkShapeContract` checks those shapes against the live
registries when AGENT_GUARD_INTEGRATION=1.

Before the fix the hint was `scan_url.py npm:<pkg>@<ver>` / `pypi:<pkg>==<ver>`,
a form scan_url.py never knew ("unknown url type", exit 2).
"""
import base64
import contextlib
import hashlib
import importlib
import io
import os
import re
import shlex
import sys
import tarfile
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
skillspector = importlib.import_module("_skillspector")

SHA = "0123456789abcdef0123456789abcdef01234567"
HINT = re.compile(r"python scripts/scan_url\.py (\S+)")


def npm_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in (("package/package.json", '{"name": "x", "version": "1.2.3"}\n'),
                           ("package/index.js", "console.log('ok');\n")):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def pure_wheel() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/__init__.py", "def main():\n    return 0\n")
    return buf.getvalue()


def git_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"mcp-{SHA}/server/pyproject.toml",
                    '[project]\nname = "example-mcp"\nversion = "1.0"\n')
        zf.writestr(f"mcp-{SHA}/server/ex.py", "def main():\n    return 0\n")
    return buf.getvalue()


class FakeNet:
    """Registry JSON and archive bytes in the shapes the live registries serve."""

    def __init__(self):
        self.npm = npm_tarball()
        self.wheel = pure_wheel()
        self.zip = git_zip()
        self.urls: list[str] = []

    def json(self, url):
        self.urls.append(url)
        if url.startswith("https://registry.npmjs.org/"):
            name = url.removeprefix("https://registry.npmjs.org/")
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(self.npm).digest()).decode()
            return {"dist-tags": {"latest": "9.9.9"}, "versions": {"1.2.3": {"dist": {
                "tarball": f"https://registry.npmjs.org/{name}/-/x-1.2.3.tgz",
                "integrity": integrity}}}}
        if url.startswith("https://pypi.org/pypi/"):
            return {"info": {"version": "9.9.9"}, "releases": {"2026.8.18": [{
                "packagetype": "bdist_wheel", "url": "https://files.example/demo.whl",
                "filename": "My_Server-2026.8.18-py3-none-any.whl",
                "digests": {"sha256": hashlib.sha256(self.wheel).hexdigest()}}]}}
        raise AssertionError(f"unexpected JSON fetch {url}")

    def bytes(self, url):
        self.urls.append(url)
        if url.endswith(".tgz"):
            return self.npm
        if url.endswith(".whl"):
            return self.wheel
        if url == f"https://github.com/example/mcp/archive/{SHA}.zip":
            return self.zip
        raise AssertionError(f"unexpected download {url}")


class InstallerHintRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mcp"
        self.net = FakeNet()

    def tearDown(self):
        self.tmp.cleanup()

    def installer_hint(self, kind, package, version) -> list[str]:
        """The command line the installer prints when the receipt is missing."""
        with self.assertRaises(locked.Refused) as ctx:
            receipts.require_receipt(self.root, kind, package, version, None)
        self.assertEqual(ctx.exception.code, 2)
        found = HINT.findall(str(ctx.exception))
        self.assertEqual(len(found), 1, str(ctx.exception))
        return shlex.split(f"scan_url.py {found[0]}")

    def run_scan_url(self, argv) -> int:
        """scan_url.py's own main(), with only the network replaced."""
        out = io.StringIO()
        with patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}):
            # _skillspector picks the LLM at import (_skillspector.py:403);
            # pick again under this environment, as a fresh process would.
            llm = dict(zip(("PROVIDER", "LLM_READY", "LLM_REASON"), skillspector.resolve_llm()))
            llm["LLM_EXPLICIT"] = skillspector._llm_explicit()
        with patch.object(sys, "argv", argv + ["--dry-run", "--no-dynamic"]), \
                patch.dict(os.environ, {"AGENT_GUARD_STATIC_ONLY": "1"}), \
                patch.multiple(skillspector, **llm), \
                patch.dict(skillspector.USER_CONFIG, {"mcp": {"install_dir": str(self.root)}}), \
                patch.object(scan_mcp, "http_json", self.net.json), \
                patch.object(scan_mcp, "http_bytes", self.net.bytes), \
                patch.object(resolver, "http_bytes", self.net.bytes), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            with self.assertRaises(SystemExit) as ctx:
                scan_url.main()
        self.assertIn(ctx.exception.code, (0, 1), out.getvalue())
        self.assertIn("Scan receipt:", out.getvalue())
        self.assertNotIn("[LLM:", out.getvalue(), "a unit test must not spend LLM budget")
        return ctx.exception.code

    def assert_roundtrip(self, kind, package, version, archive: bytes):
        code = self.run_scan_url(self.installer_hint(kind, package, version))
        receipt, accepted = receipts.require_receipt(self.root, kind, package, version, "test")
        self.assertEqual(receipt.verdict, "SAFE" if code == 0 else "BLOCK")
        self.assertEqual(accepted is None, code == 0)
        self.assertEqual(receipt.archive_sha256, hashlib.sha256(archive).hexdigest())

    def test_npm_scoped_package(self):
        self.assert_roundtrip("npm", "@scope/srv", "1.2.3", self.net.npm)
        self.assertIn("https://registry.npmjs.org/@scope/srv", self.net.urls)

    def test_npm_plain_package(self):
        self.assert_roundtrip("npm", "srv", "1.2.3", self.net.npm)

    def test_pypi_package_with_unnormalized_name(self):
        self.assert_roundtrip("pypi", "My_Server", "2026.8.18", self.net.wheel)

    def test_git_subdirectory(self):
        self.assert_roundtrip("git", "example/mcp#server", SHA, self.net.zip)

    def test_fast_lane_needs_scan_lists_accepted_commands(self):
        items = [{"kind": "npm", "package": "@scope/srv", "version": "1.2.3"},
                 {"kind": "pypi", "package": "My_Server", "version": "2026.8.18"}]
        lines = HINT.findall(str(locked.NeedsScan(items)))
        self.assertEqual(len(lines), 2)
        for (item, line), archive in zip(zip(items, lines), (self.net.npm, self.net.wheel)):
            with self.subTest(kind=item["kind"]):
                self.run_scan_url(shlex.split(f"scan_url.py {line}"))
                receipt, _ = receipts.require_receipt(self.root, item["kind"], item["package"],
                                                      item["version"], "test")
                self.assertEqual(receipt.archive_sha256, hashlib.sha256(archive).hexdigest())


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to check the fake shapes against the registries")
class NetworkShapeContract(unittest.TestCase):
    """The live registries answer in the shapes FakeNet serves (keys the fetchers read)."""

    def test_npm_registry_document(self):
        doc = resolver.http_json("https://registry.npmjs.org/@modelcontextprotocol/server-filesystem")
        dist = doc["versions"]["2.3.0"]["dist"]
        self.assertTrue(dist["tarball"].endswith(".tgz"))
        self.assertTrue(dist["integrity"].startswith("sha512-"))
        self.assertIn("latest", doc["dist-tags"])

    def test_pypi_release_files(self):
        info = resolver.http_json("https://pypi.org/pypi/mcp-server-time/json")
        files = info["releases"]["2026.8.18"]
        wheel = [f for f in files if f["packagetype"] == "bdist_wheel"
                 and f["filename"].endswith("-none-any.whl")]
        self.assertEqual(len(wheel), 1)
        self.assertRegex(wheel[0]["digests"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(wheel[0]["url"].startswith("https://"))

    def test_github_archive_is_a_zip_with_one_top_folder(self):
        data = resolver.http_bytes("https://github.com/modelcontextprotocol/servers/archive/"
                                   "HEAD.zip")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            tops = {n.split("/", 1)[0] for n in zf.namelist()}
        self.assertEqual(len(tops), 1)


if __name__ == "__main__":
    unittest.main()
