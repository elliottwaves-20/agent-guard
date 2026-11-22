"""Receipts bind a locked MCP install to the scan verdict (#48, K1).

A locked installer runs only for a package version scan_url.py judged; a
BLOCK needs an explicit reason, and that reason holds for this version only.
"""
import dataclasses
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
receipts = importlib.import_module("_mcp_receipts")
locked = importlib.import_module("_mcp_locked")


def receipt(kind="npm", package="@scope/pkg", version="1.0.0", verdict="SAFE"):
    return receipts.Receipt(kind=kind, package=package, version=version,
                            archive_sha256="ab" * 32, integrity="sha512-x", verdict=verdict,
                            at="2026-11-22T00:00:00+00:00", agent_guard="0.5.2")


class Receipts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_safe_receipt_is_found(self):
        receipts.write_receipt(self.root, receipt())
        found, accepted = receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", None)
        self.assertEqual(found, receipt())
        self.assertIsNone(accepted)

    def test_receipt_lives_under_receipts(self):
        path = receipts.write_receipt(self.root, receipt())
        self.assertEqual(path.parent, self.root / ".receipts")
        self.assertEqual(path.name, "npm-scope__pkg-1.0.0.json")

    def test_missing_receipt_names_the_scan_command(self):
        with self.assertRaises(locked.Refused) as ctx:
            receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", None)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("scan_url.py", str(ctx.exception))

    def test_receipt_for_another_version_does_not_count(self):
        receipts.write_receipt(self.root, receipt(version="1.0.0"))
        with self.assertRaises(locked.Refused) as ctx:
            receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.1", None)
        self.assertEqual(ctx.exception.code, 2)

    def test_block_needs_accept(self):
        receipts.write_receipt(self.root, receipt(verdict="BLOCK"))
        with self.assertRaises(locked.Refused) as ctx:
            receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", None)
        self.assertEqual(ctx.exception.code, 1)

    def test_block_with_reason_is_accepted_for_this_version_only(self):
        receipts.write_receipt(self.root, receipt(verdict="BLOCK"))
        receipts.write_receipt(self.root, receipt(version="2.0.0", verdict="BLOCK"))
        _, accepted = receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0",
                                               "false positive, reviewed by hand")
        self.assertEqual(accepted["version"], "1.0.0")
        self.assertEqual(accepted["grund"], "false positive, reviewed by hand")
        self.assertRegex(accepted["at"], r"^\d{4}-\d{2}-\d{2}$")
        with self.assertRaises(locked.Refused) as ctx:
            receipts.require_receipt(self.root, "npm", "@scope/pkg", "2.0.0", None)
        self.assertEqual(ctx.exception.code, 1)

    def test_empty_reason_is_refused(self):
        receipts.write_receipt(self.root, receipt(verdict="BLOCK"))
        for reason in ("", "   "):
            with self.subTest(reason=reason):
                with self.assertRaises(locked.Refused) as ctx:
                    receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", reason)
                self.assertEqual(ctx.exception.code, 2)

    def test_safe_ignores_accept(self):
        receipts.write_receipt(self.root, receipt())
        _, accepted = receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", "x")
        self.assertIsNone(accepted)

    def test_tampered_receipt_has_no_verdict(self):
        path = receipts.write_receipt(self.root, receipt())
        data = json.loads(path.read_text(encoding="utf-8"))
        for field, value in (("package", "@scope/other"), ("version", "9.9.9"),
                             ("kind", "pypi"), ("verdict", "MAYBE")):
            with self.subTest(field=field):
                path.write_text(json.dumps({**data, field: value}), encoding="utf-8")
                with self.assertRaises(locked.Refused) as ctx:
                    receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", None)
                self.assertEqual(ctx.exception.code, 2)

    def test_unreadable_receipt_has_no_verdict(self):
        path = receipts.write_receipt(self.root, receipt())
        for text in ("{", "[]", json.dumps({"kind": "npm"})):
            with self.subTest(text=text):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(locked.Refused):
                    receipts.require_receipt(self.root, "npm", "@scope/pkg", "1.0.0", None)

    def test_names_are_normalised_for_lookup(self):
        receipts.write_receipt(self.root, receipt(kind="pypi", package="mcp-server-time",
                                                  version="2026.8.18"))
        found, _ = receipts.require_receipt(self.root, "pypi", "Mcp_Server.Time", "2026.8.18", None)
        self.assertEqual(found.package, "mcp-server-time")

    def test_git_receipt_key_includes_subdirectory(self):
        sha = "a" * 40
        path = receipts.write_receipt(self.root, receipt(kind="git", package="Owner/Repo#sub/dir",
                                                         version=sha))
        self.assertEqual(path.name, f"git-owner__repo__sub__dir-{sha}.json")
        receipts.require_receipt(self.root, "git", "owner/repo#sub/dir", sha, None)
        with self.assertRaises(locked.Refused):
            receipts.require_receipt(self.root, "git", "owner/repo", sha, None)

    def test_write_is_atomic(self):
        receipts.write_receipt(self.root, receipt())
        receipts.write_receipt(self.root, dataclasses.replace(receipt(), verdict="BLOCK"))
        names = [p.name for p in (self.root / ".receipts").iterdir()]
        self.assertEqual(names, ["npm-scope__pkg-1.0.0.json"])


if __name__ == "__main__":
    unittest.main()
