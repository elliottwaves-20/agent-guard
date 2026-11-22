"""Ordering and interval membership for public package versions."""

import importlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
versions = importlib.import_module("_versions")


class VersionTests(unittest.TestCase):
    def assert_precedence(self, ecosystem, ordered):
        for lower, upper in zip(ordered, ordered[1:]):
            with self.subTest(ecosystem=ecosystem, lower=lower, upper=upper):
                self.assertLess(
                    versions.key(ecosystem, lower), versions.key(ecosystem, upper)
                )

    def test_semver_precedence(self):
        self.assert_precedence("npm", (
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.2", "1.0.0-alpha.10",
            "1.0.0-alpha.x", "1.0.0-beta", "1.0.0", "1.0.1", "1.10.0",
        ))
        self.assertEqual(versions.key("npm", "1.0.0+x"), versions.key("npm", "1.0.0+y"))

    def test_pep440_order(self):
        self.assert_precedence("PyPI", (
            "1.0.dev1", "1.0a1", "1.0rc1", "1.0", "1.0.post1", "1!0.1",
        ))
        self.assert_precedence("PyPI", (
            "1.0rc1.dev1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1",
        ))
        self.assertEqual(versions.key("PyPI", "1.0"), versions.key("PyPI", "1.0.0"))
        self.assertEqual(versions.key("PyPI", "v1.0-RC_1"), versions.key("PyPI", "1.0rc1"))

    def test_unreadable_versions_raise(self):
        for ecosystem, version in (
            ("PyPI", "1.0.0+local"), ("PyPI", ">=1"), ("PyPI", ""),
            ("npm", ">=1"), ("npm", ""), ("npm", "latest"), ("npm", "01.0.0"),
            ("npm", "1.0.0-alpha.01"),
        ):
            with self.subTest(ecosystem=ecosystem, version=version):
                with self.assertRaises(ValueError):
                    versions.key(ecosystem, version)

    def test_interval_bounds(self):
        interval = {
            "lower": None, "lower_inclusive": False, "upper": "2.0.0",
            "upper_inclusive": True, "fixed": "bad-version",
        }
        self.assertTrue(versions.in_interval("npm", "0.0.0", interval))
        self.assertTrue(versions.in_interval("npm", "2.0.0", interval))
        self.assertFalse(versions.in_interval("npm", "2.0.1", interval))
        interval.update({"lower": "2.0.0", "upper": None})
        self.assertFalse(versions.in_interval("npm", "2.0.0", interval))
        self.assertTrue(versions.in_interval("npm", "9.0.0", interval))

    def test_major_of_zero_versions(self):
        self.assertEqual(versions.major("npm", "0.4.1"), 0)
        self.assertEqual(versions.major("PyPI", "2!0.4.1"), 0)

    def test_prerelease_detection(self):
        for ecosystem, version, expected in (
            ("npm", "1.0.0-alpha.1", True), ("npm", "1.0.0+build-2", False),
            ("PyPI", "1.0a1", True), ("PyPI", "1.0b1", True),
            ("PyPI", "1.0rc1", True), ("PyPI", "1.0.post1.dev1", True),
            ("PyPI", "1.0.post1", False),
        ):
            with self.subTest(ecosystem=ecosystem, version=version):
                self.assertIs(versions.is_prerelease(ecosystem, version), expected)
