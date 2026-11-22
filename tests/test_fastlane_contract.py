"""Shared, offline fast lane contract also consumed by update-globals."""

import importlib
import json
import sys
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parent / "scripts"))
fastlane = importlib.import_module("_fastlane")
locked = importlib.import_module("_mcp_locked")

CONTRACT_FILE = TEST_DIR / "contract" / "fastlane_cases.json"
REQUIRED_CASES = {
    "trigger-critical", "trigger-high", "trigger-kev-moderate",
    "no-trigger-moderate", "no-trigger-withdrawn", "no-trigger-osv-cvss-only",
    "lowest-not-latest", "two-advisories-max-fix", "alias-duplicate",
    "fix-with-residual-advisory", "fix-needs-major", "prerelease-fix", "malware",
    "provenance-missing", "provenance-missing-with-override", "repo-changed",
    "repo-changed-with-override", "provenance-lookup-failed-with-override",
    "pypi-no-pure-wheel", "pypi-sdist-only", "lookup-failed", "kev-unavailable",
    "kev-unavailable-high", "exclusive-lower-bound", "separate-intervals",
    "last-affected-closed-interval", "disabled", "s1-npm-3-days-same-repo",
    "s1-npm-1-day-same-repo", "s1-npm-other-repo", "s1-no-previous",
    "s1-provenance-failed", "s1-pypi-same-repo", "s2-8-days",
    "s2-exactly-7-days", "young-without-trigger",
}
RESULT_KEYS = {"action", "version", "tier", "reason", "wait_until", "advisories"}


class FastLaneContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))

    def test_contract_lists_required_cases(self):
        case_ids = [case["id"] for case in self.contract["cases"]]
        self.assertEqual(self.contract["version"], 1)
        self.assertEqual(len(case_ids), len(set(case_ids)))
        self.assertFalse(REQUIRED_CASES - set(case_ids))

    def test_contract_cases_match(self):
        for case in self.contract["cases"]:
            with self.subTest(case=case["id"]):
                actual = fastlane.decide({"kind": case["kind"], "input": case["input"]})
                self.assertEqual(set(actual), RESULT_KEYS)
                self.assertEqual(
                    {key: actual[key] for key in case["expect"]}, case["expect"]
                )

    def test_select_fix_uses_advisories_without_version_metadata(self):
        case = next(
            case for case in self.contract["cases"] if case["id"] == "two-advisories-max-fix"
        )
        fix_input = {
            key: case["input"][key] for key in ("ecosystem", "installed", "advisories", "kev")
        }
        version, _ = fastlane.select_fix({"kind": "fast_lane", "input": fix_input})
        self.assertEqual(version, case["expect"]["version"])

    def test_policy_validation(self):
        self.assertEqual(fastlane.policy(None, None, False), fastlane.Policy(7, 2, True))
        self.assertEqual(fastlane.policy(0, 0, True), fastlane.Policy(0, 0, False))
        for min_age_days, trusted_days in ((2, 3), (-1, 0), (7, -1), (7, 2.5), (7, True)):
            with self.subTest(min_age_days=min_age_days, trusted_days=trusted_days):
                with self.assertRaises(locked.Refused) as caught:
                    fastlane.policy(min_age_days, trusted_days, False)
                self.assertEqual(caught.exception.code, 2)
