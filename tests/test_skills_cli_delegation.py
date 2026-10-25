"""Trust-boundary and behaviour regressions for the delegated `skills` CLI.

Distribution is delegated to a third-party CLI, so the interesting part is the
gate in front of it: the pin, the reviewed findings, the reduced environment,
and the fallback that must take over whenever any of those does not hold.
"""
import contextlib
import copy
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

cli = importlib.import_module("_skills_cli")
installer = importlib.import_module("install_skill")


def review_data():
    return {
        "version": 1,
        "package": "skills",
        "package_version": cli.SKILLS_VERSION,
        "shasum": cli.SKILLS_SHASUM,
        "integrity": cli.SKILLS_INTEGRITY,
        "source": "https://github.com/vercel-labs/skills",
        "scanner": "guarddog npm scan",
        "reviewed_on": "2026-09-13",
        "findings": [
            {"rule": "capability-process-hooks", "file": "package/package.json",
             "match": '"prepare": "husky', "reason": "npm does not run prepare for a registry tarball"},
        ],
    }


def guarddog_report(rule="capability-process-hooks",
                    location="package/package.json:24",
                    match='"prepare": "husky'):
    return {"results": {rule: [{"location": location, "match": match}],
                        "capability-network-outbound": [
                            {"location": "package/dist/cli.mjs:82", "match": "fetch("}]},
            "issues": 1}


class ShippedReviewFileTests(unittest.TestCase):
    """The file that ships in the repo must cover the pinned version."""

    def test_pinned_version_has_a_valid_review_file(self):
        review = cli.load_review(cli.review_path())
        self.assertEqual(review["package_version"], cli.SKILLS_VERSION)
        self.assertEqual(review["shasum"], cli.SKILLS_SHASUM)
        self.assertEqual(review["integrity"], cli.SKILLS_INTEGRITY)
        for finding in review["findings"]:
            self.assertGreater(len(finding["reason"]), 40, finding)

    def test_review_file_rejects_wildcards_and_missing_fields(self):
        valid = review_data()
        invalid = [
            {**valid, "version": 2},
            {**valid, "package": "other"},
            {**valid, "findings": []},
            {**valid, "reviewed_on": ""},
            {**valid, "shasum": ""},
        ]
        for field in ("rule", "file", "match", "reason"):
            for value in ("", "*", None):
                broken = copy.deepcopy(valid)
                broken["findings"][0][field] = value
                invalid.append(broken)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            for data in invalid:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        cli.load_review(path)
            path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(cli.load_review(path), valid)


class FindingIdentityTests(unittest.TestCase):
    def test_line_numbers_are_not_part_of_the_identity(self):
        first = cli.finding_key("r", {"location": "package/dist/cli.mjs:3721", "match": "x"})
        moved = cli.finding_key("r", {"location": "package/dist/cli.mjs:9999", "match": "x"})
        self.assertEqual(first, moved)
        self.assertEqual(first, ("r", "package/dist/cli.mjs", "x"))

    def test_informational_capabilities_do_not_count_as_blocking(self):
        found = cli.blocking_findings(guarddog_report())
        self.assertEqual(found, {("capability-process-hooks", "package/package.json",
                                  '"prepare": "husky')})


class VerificationGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.review = root / "review.json"
        self.review.write_text(json.dumps(review_data()), encoding="utf-8")
        self.marker = root / "marker.json"

    def _patches(self, **extra):
        base = {
            "review_path": lambda version=cli.SKILLS_VERSION: self.review,
            "verification_marker": lambda version=cli.SKILLS_VERSION: self.marker,
            "registry_metadata": lambda version=cli.SKILLS_VERSION: {
                "dist": {"shasum": cli.SKILLS_SHASUM, "integrity": cli.SKILLS_INTEGRITY}},
            "latest_version": lambda: cli.SKILLS_VERSION,
            "guarddog_report": lambda version=cli.SKILLS_VERSION, timeout=900.0: guarddog_report(),
        }
        base.update(extra)
        return base

    def _run(self, **extra):
        with patch.multiple(cli, **self._patches(**extra)):
            return cli.verify_pinned_package()

    def test_reviewed_block_is_accepted_and_cached(self):
        self.assertTrue(self._run())
        cached = json.loads(self.marker.read_text(encoding="utf-8"))
        self.assertTrue(cached["accepted"])
        self.assertEqual(cached["version"], cli.SKILLS_VERSION)

        # A cached result must not reach the network or the scanner again.
        def boom(*args, **kwargs):
            raise AssertionError("verification re-ran despite a cached result")

        with patch.multiple(cli, **self._patches(registry_metadata=boom, guarddog_report=boom)):
            self.assertTrue(cli.verify_pinned_package())

    def test_unreviewed_finding_blocks_delegation(self):
        report = guarddog_report(rule="threat-runtime-keylogging",
                                 location="package/dist/cli.mjs:10", match="keylog")
        self.assertFalse(self._run(
            guarddog_report=lambda version=cli.SKILLS_VERSION, timeout=900.0: report))
        self.assertFalse(self.marker.exists())

    def test_registry_digest_mismatch_blocks_delegation(self):
        self.assertFalse(self._run(
            registry_metadata=lambda version=cli.SKILLS_VERSION: {
                "dist": {"shasum": "deadbeef", "integrity": "sha512-other"}}))
        self.assertFalse(self.marker.exists())

    def test_missing_scanner_report_blocks_delegation(self):
        self.assertFalse(self._run(
            guarddog_report=lambda version=cli.SKILLS_VERSION, timeout=900.0: None))

    def test_clean_scan_needs_no_reviewed_findings(self):
        self.assertTrue(self._run(
            guarddog_report=lambda version=cli.SKILLS_VERSION, timeout=900.0: {"results": {}, "issues": 0}))


class InvocationTests(unittest.TestCase):
    def test_default_targets_every_agent_the_cli_detects(self):
        self.assertEqual(cli.agent_names(None), ["*"])

    def test_selection_maps_own_ids_and_passes_others_through(self):
        names = cli.agent_names(["claude-code", "hermes", "antigravity", "cursor"])
        self.assertEqual(names, ["claude-code", "hermes-agent", "antigravity",
                                 "antigravity-cli", "cursor"])

    def test_claude_desktop_shares_claude_code_and_adds_no_agent(self):
        self.assertEqual(cli.agent_names(["claude-desktop"]), [])

    def test_argv_pins_the_version_and_stays_non_interactive(self):
        argv = cli.skills_argv(Path("/src/demo"), ["claude-code"], copy=True)
        self.assertEqual(argv[1:4], ["-y", f"skills@{cli.SKILLS_VERSION}", "add"])
        self.assertIn("-g", argv)
        self.assertIn("--copy", argv)
        self.assertEqual(argv[-1], "-y")

    def test_delegated_environment_carries_no_credentials(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "secret", "GH_TOKEN": "secret",
                                     "ANTHROPIC_API_KEY": "secret",
                                     "COPILOT_GITHUB_TOKEN": "secret"}, clear=False):
            env = cli.hardened_env()
        self.assertEqual(env["npm_config_ignore_scripts"], "true")
        for name in ("GITHUB_TOKEN", "GH_TOKEN", "ANTHROPIC_API_KEY", "COPILOT_GITHUB_TOKEN"):
            self.assertNotIn(name, env)
        self.assertIn("PATH", env)

    def test_dry_run_never_starts_the_cli(self):
        def boom(*args, **kwargs):
            raise AssertionError("dry run executed the CLI")

        with patch.object(cli, "npx_path", return_value="npx"), \
             patch.object(cli, "run_bounded", boom), \
             patch.object(cli, "verify_pinned_package", boom):
            handled, names = cli.distribute(Path("/src/demo"), dry=True)
        self.assertTrue(handled)
        self.assertEqual(names, ["*"])


class FallbackTests(unittest.TestCase):
    def _distribute(self, **patches):
        defaults = {"npx_path": lambda: "npx",
                    "verify_pinned_package": lambda force=False: True}
        defaults.update(patches)
        with patch.multiple(cli, **defaults):
            return cli.distribute(Path("/src/demo"), dry=False)

    def test_disabled_by_environment(self):
        with patch.dict(os.environ, {"AGENT_GUARD_SKILLS_CLI": "0"}):
            self.assertEqual(cli.distribute(Path("/src/demo"), dry=False), (False, []))

    def test_missing_npx(self):
        self.assertEqual(self._distribute(npx_path=lambda: None), (False, []))

    def test_failed_verification(self):
        self.assertEqual(self._distribute(verify_pinned_package=lambda force=False: False),
                         (False, []))

    def test_non_zero_exit(self):
        result = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
        self.assertEqual(self._distribute(run_bounded=lambda *a, **k: result), (False, []))

    def test_timeout(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("npx", 1)

        self.assertEqual(self._distribute(run_bounded=timeout), (False, []))

    def test_cli_glyphs_do_not_break_reporting(self):
        result = subprocess.CompletedProcess([], 0, stdout="✔ installed │", stderr="")
        handled, _ = self._distribute(run_bounded=lambda *a, **k: result)
        self.assertTrue(handled)


class InstallerIntegrationTests(unittest.TestCase):
    def test_targets_split_between_our_ids_and_cli_agent_names(self):
        own, for_cli = installer.split_targets(["codex", "cursor"])
        self.assertEqual(own, ["codex"])
        self.assertEqual(for_cli, ["codex", "cursor"])
        self.assertEqual(installer.split_targets(None), (None, None))

    def test_empty_selection_detects_nothing(self):
        self.assertEqual(installer.detect_tools([]), {})

    def test_top_up_links_only_paths_the_cli_left_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canonical = root / "canonical" / "demo"
            canonical.mkdir(parents=True)
            (canonical / "SKILL.md").write_text("# Demo", encoding="utf-8")
            covered = root / "covered"
            (covered / "demo").mkdir(parents=True)
            empty = root / "empty"
            empty.mkdir()

            tools = {
                "claude-code": {"label": "Claude Code", "detect": [], "skills": covered},
                "codex": {"label": "Codex", "detect": [], "skills": empty},
                "hermes": {"label": "Hermes", "detect": [], "skills": root / "absent"},
            }
            with patch.object(installer, "TOOLS", tools):
                installer.top_up_verified_paths(
                    canonical, "demo",
                    {"claude-code": True, "codex": True, "hermes": False}, dry=False)

            self.assertTrue((empty / "demo").exists())
            self.assertFalse((root / "absent").exists())

    def test_distributed_copy_must_match_the_scanned_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scanned = root / "scanned"
            scanned.mkdir()
            (scanned / "SKILL.md").write_text("reviewed", encoding="utf-8")
            canonical = root / "canonical"
            canonical.mkdir()
            (canonical / "SKILL.md").write_text("tampered", encoding="utf-8")
            with self.assertRaises(SystemExit):
                installer.verify_distributed_copy(scanned, canonical)

            (canonical / "SKILL.md").write_text("reviewed", encoding="utf-8")
            (canonical / "NOTES.md").write_text("unscanned", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()) as err:
                installer.verify_distributed_copy(scanned, canonical)
            self.assertEqual(ctx.exception.code, 2)      # extra files are unscanned content
            self.assertIn("NOTES.md", err.getvalue())
            self.assertIn("already in place", err.getvalue())   # the skill is live
            self.assertIn(str(canonical), err.getvalue())
            self.assertIn("review it before use or remove it", err.getvalue())
            self.assertTrue((canonical / "NOTES.md").exists())   # nothing is deleted

    def test_missing_canonical_copy_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanned = Path(tmp) / "scanned"
            scanned.mkdir()
            (scanned / "SKILL.md").write_text("reviewed", encoding="utf-8")
            with self.assertRaises(SystemExit):
                installer.verify_distributed_copy(scanned, Path(tmp) / "nope")


class VerifyUpdateFailureTests(unittest.TestCase):
    """verify_skills_cli --update must not report success when it has nothing to review."""

    def setUp(self):
        self.tool = importlib.import_module("verify_skills_cli")
        self.meta = {"dist": {"shasum": "abc", "integrity": "sha512-xyz"}}

    def _update(self, **fakes):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out),              patch.object(cli, "registry_metadata", **fakes.get("meta", {"return_value": self.meta})),              patch.object(cli, "guarddog_report", **fakes.get("report", {"return_value": guarddog_report()})):
            return self.tool.update("9.9.9"), out.getvalue()

    def test_registry_metadata_failure_is_no_verdict(self):
        for error in (OSError("offline"), ValueError("bad json"), TimeoutError()):
            with self.subTest(error=type(error).__name__):
                code, out = self._update(meta={"side_effect": error})
                self.assertEqual(code, 2)
                self.assertNotIn("Draft for", out)

    def test_missing_digests_are_no_verdict(self):
        for meta in ({}, {"dist": {}}, {"dist": {"shasum": "abc"}},
                     {"dist": {"integrity": "sha512-xyz"}}, {"dist": None}):
            with self.subTest(meta=meta):
                code, out = self._update(meta={"return_value": meta})
                self.assertEqual(code, 2)
                self.assertNotIn("Draft for", out)

    def test_missing_scanner_report_is_no_verdict(self):
        code, out = self._update(report={"return_value": None})
        self.assertEqual(code, 2)
        self.assertNotIn("Draft for", out)

    def test_guarddog_timeout_or_garbage_gives_no_report(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("docker", 1)

        garbage = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
        for label, fake in (("timeout", timeout), ("garbage", lambda *a, **k: garbage)):
            with self.subTest(label),                  patch.object(cli, "run_bounded", fake),                  patch.object(cli, "registry_metadata", return_value=self.meta):
                import contextlib
                import io
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(self.tool.update("9.9.9"), 2)

    def test_main_passes_the_failure_code_on(self):
        import contextlib
        import io
        with patch.object(sys, "argv", ["verify_skills_cli.py", "--update", "9.9.9"]),              patch.object(cli, "registry_metadata", side_effect=OSError("offline")),              contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.tool.main(), 2)


if __name__ == "__main__":
    unittest.main()
