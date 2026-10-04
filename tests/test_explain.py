"""Plain-language output: outcome first, scanner vocabulary only on request."""
import importlib
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
t = importlib.import_module("_triage")
x = importlib.import_module("_explain")


def disp(rule, status, llm=False, severity="HIGH"):
    f = t.Finding(rule=rule, severity=severity, file="SKILL.md", line=3, snippet="", llm=llm)
    return t.Disposition(f, status, None, "reason text")


def result(verdict, *items):
    return t.Result(verdict, list(items))


class ExplainTests(unittest.TestCase):
    def test_safe_counts_checked_notes_without_jargon(self):
        text = x.explain(result(t.SAFE, disp("TP4", t.CLEARED, llm=True)), "music", lang="en")
        self.assertIn("SAFE: music", text)
        self.assertIn("1 automatic scanner note(s) were checked and are harmless", text)
        for word in ("TP4", "HIGH", "CRITICAL", "false"):
            self.assertNotIn(word, text)

    def test_dangerous_names_the_most_telling_reason(self):
        text = x.explain(result(t.DANGEROUS, disp("PE2", t.OPEN), disp("TT3", t.HARD)),
                         "csv-tidy", lang="en")
        self.assertIn("sends data such as credentials", text)
        self.assertIn("do not use", text)
        self.assertNotIn("TT3", text)

    def test_reasons_by_rule_family(self):
        cases = {"YR1": "malware", "AST8": "hidden_code", "E2": "exfil", "P2": "steer_ai",
                 "AR1": "steer_ai", "PE3": "credentials", "SC2": "foreign_installer",
                 "PE2": "admin", "EA1": "other", "PE1": "other"}
        for rule, key in cases.items():
            with self.subTest(rule):
                self.assertEqual(x.why_key(rule), key)

    def test_open_llm_findings_do_not_supply_the_danger_reason(self):
        text = x.explain(result(t.DANGEROUS, disp("TP4", t.OPEN, llm=True), disp("YR2", t.HARD)),
                         "s", lang="en")
        self.assertIn("malware", text)

    def test_unclear_asks_with_a_recommendation(self):
        text = x.explain(result(t.UNCLEAR, disp("TP4", t.OPEN, llm=True)), "abc", lang="en")
        self.assertIn("YOUR DECISION: abc -- 1 point(s)", text)
        self.assertIn("trust its publisher", text)

    def test_no_verdict_is_never_reported_as_safe(self):
        text = x.explain(result(t.NO_VERDICT), "abc", lang="en")
        self.assertTrue(text.startswith("NOT INSTALLED"))

    def test_details_show_the_scanner_vocabulary(self):
        text = x.explain(result(t.SAFE, disp("TP4", t.CLEARED, llm=True)), "m", lang="en",
                         details=True)
        self.assertIn("HIGH TP4 @ SKILL.md:3 -- checked, harmless: reason text", text)

    def test_german(self):
        text = x.explain(result(t.SAFE), "music", lang="de")
        self.assertIn("SICHER: music kann installiert werden.", text)
        self.assertEqual(x.language({"AGENT_GUARD_LANG": "de_DE"}), "de")
        self.assertEqual(x.language({"AGENT_GUARD_LANG": "fr"}), "en")
        self.assertEqual(set(x.TEXT["de"]), set(x.TEXT["en"]))

    def test_as_dict_carries_everything(self):
        data = x.as_dict(result(t.UNCLEAR, disp("TP4", t.OPEN, llm=True)), "abc")
        self.assertEqual(data["verdict"], "unclear")
        self.assertEqual(data["findings"][0]["rule"], "TP4")
        self.assertTrue(data["findings"][0]["llm"])


if __name__ == "__main__":
    unittest.main()
