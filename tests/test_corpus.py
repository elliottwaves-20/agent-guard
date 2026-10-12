"""The calibration corpus manifest is well-formed, and its pins still resolve.

The offline tests guard the manifest itself. The integration test fetches every
entry and checks its content hash, so a moved tag, a rewritten history or a
changed sample shows up here and not as a silent shift in triage results.
"""
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _corpus as corpus

HEX64 = re.compile(r"[0-9a-f]{64}")


def assert_meets_expectation(case, sample, result, _triage, verified=False):
    """Open rules the manifest names stay open on purpose: dangerous, only those.
    With the verifier in the chain (`verified`) it may settle them; the verdict is
    then the expected one. A finding it confirms still fails the expectation."""
    still_open = [(d.finding.rule, d.reason) for d in result.by_status(_triage.OPEN)]
    if verified and sample.open and result.verdict == sample.expect:
        return
    if sample.open:
        case.assertEqual(result.verdict, "dangerous", still_open)
        case.assertEqual({r for r, _ in still_open}, set(sample.open),
                         (still_open, sample.open_until))
    else:
        case.assertEqual(result.verdict, sample.expect, still_open)


class ExpectationTests(unittest.TestCase):
    """What counts as meeting an `open` expectation, with and without the verifier."""

    def result(self, verdict, *statuses):
        import _triage
        from types import SimpleNamespace
        ds = [SimpleNamespace(finding=SimpleNamespace(rule="SC2"), status=s, reason="r")
              for s in statuses]
        return SimpleNamespace(verdict=verdict,
                               by_status=lambda st: [d for d in ds if d.status == st]), _triage

    def sample(self):
        from types import SimpleNamespace
        return SimpleNamespace(expect="safe", open=("SC2",), open_until="agent-guard#14")

    def test_static_chain_keeps_the_rule_open(self):
        result, tr = self.result("dangerous", "open")
        assert_meets_expectation(self, self.sample(), result, tr)
        result, tr = self.result("safe", "cleared")
        with self.assertRaises(AssertionError):
            assert_meets_expectation(self, self.sample(), result, tr)

    def test_verifier_may_settle_the_open_rule(self):
        result, tr = self.result("safe", "cleared")
        assert_meets_expectation(self, self.sample(), result, tr, verified=True)

    def test_a_confirmed_finding_still_fails(self):
        result, tr = self.result("dangerous", "confirmed")
        with self.assertRaises(AssertionError):
            assert_meets_expectation(self, self.sample(), result, tr, verified=True)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.samples = corpus.load_manifest()

    def test_both_kinds_are_present(self):
        kinds = {s.kind for s in self.samples}
        self.assertEqual(kinds, {"benign", "malicious"})

    def test_ids_are_unique(self):
        ids = [s.id for s in self.samples]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_entry_is_pinned_to_a_commit_and_a_hash(self):
        for s in self.samples:
            with self.subTest(s.id):
                self.assertRegex(s.ref, corpus.staging.SHA)
                self.assertRegex(s.tree_hash, HEX64)
                corpus.staging.check_source(s.source)

    def test_expectations_match_the_kind(self):
        for s in self.samples:
            with self.subTest(s.id):
                self.assertIn(s.expect, corpus.VERDICTS)
                self.assertEqual(s.expect, "safe" if s.kind == "benign" else "dangerous")

    def test_benign_entries_name_the_noise_they_produce(self):
        for s in self.samples:
            if s.kind == "benign":
                with self.subTest(s.id):
                    self.assertTrue(s.noise)

    def test_open_rules_are_noise_and_name_the_issue_that_closes_them(self):
        for s in self.samples:
            with self.subTest(s.id):
                self.assertEqual(bool(s.open), bool(s.open_until))
                if s.open:
                    self.assertRegex(s.open_until, r"agent-guard#\d+")
                    self.assertLessEqual(set(s.open), set(s.noise))


class VerifyTests(unittest.TestCase):
    def test_changed_content_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x"
            path.mkdir()
            (path / "SKILL.md").write_text("a", encoding="utf-8")
            sample = corpus.Sample("x", "benign", "safe", "0" * 64, "o/r", "a" * 40)
            with self.assertRaises(corpus.CorpusError):
                corpus.verify(sample, path)

    def test_malicious_samples_must_share_one_pin(self):
        a = corpus.Sample("a", "malicious", "dangerous", "0" * 64, "o/r", "a" * 40)
        b = corpus.Sample("b", "malicious", "dangerous", "0" * 64, "o/r", "b" * 40)
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(corpus.resolver, "http_bytes") as download:
            with self.assertRaises(corpus.CorpusError):
                corpus.fetch_malicious([a, b], Path(tmp))
            download.assert_not_called()


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to fetch and scan the corpus")
class CorpusAcceptanceTests(unittest.TestCase):
    """Every triage change must keep attacks dangerous and the known noise safe."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.samples = {s.id: s for s in corpus.load_manifest()}
        cls.fetched = corpus.fetch_all(Path(cls.tmp.name) / "src", tuple(cls.samples.values()))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_entry_resolves_to_its_pinned_content(self):
        self.assertEqual(set(self.fetched), set(self.samples))

    def test_static_triage_meets_every_expectation(self):
        import contextlib
        import io
        import json
        import subprocess
        import _skillspector as ss
        import _parse_spans
        import _yara_recheck
        import _triage
        ss.need_skillspector()
        for sid, path in sorted(self.fetched.items()):
            sample = self.samples[sid]
            if sample.needs_llm:
                continue
            with self.subTest(sid):
                out = Path(self.tmp.name) / f"{sid}.json"
                cmd = ss.skillspector_command() + ["scan", str(path), "--no-llm", "--format",
                                                   "json", "--output", str(out)]
                done = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                      errors="replace", env=ss.skillspector_env(), timeout=900)
                with contextlib.redirect_stdout(io.StringIO()):
                    raw = ss.verdict_skillspector(out, done.returncode)
                result = _triage.triage(json.loads(out.read_text(encoding="utf-8")), path, raw,
                                        origin=_triage.Origin(sample.source, sample.ref),
                                        spans=_parse_spans.from_skillspector(),
                                        yara=_yara_recheck.from_skillspector())
                assert_meets_expectation(self, sample, result, _triage)


@unittest.skipUnless(os.environ.get("AGENT_GUARD_LLM_INTEGRATION") == "1",
                     "set AGENT_GUARD_LLM_INTEGRATION=1 to scan the corpus with the LLM layer "
                     "and the verifier (real subscription budget, ~25 min)")
class LiveCorpusAcceptanceTests(unittest.TestCase):
    """The full chain -- LLM scan, triage, verifier -- meets every expectation,
    including the sample only an LLM can catch."""

    def test_full_chain_meets_every_expectation(self):
        import importlib
        import json
        from unittest.mock import patch as patch_env
        import _skillspector as ss
        import _parse_spans
        import _yara_recheck
        import _triage
        import _verifier
        from test_llm_integration import live_selection
        env, label = live_selection(os.environ)
        with tempfile.TemporaryDirectory() as tmp, patch_env.dict(os.environ, env):
            importlib.reload(ss)
            try:
                self.assertTrue(ss.LLM_READY, f"{label}: {ss.LLM_REASON}")
                verifier = _verifier.from_setup()
                self.assertIsNotNone(verifier, f"{label}: no verifier (LLM not ready or provider refused)")
                samples = {s.id: s for s in corpus.load_manifest()}
                fetched = corpus.fetch_all(Path(tmp) / "src", tuple(samples.values()))
                for sid, path in sorted(fetched.items()):
                    sample = samples[sid]
                    with self.subTest(sid):
                        out = Path(tmp) / f"{sid}.json"
                        raw = ss.run_skillspector(path, report_output=out)
                        data = json.loads(out.read_text(encoding="utf-8"))
                        self.assertEqual(ss.llm_run_incomplete(data, expected=True), "")
                        result = _triage.triage(data, path, raw, verifier=verifier,
                                                origin=_triage.Origin(sample.source, sample.ref),
                                                spans=_parse_spans.from_skillspector(),
                                                yara=_yara_recheck.from_skillspector())
                        assert_meets_expectation(self, sample, result, _triage, verified=True)
            finally:
                importlib.reload(ss)


if __name__ == "__main__":
    unittest.main()
