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
                     "set AGENT_GUARD_INTEGRATION=1 to fetch the corpus")
class FetchTests(unittest.TestCase):
    def test_every_entry_resolves_to_its_pinned_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            fetched = corpus.fetch_all(Path(tmp))
            self.assertEqual(set(fetched), {s.id for s in corpus.load_manifest()})


if __name__ == "__main__":
    unittest.main()
