"""Drawing the benign holdout: reproducible, and never a skill we have seen."""
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
ev = importlib.import_module("_eval")

LISTING = {"a/x": ["one", "two", "three"], "b/y": ["four", "five"], "c/z": ["six"]}


class DrawTests(unittest.TestCase):
    def test_draw_is_deterministic(self):
        self.assertEqual(ev.draw(LISTING, set(), 2, 7), ev.draw(LISTING, set(), 2, 7))

    def test_draw_excludes_seen_names(self):
        picked = ev.draw(LISTING, {"one", "four"}, 2, 7)
        self.assertNotIn("one", [n for _, n in picked])
        self.assertNotIn("four", [n for _, n in picked])

    def test_at_most_per_repo_from_each_source(self):
        picked = ev.draw(LISTING, set(), 2, 7)
        for source in LISTING:
            self.assertLessEqual(sum(1 for s, _ in picked if s == source), 2)
        self.assertEqual(sum(1 for s, _ in picked if s == "c/z"), 1)

    def test_skill_names_come_from_the_cli_listing(self):
        # Names are what the skills CLI installs (SKILL.md `name`), not directories.
        text = ("\x1b[36m◇\x1b[0m  Found 2 skills\n│\n◇  Available Skills\n│\n"
                "│    vercel-react-best-practices\n│\n│      React guidelines.\n│\n"
                "│    deploy-to-vercel\n│\n│      Deploy apps. Use when asked to\n│\n└  Done\n")
        self.assertEqual(ev.parse_cli_list(text),
                         ["deploy-to-vercel", "vercel-react-best-practices"])

    def test_listing_without_skills_section_is_empty(self):
        self.assertEqual(ev.parse_cli_list("■  Failed to clone repository\n"), [])

    def test_load_returns_only_fresh_entries(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "h.toml"
            p.write_text('version = 1\nseed = 7\n'
                         '[[benign]]\nname = "one"\nsource = "a/x"\nref = "' + "a" * 40 + '"\n'
                         'tree_hash = "h1"\nstatus = "fresh"\n'
                         '[[benign]]\nname = "two"\nsource = "a/x"\nref = "' + "a" * 40 + '"\n'
                         'tree_hash = "h2"\nstatus = "retired"\n', encoding="utf-8")
            loaded = ev.load(p)
            self.assertEqual([(s.id, s.kind, s.expect, s.tree_hash) for s in loaded],
                             [("one", "benign", "safe", "h1")])


if __name__ == "__main__":
    unittest.main()
