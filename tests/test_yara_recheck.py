"""YARA corrections: a built-in rule match is rechecked with the corrected rule.

Unit tests use a fake runner. The integration test runs the boot script in
SkillSpector's environment against stealer paths that are assembled at run time,
so this file never carries a signature the self-scan would match.
"""
import base64
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
y = importlib.import_module("_yara_recheck")

# Stealer paths, parts separated by | and joined with a real separator at run time.
STEALER_PATHS = [
    ("\\", "LOCALAPPDATA|Google|Chrome|User Data|Default|Network|Cookies"),
    ("\\", "LOCALAPPDATA|Microsoft|Edge|User Data|Default|Network|Cookies"),
    ("/", "~|.config|BraveSoftware|Brave-Browser|User Data|Default|Cookies"),
    ("/", "~|Library|Application Support|Google|Chrome|Default|Cookies"),
    ("\\", "APPDATA|Opera Software|Opera Stable|Network|Cookies"),
    ("/", "profiles|abc.default-release|cookies.sqlite"),
]
# Prose the built-in rule matches; {c} becomes the word for the browser store at
# run time, so this file itself does not match.
HARMLESS = [s.format(c=c) for s, c in (
    ("auth issues (login, logout, sessions, JWT, {c}, getSession, getUser, getClaims, RLS); "
     "Supabase CLI or MCP server; debugging timeouts, Edge Function crashes", "cookies"),
    ("Set {c} for Edge Functions with the SSR helper.", "cookies"),
    ("{c} set by the Edge middleware are httpOnly.", "Cookies"),
    ("Forward {c} to Chrome headless through the Playwright context.", "cookies"),
)]
STEALER_CODE = [
    "Y29va2llc19kYiA9IHNxbGl0ZTMuY29ubmVjdChjaHJvbWVfcHJvZmlsZSArICIvQ29va2llcyIp",
    "c2h1dGlsLmNvcHkocHJvZmlsZSAvICJDb29raWVzIiwgY2hyb21lX291dCk=",
    "ZGIgPSBvcy5wYXRoLmpvaW4oQ0hST01FX0RJUiwgIkRlZmF1bHQiLCAiQ29va2llcyIp",
    "c3RlYWwoIkNvb2tpZXMiLCAiZmlyZWZveCIp",
    "Z3JhYl9jb29raWVzKGJyb3dzZXI9ImVkZ2UiKQ==",
    "Y29va2llcyA9IHJlYWQob3BlcmEucHJvZmlsZSk=",
]
# The built-in rule does not match this one at all: nothing to correct.
UNMATCHED = "Open Chrome DevTools > Application > Cookies to inspect the session."


def stealer(sep, parts):
    return sep.join(parts.split("|"))


class CatalogTests(unittest.TestCase):
    def test_shipped_catalog_matches_the_pin(self):
        import _pins
        data = y.load_corrections()
        self.assertEqual(data["skillspector"], _pins.SKILLSPECTOR_VERSION)
        self.assertEqual([r["name"] for r in data["rule"]], ["info_stealer"])
        self.assertTrue((y.CORRECTIONS.parent / data["corrected"]).is_file())

    def test_malformed_catalog_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text('version = 1\nskillspector = "2.12.0"\ncorrected = "x"\n'
                            '[[rule]]\nname = "info_stealer"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                y.load_corrections(path)


class AnswerTests(unittest.TestCase):
    def test_only_original_match_clears(self):
        self.assertIs(y.parse_answer({"original": True, "corrected": False}), True)

    def test_corrected_match_keeps_it(self):
        self.assertIs(y.parse_answer({"original": True, "corrected": True}), False)

    def test_anything_else_is_unknown(self):
        for item in ({"original": False, "corrected": False}, {"error": "x"}, None, [],
                     {"original": "yes", "corrected": False}, {"original": True}):
            self.assertIsNone(y.parse_answer(item), item)


class RecheckerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "SKILL.md").write_text("x\n", encoding="utf-8")
        self.calls = []

        def runner(checks, rules):
            self.calls.append([(rule, path.name) for rule, path in checks])
            return [True] * len(checks)
        self.recheck = y.Rechecker(runner, y.load_corrections())

    def test_asks_only_for_corrected_rules(self):
        out = self.recheck(self.dir, [("info_stealer", "SKILL.md"), ("reverse_shell", "SKILL.md")])
        self.assertEqual(out, {("info_stealer", "SKILL.md"): True})
        self.assertEqual(self.calls, [[("info_stealer", "SKILL.md")]])

    def test_out_of_tree_file_is_not_checked(self):
        out = self.recheck(self.dir, [("info_stealer", "../outside.md"),
                                      ("info_stealer", "missing.md")])
        self.assertEqual(out, {("info_stealer", "../outside.md"): None,
                               ("info_stealer", "missing.md"): None})
        self.assertEqual(self.calls, [])

    def test_runner_failure_is_unknown(self):
        def broken(checks, rules):
            raise OSError("no venv")
        out = y.Rechecker(broken, y.load_corrections())(self.dir, [("info_stealer", "SKILL.md")])
        self.assertEqual(out, {("info_stealer", "SKILL.md"): None})


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1", "integration")
class BootTests(unittest.TestCase):
    """The boot script in SkillSpector's environment, with the real YARA engine."""

    @classmethod
    def setUpClass(cls):
        import _skillspector
        cls.python = _skillspector.skillspector_python()
        if cls.python is None:
            raise unittest.SkipTest("no SkillSpector environment")
        cls.rules = {r["name"]: r for r in y.load_corrections()["rule"]}

    def run_on(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.md"
            path.write_bytes(text.encode("utf-8"))
            return y.run_boot(self.python, [("info_stealer", path)], self.rules)[0]

    def test_harmless_prose_is_cleared(self):
        for text in HARMLESS:
            with self.subTest(text=text[:40]):
                self.assertIs(self.run_on(text), True)

    def test_stealer_paths_stay(self):
        # Behind prose the built-in rule matches, every stealer path keeps the match.
        for sep, parts in STEALER_PATHS:
            with self.subTest(parts=parts):
                text = f"{HARMLESS[1]}\np = '{stealer(sep, parts)}'\n"
                self.assertIs(self.run_on(text), False)

    def test_stealer_code_naming_the_store_first_stays(self):
        # Code that names the store before the browser, which the built-in
        # string also matches (base64: the source must not match it itself).
        for encoded in STEALER_CODE:
            code = base64.b64decode(encoded).decode()
            with self.subTest(code=code):
                self.assertIs(self.run_on(f"{HARMLESS[1]}\n{code}\n"), False)

    def test_prose_and_stealer_in_one_file_stays(self):
        sep, parts = STEALER_PATHS[0]
        self.assertIs(self.run_on(HARMLESS[0] + "\n" + stealer(sep, parts) + "\n"), False)

    def test_file_without_any_match_is_unknown(self):
        self.assertIsNone(self.run_on("nothing to see\n"))
        self.assertIsNone(self.run_on(UNMATCHED))

    def test_changed_builtin_rule_is_an_error(self):
        rules = {"info_stealer": dict(self.rules["info_stealer"], original_sha256="0" * 64)}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.md"
            path.write_text(HARMLESS[1], encoding="utf-8")
            self.assertIsNone(y.run_boot(self.python, [("info_stealer", path)], rules)[0])


if __name__ == "__main__":
    unittest.main()
