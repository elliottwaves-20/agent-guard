"""The SkillSpector provider catalog: the one place that says which providers exist."""
from pathlib import Path
import sys
import unittest
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
import _providers as pv


class CatalogTests(unittest.TestCase):
    def test_every_skillspector_provider_of_the_pin_is_listed(self):
        expected = {"openai", "anthropic", "anthropic_proxy", "bedrock", "nv_build",
                    "nv_inference", "ollama", "azure_openai", "openai_compatible", "gemini",
                    "claude_cli", "gemini_cli", "opencode_cli", "codex_cli", "antigravity_cli"}
        self.assertEqual(set(pv.CATALOG), expected)

    def test_codex_and_antigravity_are_disabled_with_a_reason(self):
        for pid in ("codex_cli", "antigravity_cli"):
            with self.subTest(pid):
                with self.assertRaises(pv.DisabledProvider) as ctx:
                    pv.check_enabled(pid)
                self.assertIn(pid, str(ctx.exception))
                self.assertTrue(pv.CATALOG[pid].disabled)

    def test_autodetect_never_offers_a_disabled_provider(self):
        for pid in pv.AUTODETECT_KEYS + pv.AUTODETECT_CLIS:
            self.assertFalse(pv.CATALOG[pid].disabled, pid)
        self.assertEqual(pv.AUTODETECT_CLIS, ("claude_cli", "opencode_cli"))

    def test_required_vars_are_declared_secrets_or_settings(self):
        for p in pv.CATALOG.values():
            with self.subTest(p.id):
                self.assertTrue(set(p.required) <= set(p.secrets) | set(p.settings))
                self.assertEqual(p.kind == "cli", bool(p.binary))

    def test_settings_never_name_a_credential(self):
        import _user_config
        for p in pv.CATALOG.values():
            for var in p.settings:
                self.assertIsNone(_user_config.SECRET_FIELD.search(var), (p.id, var))

    def test_aliases_point_at_catalog_entries(self):
        for alias, target in pv.ALIASES.items():
            self.assertIn(target, pv.CATALOG, alias)
        self.assertEqual(pv.ALIASES["codex"], "codex_cli")  # resolves, then refused
        self.assertEqual(pv.cli_for_binary("opencode").id, "opencode_cli")

    def test_unknown_provider(self):
        self.assertIsNone(pv.get("nope"))
        with self.assertRaises(KeyError):
            pv.check_enabled("nope")
