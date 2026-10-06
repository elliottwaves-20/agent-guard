"""User-level agent-guard configuration: discovery, validation, secret refusal."""
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
uc = importlib.import_module("_user_config")


class UserConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def load(self, env, platform="linux"):
        return uc.load_config(env=env, platform=platform, home=self.home)

    def test_no_config_anywhere_yields_empty_config(self):
        self.assertEqual(self.load({}), {})
        self.assertEqual(self.load({"APPDATA": str(self.root / "appdata")}, "win32"), {})

    def test_explicit_path_wins_over_default_locations(self):
        explicit = self.write(self.root / "custom.toml", '[distribution]\nmode = "store"\n')
        self.write(self.home / ".config" / "agent-guard" / "config.toml",
                   '[distribution]\nmode = "skills-cli"\n')
        cfg = self.load({"AGENT_GUARD_CONFIG": str(explicit)})
        self.assertEqual(cfg["distribution"]["mode"], "store")

    def test_explicit_path_that_does_not_exist_is_an_error(self):
        with self.assertRaises(uc.ConfigError):
            self.load({"AGENT_GUARD_CONFIG": str(self.root / "missing.toml")})

    def test_windows_reads_appdata_location(self):
        appdata = self.root / "appdata"
        self.write(appdata / "agent-guard" / "config.toml", '[distribution]\nmode = "store"\n')
        cfg = self.load({"APPDATA": str(appdata)}, "win32")
        self.assertEqual(cfg["distribution"]["mode"], "store")

    def test_posix_prefers_xdg_over_home_config(self):
        xdg = self.root / "xdg"
        self.write(xdg / "agent-guard" / "config.toml", '[distribution]\nmode = "store"\n')
        self.write(self.home / ".config" / "agent-guard" / "config.toml",
                   '[distribution]\nmode = "skills-cli"\n')
        self.assertEqual(self.load({"XDG_CONFIG_HOME": str(xdg)})["distribution"]["mode"], "store")
        self.assertEqual(self.load({})["distribution"]["mode"], "skills-cli")

    def test_missing_home_directory_means_no_default_config(self):
        with patch.object(uc.Path, "home", side_effect=RuntimeError("no home")):
            self.assertEqual(uc.load_config(env={}, platform="linux"), {})

    def test_opt_out_skips_default_locations_but_keeps_explicit_path(self):
        self.write(self.home / ".config" / "agent-guard" / "config.toml",
                   '[distribution]\nmode = "store"\n')
        self.assertEqual(self.load({"AGENT_GUARD_NO_USER_CONFIG": "1"}), {})
        explicit = self.write(self.root / "custom.toml", '[distribution]\nmode = "skills-cli"\n')
        cfg = self.load({"AGENT_GUARD_NO_USER_CONFIG": "1", "AGENT_GUARD_CONFIG": str(explicit)})
        self.assertEqual(cfg["distribution"]["mode"], "skills-cli")

    def test_secret_value_is_refused_without_echoing_it(self):
        secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
        path = self.write(self.root / "c.toml",
                          f'[llm.profiles.x]\nkind = "api"\nnote = "{secret}"\n')
        with self.assertRaises(uc.ConfigError) as ctx:
            self.load({"AGENT_GUARD_CONFIG": str(path)})
        self.assertNotIn(secret, str(ctx.exception))
        self.assertIn("llm.profiles.x.note", str(ctx.exception))

    def test_secret_named_field_is_refused(self):
        path = self.write(self.root / "c.toml",
                          '[llm.profiles.x]\nkind = "api"\napi_key = "anything"\n')
        with self.assertRaises(uc.ConfigError):
            self.load({"AGENT_GUARD_CONFIG": str(path)})

    def test_settings_table_cannot_carry_a_key(self):
        path = self.write(self.root / "c.toml",
                          '[llm.profiles.x]\nkind = "api"\nsettings = { ANTHROPIC_API_KEY = "x" }\n')
        with self.assertRaises(uc.ConfigError):
            self.load({"AGENT_GUARD_CONFIG": str(path)})

    def test_key_env_names_a_variable_and_is_allowed(self):
        path = self.write(self.root / "c.toml",
                          '[llm.profiles.x]\nkind = "api"\nkey_env = "CEREBRAS_API_KEY"\n')
        cfg = self.load({"AGENT_GUARD_CONFIG": str(path)})
        self.assertEqual(cfg["llm"]["profiles"]["x"]["key_env"], "CEREBRAS_API_KEY")

    def test_unknown_top_level_section_is_refused(self):
        path = self.write(self.root / "c.toml", '[distributon]\nmode = "store"\n')
        with self.assertRaises(uc.ConfigError):
            self.load({"AGENT_GUARD_CONFIG": str(path)})

    def test_invalid_toml_is_an_error(self):
        path = self.write(self.root / "c.toml", "[llm\nbroken")
        with self.assertRaises(uc.ConfigError):
            self.load({"AGENT_GUARD_CONFIG": str(path)})

    def test_existing_config_without_toml_support_is_an_error(self):
        path = self.write(self.root / "c.toml", '[distribution]\nmode = "store"\n')
        with patch.object(uc, "tomllib", None):
            with self.assertRaises(uc.ConfigError):
                self.load({"AGENT_GUARD_CONFIG": str(path)})
            self.assertEqual(self.load({}), {})


class WrapperConfigGateTests(unittest.TestCase):
    """Every wrapper imports _skillspector; a broken config must stop it early."""

    def run_import(self, config_text):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(config_text, encoding="utf-8")
            env = dict(os.environ, AGENT_GUARD_CONFIG=str(path), AGENT_GUARD_NO_DOTENV="1")
            scripts = str(Path(__file__).resolve().parents[1] / "scripts")
            return subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, sys.argv[1]); import _skillspector as s; "
                 "print(sorted(s.USER_CONFIG))", scripts],
                capture_output=True, text=True, env=env, timeout=60)

    def test_broken_config_stops_the_wrapper_with_exit_2(self):
        result = self.run_import('[llm.profiles.x]\napi_key = "x"\n')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("api_key", result.stdout + result.stderr)

    def test_valid_config_is_exposed_to_wrappers(self):
        result = self.run_import('[distribution]\nmode = "store"\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("['distribution']", result.stdout)


if __name__ == "__main__":
    unittest.main()
