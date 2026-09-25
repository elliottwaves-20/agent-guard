"""LLM profiles: selection, validation and translation into scanner-native env."""
import importlib
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
lp = importlib.import_module("_llm_profile")

LUNA = {"kind": "cli", "cli": "codex", "model": "gpt-6-luna"}
CEREBRAS = {"kind": "api", "protocol": "openai", "base_url": "https://api.cerebras.ai/v1",
            "model": "gpt-oss-120b", "key_env": "CEREBRAS_API_KEY"}
HAIKU = {"kind": "api", "protocol": "native", "provider": "anthropic",
         "model": "claude-haiku-4-5", "key_env": "MY_ANTHROPIC"}


def config(use=None, **profiles):
    return {"llm": {"use": use or {}, "profiles": profiles}}


def on_path(name):
    return f"/bin/{name}"


def nowhere(name):
    return None


class SelectionTests(unittest.TestCase):
    def test_no_llm_section_means_legacy_resolution(self):
        self.assertIsNone(lp.select_profile({}, "skills", {}))
        self.assertIsNone(lp.select_profile({"distribution": {}}, "mcp", {}))

    def test_use_table_picks_profile_per_scanner(self):
        cfg = config({"skills": "luna", "mcp": "cerebras"}, luna=LUNA, cerebras=CEREBRAS)
        self.assertEqual(lp.select_profile(cfg, "skills", {})[0], "luna")
        self.assertEqual(lp.select_profile(cfg, "mcp", {})[0], "cerebras")

    def test_scanner_without_use_entry_keeps_legacy_resolution(self):
        cfg = config({"skills": "luna"}, luna=LUNA)
        self.assertIsNone(lp.select_profile(cfg, "mcp", {}))

    def test_run_override_beats_use_and_scanner_override_beats_both(self):
        cfg = config({"skills": "luna", "mcp": "cerebras"}, luna=LUNA,
                     cerebras=CEREBRAS, haiku=HAIKU)
        env = {"AGENT_GUARD_LLM": "haiku"}
        self.assertEqual(lp.select_profile(cfg, "skills", env)[0], "haiku")
        env["AGENT_GUARD_LLM_MCP"] = "cerebras"
        self.assertEqual(lp.select_profile(cfg, "mcp", env)[0], "cerebras")

    def test_unknown_profile_name_is_an_error(self):
        with self.assertRaises(lp.ProfileError):
            lp.select_profile(config({"skills": "nope"}, luna=LUNA), "skills", {})

    def test_cisco_refuses_cli_profile(self):
        with self.assertRaises(lp.ProfileError) as ctx:
            lp.select_profile(config({"mcp": "luna"}, luna=LUNA), "mcp", {})
        self.assertIn("api", str(ctx.exception))

    def test_campaign_accepts_only_openai_protocol_api_profiles(self):
        cfg = config({"campaign": "cerebras"}, cerebras=CEREBRAS, luna=LUNA, haiku=HAIKU)
        self.assertEqual(lp.select_profile(cfg, "campaign", {})[0], "cerebras")
        for name in ("luna", "haiku"):
            with self.subTest(name=name), self.assertRaises(lp.ProfileError):
                lp.select_profile(cfg, "campaign", {"AGENT_GUARD_LLM_CAMPAIGN": name})

    def test_invalid_profiles_are_rejected(self):
        bad = [
            {"kind": "magic"},
            {"kind": "cli"},
            {"kind": "cli", "cli": "codex; rm -rf /"},
            {"kind": "api", "protocol": "openai", "model": "m", "key_env": "K"},
            {"kind": "api", "protocol": "openai", "base_url": "ftp://x", "model": "m", "key_env": "K"},
            {"kind": "api", "protocol": "native", "model": "m", "key_env": "K"},
            {"kind": "api", "protocol": "openai", "base_url": "https://x", "model": "m",
             "key_env": "K", "max_output": 0},
            {"kind": "api", "protocol": "openai", "base_url": "https://x", "model": "m",
             "key_env": "not a var"},
        ]
        for profile in bad:
            with self.subTest(profile=profile), self.assertRaises(lp.ProfileError):
                lp.select_profile(config({"skills": "p"}, p=profile), "skills", {})


class ExampleConfigTests(unittest.TestCase):
    def test_shipped_example_config_is_accepted_and_every_profile_validates(self):
        uc = importlib.import_module("_user_config")
        example = Path(__file__).resolve().parents[1] / "config.example.toml"
        cfg = uc.load_config(env={"AGENT_GUARD_CONFIG": str(example)})
        for name, profile in cfg["llm"]["profiles"].items():
            with self.subTest(profile=name):
                lp.validate_profile(name, profile)
        for scanner in cfg["llm"]["use"]:
            with self.subTest(scanner=scanner):
                self.assertIsNotNone(lp.select_profile(cfg, scanner, {}))


class SkillSpectorTranslationTests(unittest.TestCase):
    def test_cli_profile_sets_provider_and_model_and_clears_stale_settings(self):
        env = {"SKILLSPECTOR_MODEL": "gpt-5.4-nano", "SKILLSPECTOR_COMPAT_BASE_URL": "https://old",
               "SKILLSPECTOR_MAX_WORKFLOW_SECONDS": "780", "PATH": "x"}
        out, ready, reason, registry = lp.skillspector_env("luna", LUNA, env, which=on_path)
        self.assertTrue(ready, reason)
        self.assertEqual(out["SKILLSPECTOR_PROVIDER"], "codex_cli")
        self.assertEqual(out["SKILLSPECTOR_MODEL"], "gpt-6-luna")
        self.assertNotIn("SKILLSPECTOR_COMPAT_BASE_URL", out)
        self.assertEqual(out["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"], "780")
        self.assertEqual(out["PATH"], "x")
        self.assertIsNone(registry)
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "gpt-5.4-nano")  # input untouched

    def test_cli_profile_without_model_uses_cli_default(self):
        out, ready, _, _ = lp.skillspector_env("c", {"kind": "cli", "cli": "gemini"},
                                               {"SKILLSPECTOR_MODEL": "old"}, which=on_path)
        self.assertTrue(ready)
        self.assertEqual(out["SKILLSPECTOR_PROVIDER"], "gemini_cli")
        self.assertNotIn("SKILLSPECTOR_MODEL", out)

    def test_cli_profile_needs_binary_on_path(self):
        _, ready, reason, _ = lp.skillspector_env("luna", LUNA, {}, which=nowhere)
        self.assertFalse(ready)
        self.assertIn("codex", reason)

    def test_openai_protocol_maps_to_openai_compatible(self):
        out, ready, _, _ = lp.skillspector_env("cerebras", CEREBRAS,
                                               {"CEREBRAS_API_KEY": "secret"}, which=nowhere)
        self.assertTrue(ready)
        self.assertEqual(out["SKILLSPECTOR_PROVIDER"], "openai_compatible")
        self.assertEqual(out["SKILLSPECTOR_MODEL"], "gpt-oss-120b")
        self.assertEqual(out["SKILLSPECTOR_COMPAT_BASE_URL"], "https://api.cerebras.ai/v1")
        self.assertEqual(out["SKILLSPECTOR_COMPAT_API_KEY"], "secret")

    def test_missing_key_is_not_ready_and_names_the_variable(self):
        out, ready, reason, _ = lp.skillspector_env("cerebras", CEREBRAS, {}, which=nowhere)
        self.assertFalse(ready)
        self.assertIn("CEREBRAS_API_KEY", reason)
        self.assertNotIn("SKILLSPECTOR_COMPAT_API_KEY", out)

    def test_native_protocol_copies_key_into_provider_variable(self):
        out, ready, _, _ = lp.skillspector_env("haiku", HAIKU, {"MY_ANTHROPIC": "k"}, which=nowhere)
        self.assertTrue(ready)
        self.assertEqual(out["SKILLSPECTOR_PROVIDER"], "anthropic")
        self.assertEqual(out["ANTHROPIC_API_KEY"], "k")

    def test_token_limits_become_a_single_model_registry(self):
        profile = dict(LUNA, context=400000, max_output=16000)
        _, _, _, registry = lp.skillspector_env("luna", profile, {}, which=on_path)
        self.assertEqual(registry, {"models": {"gpt-6-luna": {
            "context_length": 400000, "max_output_tokens": 16000}}})

    def test_concurrency_is_forwarded(self):
        out, _, _, _ = lp.skillspector_env("luna", dict(LUNA, concurrency=3), {}, which=on_path)
        self.assertEqual(out["SKILLSPECTOR_MAX_LLM_CONCURRENCY"], "3")


class CiscoTranslationTests(unittest.TestCase):
    def test_openai_protocol_uses_openai_prefix_and_base_url(self):
        env = {"CEREBRAS_API_KEY": "secret", "MCP_SCANNER_LLM_API_VERSION": "stale"}
        out, problem = lp.cisco_env("cerebras", CEREBRAS, env)
        self.assertIsNone(problem)
        self.assertEqual(out["MCP_SCANNER_LLM_MODEL"], "openai/gpt-oss-120b")
        self.assertEqual(out["MCP_SCANNER_LLM_BASE_URL"], "https://api.cerebras.ai/v1")
        self.assertEqual(out["MCP_SCANNER_LLM_API_KEY"], "secret")
        self.assertNotIn("MCP_SCANNER_LLM_API_VERSION", out)

    def test_litellm_model_overrides_derived_name(self):
        profile = dict(CEREBRAS, litellm_model="cerebras/gpt-oss-120b")
        out, _ = lp.cisco_env("cerebras", profile, {"CEREBRAS_API_KEY": "s"})
        self.assertEqual(out["MCP_SCANNER_LLM_MODEL"], "cerebras/gpt-oss-120b")

    def test_native_protocol_uses_provider_prefix(self):
        out, _ = lp.cisco_env("haiku", HAIKU, {"MY_ANTHROPIC": "k"})
        self.assertEqual(out["MCP_SCANNER_LLM_MODEL"], "anthropic/claude-haiku-4-5")
        self.assertNotIn("MCP_SCANNER_LLM_BASE_URL", out)

    def test_tuning_fields_map_to_cisco_variables(self):
        profile = dict(CEREBRAS, max_output=4096, timeout=90, retries=6,
                       retry_delay=15, temperature=1)
        out, _ = lp.cisco_env("cerebras", profile, {"CEREBRAS_API_KEY": "s"})
        self.assertEqual(out["MCP_SCANNER_DEFAULT_LLM_MAX_TOKENS"], "4096")
        self.assertEqual(out["MCP_SCANNER_LLM_TIMEOUT"], "90")
        self.assertEqual(out["MCP_SCANNER_LLM_MAX_RETRIES"], "6")
        self.assertEqual(out["MCP_SCANNER_LLM_RETRY_BASE_DELAY"], "15")
        self.assertEqual(out["MCP_SCANNER_DEFAULT_LLM_TEMPERATURE"], "1")

    def test_missing_key_is_reported(self):
        out, problem = lp.cisco_env("cerebras", CEREBRAS, {"MCP_SCANNER_LLM_API_KEY": "old"})
        self.assertIn("CEREBRAS_API_KEY", problem)
        self.assertNotIn("MCP_SCANNER_LLM_API_KEY", out)


class WrapperProfileTests(unittest.TestCase):
    """_skillspector resolves its provider from the active profile."""

    def _resolve(self, config_text, env=None, on_path=()):
        import json as _json
        import shutil
        import tempfile
        old_env, old_which = os.environ.copy(), shutil.which
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(config_text, encoding="utf-8")
            try:
                os.environ.clear()
                os.environ.update({"AGENT_GUARD_NO_DOTENV": "1",
                                   "AGENT_GUARD_CONFIG": str(path), **(env or {})})
                shutil.which = lambda name, *a, **k: (f"/fake/bin/{name}"
                                                      if name in on_path else None)
                module = importlib.reload(importlib.import_module("_skillspector"))
                run_env = module.skillspector_env()
                registry = run_env.get("SKILLSPECTOR_MODEL_REGISTRY")
                data = _json.loads(Path(registry).read_text()) if registry else None
                return module.PROVIDER, module.LLM_READY, module.LLM_REASON, run_env, data
            finally:
                shutil.which = old_which
                os.environ.clear()
                os.environ.update(old_env)
                importlib.reload(importlib.import_module("_skillspector"))

    LUNA_TOML = ('[llm.use]\nskills = "luna"\n[llm.profiles.luna]\n'
                 'kind = "cli"\ncli = "codex"\nmodel = "luna-7"\n')

    def test_profile_overrides_stale_provider_settings(self):
        provider, ready, reason, env, _ = self._resolve(
            self.LUNA_TOML, {"SKILLSPECTOR_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "k",
                             "SKILLSPECTOR_MODEL": "claude-old"}, on_path=("codex",))
        self.assertEqual(provider, "codex_cli")
        self.assertTrue(ready, reason)
        # No vendor-marker filter: an unfamiliar model name is the user's choice.
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "luna-7")
        self.assertEqual(env["SKILLSPECTOR_MAX_LLM_CONCURRENCY"], "1")

    def test_profile_token_limits_are_written_as_registry_file(self):
        toml = self.LUNA_TOML + "context = 400000\nmax_output = 16000\n"
        *_, data = self._resolve(toml, on_path=("codex",))
        self.assertEqual(data, {"models": {"luna-7": {
            "context_length": 400000, "max_output_tokens": 16000}}})

    def test_static_only_still_wins_over_profile(self):
        provider, ready, _, env, _ = self._resolve(
            self.LUNA_TOML, {"AGENT_GUARD_STATIC_ONLY": "1"}, on_path=("codex",))
        self.assertFalse(ready)
        self.assertNotIn("SKILLSPECTOR_PROVIDER", env)

    def test_unknown_profile_stops_the_wrapper(self):
        with self.assertRaises(SystemExit) as ctx:
            self._resolve('[llm.use]\nskills = "missing"\n')
        self.assertEqual(ctx.exception.code, 2)


class CiscoWrapperProfileTests(unittest.TestCase):
    """scan_mcp builds the Cisco environment from the mcp profile."""

    TOML = ('[llm.use]\nmcp = "cerebras"\n[llm.profiles.cerebras]\n'
            'kind = "api"\nprotocol = "openai"\nbase_url = "https://api.cerebras.ai/v1"\n'
            'model = "gpt-oss-120b"\nkey_env = "CEREBRAS_API_KEY"\n')

    def _load(self, config_text, env):
        import contextlib
        import io
        import tempfile
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(config_text, encoding="utf-8")
            try:
                os.environ.clear()
                os.environ.update({"AGENT_GUARD_NO_DOTENV": "1",
                                   "AGENT_GUARD_CONFIG": str(path), **env})
                importlib.reload(importlib.import_module("_skillspector"))
                scan_mcp = importlib.reload(importlib.import_module("scan_mcp"))
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    problem = scan_mcp.cisco_llm_problem()
                    try:
                        env_out = scan_mcp.cisco_env()
                    except SystemExit as exc:
                        env_out = exc
                return problem, env_out, out.getvalue()
            finally:
                os.environ.clear()
                os.environ.update(old_env)
                importlib.reload(importlib.import_module("_skillspector"))
                importlib.reload(importlib.import_module("scan_mcp"))

    def test_profile_drives_cisco_env_and_drops_stale_settings(self):
        problem, env, _ = self._load(self.TOML, {"CEREBRAS_API_KEY": "csk-live",
                                                  "MCP_SCANNER_LLM_API_VERSION": "stale",
                                                  "MCP_SCANNER_LLM_MODEL": "gpt-4o"})
        self.assertIsNone(problem)
        self.assertEqual(env["MCP_SCANNER_LLM_MODEL"], "openai/gpt-oss-120b")
        self.assertEqual(env["MCP_SCANNER_LLM_API_KEY"], "csk-live")
        self.assertNotIn("MCP_SCANNER_LLM_API_VERSION", env)

    def test_missing_profile_key_blocks_the_runtime_scan(self):
        problem, env, _ = self._load(self.TOML, {})
        self.assertIn("CEREBRAS_API_KEY", problem)
        self.assertIsInstance(env, SystemExit)
        self.assertEqual(env.code, 2)

    def test_rate_limited_profile_warns_that_cisco_cannot_honour_it(self):
        _, _, output = self._load(self.TOML + "limits = { rpm = 5 }\n",
                                  {"CEREBRAS_API_KEY": "csk-live"})
        self.assertIn("rpm", output)

    def test_legacy_config_problem_is_missing_key(self):
        problem, _, _ = self._load("", {"MCP_SCANNER_LLM_MODEL": "openai/gpt-x"})
        self.assertIn("MCP_SCANNER_LLM_API_KEY", problem)


if __name__ == "__main__":
    unittest.main()
