"""LLM profiles: selection, validation and translation into scanner-native env."""
import importlib
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
lp = importlib.import_module("_llm_profile")

LUNA = {"kind": "cli", "cli": "codex", "model": "<model-id>"}  # refused: codex_cli is disabled
CLAUDE = {"kind": "cli", "cli": "claude", "model": "<model-id>"}
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
        cfg = config({"skills": "luna", "mcp": "cerebras"}, luna=CLAUDE, cerebras=CEREBRAS)
        self.assertEqual(lp.select_profile(cfg, "skills", {})[0], "luna")
        self.assertEqual(lp.select_profile(cfg, "mcp", {})[0], "cerebras")

    def test_scanner_without_use_entry_keeps_legacy_resolution(self):
        cfg = config({"skills": "luna"}, luna=CLAUDE)
        self.assertIsNone(lp.select_profile(cfg, "mcp", {}))

    def test_run_override_beats_use_and_scanner_override_beats_both(self):
        cfg = config({"skills": "luna", "mcp": "cerebras"}, luna=CLAUDE,
                     cerebras=CEREBRAS, haiku=HAIKU)
        env = {"AGENT_GUARD_LLM": "haiku"}
        self.assertEqual(lp.select_profile(cfg, "skills", env)[0], "haiku")
        env["AGENT_GUARD_LLM_MCP"] = "cerebras"
        self.assertEqual(lp.select_profile(cfg, "mcp", env)[0], "cerebras")

    def test_unknown_profile_name_is_an_error(self):
        with self.assertRaises(lp.ProfileError):
            lp.select_profile(config({"skills": "nope"}, luna=CLAUDE), "skills", {})

    def test_cisco_refuses_cli_profile(self):
        with self.assertRaises(lp.ProfileError) as ctx:
            lp.select_profile(config({"mcp": "luna"}, luna=CLAUDE), "mcp", {})
        self.assertIn("api", str(ctx.exception))

    def test_campaign_accepts_only_openai_protocol_api_profiles(self):
        cfg = config({"campaign": "cerebras"}, cerebras=CEREBRAS, luna=CLAUDE, haiku=HAIKU)
        self.assertEqual(lp.select_profile(cfg, "campaign", {})[0], "cerebras")
        for name in ("luna", "haiku"):
            with self.subTest(name=name), self.assertRaises(lp.ProfileError):
                lp.select_profile(cfg, "campaign", {"AGENT_GUARD_LLM_CAMPAIGN": name})

    def test_invalid_profiles_are_rejected(self):
        bad = [
            {"kind": "magic"},
            {"kind": "cli"},
            {"kind": "cli", "cli": "codex; whoami"},
            {"kind": "cli", "cli": "openai-compatible"},
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
        out, ready, reason, registry = lp.skillspector_env("luna", CLAUDE, env, which=on_path)
        self.assertTrue(ready, reason)
        self.assertEqual(out["SKILLSPECTOR_PROVIDER"], "claude_cli")
        self.assertEqual(out["SKILLSPECTOR_MODEL"], "<model-id>")
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
        _, ready, reason, _ = lp.skillspector_env("luna", CLAUDE, {}, which=nowhere)
        self.assertFalse(ready)
        self.assertIn("claude", reason)

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
        profile = dict(CLAUDE, context=400000, max_output=16000)
        _, _, _, registry = lp.skillspector_env("luna", profile, {}, which=on_path)
        self.assertEqual(registry, {"models": {"<model-id>": {
            "context_length": 400000, "max_output_tokens": 16000}}})

    def test_concurrency_is_forwarded(self):
        out, _, _, _ = lp.skillspector_env("luna", dict(CLAUDE, concurrency=3), {}, which=on_path)
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
                 'kind = "cli"\ncli = "claude"\nmodel = "luna-7"\n')

    def test_profile_overrides_stale_provider_settings(self):
        provider, ready, reason, env, _ = self._resolve(
            self.LUNA_TOML, {"SKILLSPECTOR_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "k",
                             "SKILLSPECTOR_MODEL": "claude-old"}, on_path=("claude",))
        self.assertEqual(provider, "claude_cli")
        self.assertTrue(ready, reason)
        # No vendor-marker filter: an unfamiliar model name is the user's choice.
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "luna-7")
        self.assertEqual(env["SKILLSPECTOR_MAX_LLM_CONCURRENCY"], "1")

    def test_profile_token_limits_are_written_as_registry_file(self):
        toml = self.LUNA_TOML + "context = 400000\nmax_output = 16000\n"
        *_, data = self._resolve(toml, on_path=("claude",))
        self.assertEqual(data, {"models": {"luna-7": {
            "context_length": 400000, "max_output_tokens": 16000}}})

    def test_static_only_still_wins_over_profile(self):
        provider, ready, _, env, _ = self._resolve(
            self.LUNA_TOML, {"AGENT_GUARD_STATIC_ONLY": "1"}, on_path=("claude",))
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


OPENCODE = {"kind": "cli", "cli": "opencode"}
GEMINI_ADC = {"kind": "api", "protocol": "native", "provider": "gemini", "model": "<model-id>",
              "settings": {"GOOGLE_CLOUD_PROJECT": "demo-project"}}
AZURE = {"kind": "api", "protocol": "native", "provider": "azure_openai", "model": "<model-id>",
         "key_env": "MY_AZURE", "settings": {"AZURE_OPENAI_ENDPOINT": "https://x.openai.azure.com"}}


class OpennessTests(unittest.TestCase):
    def test_codex_profile_is_refused_with_the_reason(self):
        with self.assertRaises(lp.ProfileError) as ctx:
            lp.validate_profile("luna", LUNA)
        self.assertIn("codex_cli is disabled", str(ctx.exception))

    def test_antigravity_profile_is_refused(self):
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("agy", {"kind": "cli", "cli": "agy"})

    def test_unknown_cli_is_refused(self):
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("x", {"kind": "cli", "cli": "notacli"})

    def test_opencode_profile_maps_to_opencode_cli(self):
        env, ready, reason, _ = lp.skillspector_env("oc", lp.validate_profile("oc", OPENCODE),
                                                    {}, which=on_path)
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "opencode_cli")
        self.assertTrue(ready, reason)

    def test_gemini_adc_needs_no_key_but_its_project(self):
        env, ready, _r, _ = lp.skillspector_env("g", lp.validate_profile("g", GEMINI_ADC), {})
        self.assertTrue(ready)
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "gemini")
        self.assertEqual(env["GOOGLE_CLOUD_PROJECT"], "demo-project")
        bare = dict(GEMINI_ADC, settings={})
        _env, ready, reason, _ = lp.skillspector_env("g", lp.validate_profile("g", bare), {})
        self.assertFalse(ready)
        self.assertIn("GOOGLE_CLOUD_PROJECT", reason)

    def test_azure_gets_key_and_endpoint(self):
        env, ready, _r, _ = lp.skillspector_env(
            "az", lp.validate_profile("az", AZURE), {"MY_AZURE": "k"})
        self.assertTrue(ready)
        self.assertEqual(env["AZURE_OPENAI_API_KEY"], "k")
        self.assertEqual(env["AZURE_OPENAI_ENDPOINT"], "https://x.openai.azure.com")

    def test_settings_outside_the_provider_are_refused(self):
        bad = dict(GEMINI_ADC, settings={"OPENAI_BASE_URL": "https://evil.example"})
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("g", bad)

    def test_settings_must_be_strings(self):
        bad = dict(GEMINI_ADC, settings={"GOOGLE_CLOUD_PROJECT": 5})
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("g", bad)

    def test_provider_with_secret_still_needs_key_env(self):
        no_key = {k: v for k, v in AZURE.items() if k != "key_env"}
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("az", no_key)

    def test_stale_settings_from_env_are_replaced_by_the_profile(self):
        env, _ready, _r, _ = lp.skillspector_env(
            "g", lp.validate_profile("g", GEMINI_ADC), {"GOOGLE_CLOUD_PROJECT": "old"})
        self.assertEqual(env["GOOGLE_CLOUD_PROJECT"], "demo-project")

    def test_provider_setting_in_env_but_not_in_profile_is_not_ready(self):
        bedrock = {"kind": "api", "protocol": "native", "provider": "bedrock",
                   "model": "<model-id>"}
        _env, ready, reason, _ = lp.skillspector_env(
            "b", lp.validate_profile("b", bedrock), {"AWS_REGION": "eu-central-1"})
        self.assertFalse(ready)
        self.assertIn("AWS_REGION is set in the environment but not in the profile's "
                      "settings; move it into settings", reason)
        with_settings = dict(bedrock, settings={"AWS_REGION": "eu-west-1"})
        env, ready, reason, _ = lp.skillspector_env(
            "b", lp.validate_profile("b", with_settings), {"AWS_REGION": "eu-central-1"})
        self.assertTrue(ready, reason)
        self.assertEqual(env["AWS_REGION"], "eu-west-1")
        _env, ready, reason, _ = lp.skillspector_env(
            "b", lp.validate_profile("b", bedrock), {})
        self.assertTrue(ready, reason)

    def test_anthropic_proxy_url_in_env_is_not_dropped_silently(self):
        _env, ready, reason, _ = lp.skillspector_env(
            "h", lp.validate_profile("h", HAIKU),
            {"ANTHROPIC_BASE_URL": "https://proxy.example", "ANTHROPIC_API_KEY": "k"})
        self.assertFalse(ready)
        self.assertIn("ANTHROPIC_BASE_URL", reason)

    def test_settings_urls_follow_the_https_rule_of_base_url(self):
        ollama = {"kind": "api", "protocol": "native", "provider": "ollama", "model": "<model-id>"}
        azure_ep = "AZURE_OPENAI_ENDPOINT"
        for profile, bad in ((ollama, {"OLLAMA_BASE_URL": "http://10.0.0.5:11434"}),
                             (AZURE, {azure_ep: "http://x"})):
            with self.subTest(settings=bad), self.assertRaises(lp.ProfileError) as ctx:
                lp.validate_profile("p", dict(profile, settings=bad))
            self.assertIn(next(iter(bad)), str(ctx.exception))
        for url in ("http://localhost:11434", "https://gpu.example:11434"):
            lp.validate_profile("p", dict(ollama, settings={"OLLAMA_BASE_URL": url}))

    def test_openai_protocol_base_url_cannot_be_overridden_by_settings(self):
        profile = dict(CEREBRAS, settings={"SKILLSPECTOR_COMPAT_BASE_URL": "https://other.example"})
        with self.assertRaises(lp.ProfileError):
            lp.validate_profile("c", profile)

    def test_hosts_are_parsed_not_prefix_matched(self):
        ollama = {"kind": "api", "protocol": "native", "provider": "ollama", "model": "<model-id>"}
        for url in ("http://localhost.evil.example", "http://127.0.0.1.attacker.net",
                    "http://[::1].x", "https://", "http://localhost:bad"):
            with self.subTest(url=url):
                with self.assertRaises(lp.ProfileError):
                    lp.validate_profile("c", dict(CEREBRAS, base_url=url))
                with self.assertRaises(lp.ProfileError):
                    lp.validate_profile("o", dict(ollama, settings={"OLLAMA_BASE_URL": url}))
        for url in ("http://localhost:11434/v1", "http://127.0.0.1:8080", "http://[::1]:11434",
                    "https://api.example.com/v1"):
            with self.subTest(url=url):
                lp.validate_profile("c", dict(CEREBRAS, base_url=url))
                lp.validate_profile("o", dict(ollama, settings={"OLLAMA_BASE_URL": url}))


OPENCODE = {"kind": "cli", "cli": "opencode", "model": "openai/m", "concurrency": 2}


class CiscoBridgeProfileTests(unittest.TestCase):
    def test_mcp_accepts_an_opencode_cli_profile(self):
        cfg = config({"mcp": "chatgpt"}, chatgpt=OPENCODE)
        self.assertEqual(lp.select_profile(cfg, "mcp", {})[0], "chatgpt")

    def test_mcp_refuses_other_clis(self):
        cfg = config({"mcp": "claude"}, claude=CLAUDE)
        with self.assertRaisesRegex(lp.ProfileError, "only OpenCode"):
            lp.select_profile(cfg, "mcp", {})

    def test_bridge_env_points_cisco_at_the_bridge(self):
        env = {"MCP_SCANNER_LLM_API_KEY": "old", "MCP_SCANNER_LLM_BASE_URL": "https://x", "PATH": "p"}
        out = lp.cisco_bridge_env("chatgpt", OPENCODE, env, 4321, "tok", 900)
        self.assertEqual(out["MCP_SCANNER_LLM_MODEL"], "openai/openai/m")
        self.assertEqual(out["MCP_SCANNER_LLM_BASE_URL"], "http://127.0.0.1:4321/v1")
        self.assertEqual(out["MCP_SCANNER_LLM_API_KEY"], "tok")
        self.assertEqual(out["MCP_SCANNER_LLM_TIMEOUT"], "840")
        self.assertEqual(out["MCP_SCANNER_LLM_MAX_RETRIES"], "1")
        self.assertEqual(out["PATH"], "p")

    def test_bridge_timeout_has_a_floor(self):
        out = lp.cisco_bridge_env("chatgpt", OPENCODE, {}, 1, "t", 90)
        self.assertEqual(out["MCP_SCANNER_LLM_TIMEOUT"], "60")


if __name__ == "__main__":
    unittest.main()
