"""OpenCode's internal OAuth plugins stay enabled for SkillSpector's opencode_cli (#809)."""
import dataclasses
import importlib
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
oauth = importlib.import_module("_opencode_oauth")

NAMES = ("skillspector", "skillspector.providers", "skillspector.providers._agent_cli")


@dataclasses.dataclass(frozen=True)
class CliSpec:
    """Shape of SkillSpector's frozen CliSpec: inference reads prepare_env from here."""

    binary: str
    prepare_env: object = None


class FakeAgentCli:
    """Stand-in for SkillSpector's _agent_cli module with a chosen env builder."""

    def __init__(self, prepare):
        self.prepare = prepare

    def __enter__(self):
        self.saved = {n: sys.modules.get(n) for n in NAMES}
        module = types.ModuleType(NAMES[-1])
        if self.prepare is not None:
            module._prepare_opencode_env = self.prepare
            # Bound at import time, like SkillSpector's _REGISTRY.
            module._REGISTRY = {"opencode": CliSpec("opencode", self.prepare),
                                "claude": CliSpec("claude")}
        for name in NAMES[:-1]:
            sys.modules[name] = types.ModuleType(name)
        sys.modules[NAMES[-1]] = module
        return module

    def __exit__(self, *exc):
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def upstream_env(base_env, temp_root, argv):
    """SkillSpector 2.12 behavior: switches all of OpenCode's plugins off."""
    return {"OPENCODE_PURE": "1", "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1", "ROOT": temp_root}


class KeepOAuthPluginsTest(unittest.TestCase):
    def test_removes_only_the_default_plugin_switch(self):
        with FakeAgentCli(upstream_env) as module:
            self.assertTrue(oauth.keep_oauth_plugins())
            env = module._prepare_opencode_env({}, "/tmp/x", ["opencode", "run"])
        self.assertEqual(env, {"OPENCODE_PURE": "1", "ROOT": "/tmp/x"})

    def test_inference_spec_uses_the_wrapped_builder(self):
        # run_agent_cli calls spec.prepare_env, not the module attribute.
        with FakeAgentCli(upstream_env) as module:
            oauth.keep_oauth_plugins()
            spec = module._REGISTRY["opencode"]
            env = spec.prepare_env({}, "/tmp/x", [])
            self.assertIs(spec.prepare_env, module._prepare_opencode_env)
            self.assertIsNone(module._REGISTRY["claude"].prepare_env)
        self.assertNotIn("OPENCODE_DISABLE_DEFAULT_PLUGINS", env)

    def test_is_a_no_op_once_upstream_stops_setting_the_switch(self):
        def fixed_env(base_env, temp_root, argv):
            return {"OPENCODE_PURE": "1"}

        with FakeAgentCli(fixed_env) as module:
            self.assertTrue(oauth.keep_oauth_plugins())
            env = module._prepare_opencode_env({}, "/tmp/x", [])
        self.assertEqual(env, {"OPENCODE_PURE": "1"})

    def test_installs_once(self):
        with FakeAgentCli(upstream_env) as module:
            oauth.keep_oauth_plugins()
            first = module._prepare_opencode_env
            oauth.keep_oauth_plugins()
            self.assertIs(module._prepare_opencode_env, first)

    def test_missing_builder_leaves_skillspector_untouched(self):
        with FakeAgentCli(None) as module:
            self.assertFalse(oauth.keep_oauth_plugins())
            self.assertFalse(hasattr(module, "_prepare_opencode_env"))

    def test_skillspector_not_installed(self):
        saved = {n: sys.modules.get(n) for n in NAMES}
        try:
            for name in NAMES:
                sys.modules[name] = None  # makes the import raise ImportError
            self.assertFalse(oauth.keep_oauth_plugins())
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module


class BootsInstallShimTest(unittest.TestCase):
    def test_skill_scan_boot_keeps_oauth_plugins_before_the_cli_runs(self):
        boot = importlib.import_module("_skillspector_boot")
        calls = []
        fake_cli = types.ModuleType("skillspector.cli")
        fake_cli.app = lambda: calls.append("app")
        with FakeAgentCli(upstream_env), \
                patch.dict(sys.modules, {"skillspector.cli": fake_cli}), \
                patch.object(boot._opencode_oauth, "keep_oauth_plugins",
                             side_effect=lambda: calls.append("oauth")):
            boot.main()
        self.assertEqual(calls, ["oauth", "app"])

    def test_verifier_boot_keeps_oauth_plugins(self):
        boot = importlib.import_module("_verifier_boot")
        self.assertIs(boot._opencode_oauth, oauth)
        source = (ROOT / "scripts" / "_verifier_boot.py").read_text(encoding="utf-8")
        main_body = source.split("def main()", 1)[1]
        self.assertLess(main_body.index("keep_oauth_plugins()"), main_body.index("chat_completion("))

    def test_skills_probe_keeps_oauth_plugins_like_a_scan(self):
        source = (ROOT / "scripts" / "llm_check.py").read_text(encoding="utf-8")
        probe = source.split("SKILLS_PROBE = (", 1)[1].split(")\n\n", 1)[0]
        self.assertLess(probe.index("keep_oauth_plugins()"), probe.index("get_chat_model"))


if __name__ == "__main__":
    unittest.main()
