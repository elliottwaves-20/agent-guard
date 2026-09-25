"""Profile-declared reasoning models get Cisco's own reasoning request rule."""
import importlib
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
boot = importlib.import_module("_cisco_boot")
lp = importlib.import_module("_llm_profile")


def cisco_rule(model, params):
    """Cisco 4.8.4's rule: only names containing gpt-5 are treated as reasoning."""
    if "gpt-5" not in model.lower():
        return
    if "max_tokens" in params:
        params["max_completion_tokens"] = params.pop("max_tokens")
    params["temperature"] = 1


class FakeCisco:
    def __enter__(self):
        names = ("mcpscanner", "mcpscanner.utils", "mcpscanner.utils.llm_request_params")
        self.saved = {n: sys.modules.get(n) for n in names}
        module = types.ModuleType(names[-1])
        module.apply_model_constraints = cisco_rule
        for name in names[:-1]:
            sys.modules[name] = types.ModuleType(name)
        sys.modules[names[-1]] = module
        return module

    def __exit__(self, *exc):
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


class BootTests(unittest.TestCase):
    def test_flag_applies_reasoning_rule_to_any_model_name(self):
        with FakeCisco() as module, patch.dict(os.environ, {"AGENT_GUARD_CISCO_REASONING": "1"}):
            boot.install()
            params = {"max_tokens": 1000, "temperature": 0.1, "model": "gpt-6-luna"}
            module.apply_model_constraints("gpt-6-luna", params)
        self.assertEqual(params, {"max_completion_tokens": 1000, "temperature": 1,
                                  "model": "gpt-6-luna"})

    def test_without_flag_cisco_rule_is_untouched(self):
        with FakeCisco() as module, patch.dict(os.environ, {}, clear=True):
            boot.install()
            self.assertIs(module.apply_model_constraints, cisco_rule)

    def test_missing_cisco_hook_fails_closed(self):
        with FakeCisco() as module, patch.dict(os.environ, {"AGENT_GUARD_CISCO_REASONING": "1"}):
            del module.apply_model_constraints
            with self.assertRaises(SystemExit) as ctx:
                boot.install()
        self.assertEqual(ctx.exception.code, 2)


class ProfileFlagTests(unittest.TestCase):
    PROFILE = {"kind": "api", "protocol": "openai", "base_url": "https://api.openai.com/v1",
               "model": "gpt-6-luna", "key_env": "K"}

    def test_reasoning_profile_sets_flag_and_plain_profile_clears_stale_flag(self):
        out, _ = lp.cisco_env("p", dict(self.PROFILE, reasoning=True), {"K": "k"})
        self.assertEqual(out["AGENT_GUARD_CISCO_REASONING"], "1")
        out, _ = lp.cisco_env("p", self.PROFILE, {"K": "k", "AGENT_GUARD_CISCO_REASONING": "1"})
        self.assertNotIn("AGENT_GUARD_CISCO_REASONING", out)

    def test_reasoning_must_be_boolean(self):
        cfg = {"llm": {"use": {"mcp": "p"}, "profiles": {"p": dict(self.PROFILE, reasoning="yes")}}}
        with self.assertRaises(lp.ProfileError):
            lp.select_profile(cfg, "mcp", {})


class CommandTests(unittest.TestCase):
    def test_reasoning_flag_routes_cisco_through_boot_shim(self):
        scan_mcp = importlib.import_module("scan_mcp")
        with patch.object(scan_mcp, "mcpscanner_python", return_value="/py"), \
                patch.object(scan_mcp, "MCP_SCANNER", "/bin/mcp-scanner"):
            self.assertEqual(scan_mcp.cisco_command({"AGENT_GUARD_CISCO_REASONING": "1"}),
                             ["/py", str(ROOT / "scripts" / "_cisco_boot.py")])
            self.assertEqual(scan_mcp.cisco_command({}), ["/bin/mcp-scanner"])


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to test against the installed Cisco scanner")
class InstalledCiscoTests(unittest.TestCase):
    def test_shim_patches_the_real_cisco_hook(self):
        scan_mcp = importlib.import_module("scan_mcp")
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import _cisco_boot; "
                 "_cisco_boot.install(); "
                 "from mcpscanner.utils.llm_request_params import apply_model_constraints as a; "
                 "p = {'max_tokens': 7, 'temperature': 0.1}; a('gpt-6-luna', p); print(sorted(p.items()))")
        result = subprocess.run([scan_mcp.mcpscanner_python(), "-c", probe, str(ROOT / "scripts")],
                                capture_output=True, text=True, timeout=120,
                                env=dict(os.environ, AGENT_GUARD_CISCO_REASONING="1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[('max_completion_tokens', 7), ('temperature', 1)]", result.stdout)


if __name__ == "__main__":
    unittest.main()
