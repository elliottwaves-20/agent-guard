import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


class SkillSpectorWrapperTests(unittest.TestCase):
    def _resolve(self, env: dict, on_path=()):
        """Reload _skillspector under a controlled environment and PATH.

        `on_path` lists the binaries shutil.which should "find". Returns
        (provider, ready, reason, skillspector_env) captured under that setup;
        the module is reloaded with the real environment afterwards."""
        import shutil
        old_env = os.environ.copy()
        old_which = shutil.which
        try:
            os.environ.clear()
            os.environ.update({"AGENT_GUARD_NO_DOTENV": "1", **env})
            shutil.which = lambda name, *a, **k: (f"/fake/bin/{name}"
                                                  if name in on_path else None)
            module = importlib.reload(importlib.import_module("_skillspector"))
            return (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
                    module.skillspector_env())
        finally:
            shutil.which = old_which
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("_skillspector"))

    def test_anthropic_provider_enables_skillspector_llm(self):
        provider, ready, _reason, env = self._resolve({
            "SKILLSPECTOR_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "SKILLSPECTOR_MODEL": "claude-test-model",
        })
        self.assertEqual(provider, "anthropic")
        self.assertTrue(ready)
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "anthropic")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-ant-test")
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "claude-test-model")

    def test_claude_cli_provider_requires_the_binary_on_path(self):
        provider, ready, reason, env = self._resolve(
            {"SKILLSPECTOR_PROVIDER": "claude_cli"}, on_path=())
        self.assertEqual(provider, "claude_cli")
        self.assertFalse(ready)
        self.assertIn("not on PATH", reason)
        self.assertNotIn("SKILLSPECTOR_PROVIDER", env)

        provider, ready, reason, env = self._resolve(
            {"SKILLSPECTOR_PROVIDER": "claude_cli"}, on_path=("claude",))
        self.assertTrue(ready)
        self.assertIn("claude CLI", reason)
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "claude_cli")

    def test_provider_aliases_map_to_skillspector_ids(self):
        provider, ready, _reason, _env = self._resolve(
            {"SKILLSPECTOR_PROVIDER": "codex"}, on_path=("codex",))
        self.assertEqual(provider, "codex_cli")
        self.assertTrue(ready)

    def test_explicit_key_provider_requires_its_credential(self):
        provider, ready, reason, _env = self._resolve(
            {"SKILLSPECTOR_PROVIDER": "nv_build"})
        self.assertEqual(provider, "nv_build")
        self.assertFalse(ready)
        self.assertIn("NVIDIA_INFERENCE_KEY", reason)

        provider, ready, _reason, env = self._resolve({
            "SKILLSPECTOR_PROVIDER": "nv_build",
            "NVIDIA_INFERENCE_KEY": "nvapi-test",
        })
        self.assertTrue(ready)
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "nv_build")

    def test_autodetect_prefers_api_key_then_coding_agent_cli(self):
        provider, ready, _reason, _env = self._resolve(
            {"OPENAI_API_KEY": "sk-test"}, on_path=("claude",))
        self.assertEqual((provider, ready), ("openai", True))

        provider, ready, reason, env = self._resolve({}, on_path=("codex", "claude"))
        self.assertEqual((provider, ready), ("claude_cli", True))
        self.assertIn("auto-detected", reason)
        self.assertEqual(env["SKILLSPECTOR_PROVIDER"], "claude_cli")

        provider, ready, reason, env = self._resolve({}, on_path=())
        self.assertEqual((provider, ready), ("", False))
        self.assertNotIn("SKILLSPECTOR_PROVIDER", env)

    def test_foreign_model_is_dropped_for_vendor_cli_providers(self):
        import contextlib
        import io as _io
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            _p, ready, _r, env = self._resolve({
                "SKILLSPECTOR_PROVIDER": "claude_cli",
                "SKILLSPECTOR_MODEL": "gpt-5.4-nano",
            }, on_path=("claude",))
        self.assertTrue(ready)
        self.assertNotIn("SKILLSPECTOR_MODEL", env)
        self.assertIn("does not belong to provider claude_cli", buf.getvalue())

        _p, _ready, _r, env = self._resolve({
            "SKILLSPECTOR_PROVIDER": "claude_cli",
            "SKILLSPECTOR_MODEL": "claude-sonnet-5",
        }, on_path=("claude",))
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "claude-sonnet-5")

        _p, _ready, _r, env = self._resolve({
            "SKILLSPECTOR_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test",
            "SKILLSPECTOR_MODEL": "anything-goes",
        })
        self.assertEqual(env["SKILLSPECTOR_MODEL"], "anything-goes")

    def test_static_only_override_wins_over_available_providers(self):
        provider, ready, reason, env = self._resolve({
            "AGENT_GUARD_STATIC_ONLY": "1",
            "SKILLSPECTOR_PROVIDER": "claude_cli",
            "ANTHROPIC_API_KEY": "sk-ant-test",
        }, on_path=("claude",))
        self.assertFalse(ready)
        self.assertIn("AGENT_GUARD_STATIC_ONLY", reason)
        self.assertNotIn("SKILLSPECTOR_PROVIDER", env)

    def _write_report(self, path: Path, **overrides):
        report = {
            "risk_assessment": {"score": 0, "severity": "LOW",
                                "recommendation": "SAFE",
                                "max_issue_severity": "NONE"},
            "issues": [],
            "metadata": {"llm_requested": True, "llm_available": True,
                         "llm_calls_attempted": 4, "llm_calls_succeeded": 4},
            "execution_successful": True,
            "analysis_completeness": {"is_complete": True,
                                      "execution_successful": True,
                                      "coverage_percent": 100.0,
                                      "entirely_uninspected_files": 0,
                                      "partially_inspected_files": 0,
                                      "ledger_exceptions": []},
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(report.get(key), dict):
                report[key].update(value)
            else:
                report[key] = value
        path.write_text(json.dumps(report), encoding="utf-8")

    def test_verdict_blocks_when_execution_failed(self):
        module = importlib.import_module("_skillspector")
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "report.json"
            self._write_report(report, execution_successful=False,
                               analysis_completeness={
                                   "execution_successful": False,
                                   "ledger_exceptions": ["static_yara: boom"]})
            self.assertEqual(module.verdict_skillspector(report, 0), 2)

    def test_verdict_uses_max_issue_severity_gate(self):
        module = importlib.import_module("_skillspector")
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "report.json"
            self._write_report(report, risk_assessment={
                "score": 10, "severity": "LOW", "recommendation": "SAFE",
                "max_issue_severity": "HIGH"})
            self.assertEqual(module.verdict_skillspector(report, 0), 1)

    def test_verdict_safe_on_complete_clean_report(self):
        module = importlib.import_module("_skillspector")
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "report.json"
            self._write_report(report)
            self.assertEqual(module.verdict_skillspector(report, 0), 0)

    def test_boot_widens_skillspector_workflow_budget(self):
        import dataclasses
        import types

        boot = importlib.import_module("_skillspector_boot")

        @dataclasses.dataclass(slots=True)
        class Budget:
            max_seconds: float = 60.0
            max_bytes: int = 1
            started_at: float | None = None

        fake_state = types.ModuleType("skillspector.state")
        fake_state.MAX_WORKFLOW_SECONDS = 60.0
        fake_state.WorkflowResourceBudget = Budget
        fake_pkg = types.ModuleType("skillspector")
        fake_pkg.state = fake_state
        saved = {k: sys.modules.get(k) for k in ("skillspector", "skillspector.state")}
        try:
            sys.modules["skillspector"] = fake_pkg
            sys.modules["skillspector.state"] = fake_state

            self.assertFalse(boot.apply_workflow_budget(0))
            self.assertFalse(boot.apply_workflow_budget(30))   # upstream already >= 30
            self.assertIs(fake_state.WorkflowResourceBudget, Budget)

            self.assertTrue(boot.apply_workflow_budget(540))
            budget = fake_state.WorkflowResourceBudget()
            self.assertEqual(budget.max_seconds, 540)
            self.assertEqual(budget.max_bytes, 1)
            self.assertIsInstance(budget, Budget)
            explicit = fake_state.WorkflowResourceBudget(max_seconds=5)
            self.assertEqual(explicit.max_seconds, 5)
            self.assertEqual(fake_state.MAX_WORKFLOW_SECONDS, 540)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_scan_env_carries_workflow_budget_and_boot_command(self):
        module = importlib.import_module("_skillspector")
        env = module.skillspector_env()
        self.assertEqual(env["SKILLSPECTOR_MAX_WORKFLOW_SECONDS"], str(module.WORKFLOW_BUDGET))
        self.assertGreaterEqual(module.WORKFLOW_BUDGET, 60)
        self.assertLess(module.WORKFLOW_BUDGET, module.SCAN_TIMEOUT)

        original_cmd = module.SKILLSPECTOR_CMD
        original_python = module.skillspector_python
        try:
            module.SKILLSPECTOR_CMD = None
            module.skillspector_python = lambda: "/fake/tool/python"
            self.assertEqual(module.skillspector_command(),
                             ["/fake/tool/python", str(module.BOOT)])
            module.SKILLSPECTOR_CMD = None
            module.skillspector_python = lambda: None
            self.assertEqual(module.skillspector_command(), [module.SKILLSPECTOR])
        finally:
            module.SKILLSPECTOR_CMD = original_cmd
            module.skillspector_python = original_python

    def test_llm_run_incomplete_detects_partial_llm_coverage(self):
        module = importlib.import_module("_skillspector")
        self.assertEqual(module.llm_run_incomplete(
            {"metadata": {"llm_requested": False}}), "")
        self.assertEqual(module.llm_run_incomplete(
            {"metadata": {"llm_requested": True, "llm_available": True,
                          "llm_calls_attempted": 4, "llm_calls_succeeded": 4}}), "")
        self.assertIn("unavailable", module.llm_run_incomplete(
            {"metadata": {"llm_requested": True, "llm_available": False}}))
        self.assertIn("1 of 4", module.llm_run_incomplete(
            {"metadata": {"llm_requested": True, "llm_available": True,
                          "llm_calls_attempted": 4, "llm_calls_succeeded": 3}}))
        self.assertIn("quota", module.llm_run_incomplete(
            {"metadata": {"llm_requested": True, "llm_available": True,
                          "llm_error": "quota exceeded"}}))

    def test_scan_mcp_delegates_static_scan_to_shared_wrapper_with_runtime_hint(self):
        scan_mcp = importlib.import_module("scan_mcp")

        calls = []

        def fake_run_skillspector(src, runtime_hint=False):
            calls.append((Path(src), runtime_hint))
            return 0

        original = scan_mcp.shared_run_skillspector
        try:
            scan_mcp.shared_run_skillspector = fake_run_skillspector
            self.assertEqual(scan_mcp.run_skillspector(Path("example")), 0)
        finally:
            scan_mcp.shared_run_skillspector = original

        self.assertEqual(calls, [(Path("example"), True)])

    def test_cisco_runtime_uses_explicit_mcp_scanner_llm_config(self):
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({
                "AGENT_GUARD_NO_DOTENV": "1",
                "SKILLSPECTOR_PROVIDER": "openai",
                "OPENAI_API_KEY": "sk-openai-for-skillspector",
                "SKILLSPECTOR_MODEL": "openai-test-model",
                "MCP_SCANNER_LLM_API_KEY": "gemini-runtime-key",
                "MCP_SCANNER_LLM_MODEL": "runtime-test-model",
                "MCP_SCANNER_LLM_BASE_URL": "https://runtime.example/v1",
                "MCP_SCANNER_LLM_API_VERSION": "2026-01-01",
            })
            importlib.reload(importlib.import_module("_skillspector"))
            scan_mcp = importlib.reload(importlib.import_module("scan_mcp"))

            self.assertEqual(scan_mcp.CISCO_LLM_KEY, "gemini-runtime-key")
            self.assertEqual(scan_mcp.CISCO_LLM_MODEL, "runtime-test-model")
            env = scan_mcp.cisco_env()
            self.assertEqual(env["MCP_SCANNER_LLM_MODEL"], "runtime-test-model")
            self.assertEqual(env["MCP_SCANNER_LLM_BASE_URL"], "https://runtime.example/v1")
            self.assertEqual(env["MCP_SCANNER_LLM_API_VERSION"], "2026-01-01")
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("_skillspector"))
            importlib.reload(importlib.import_module("scan_mcp"))

    def test_cisco_runtime_does_not_implicitly_reuse_skillspector_config(self):
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({
                "AGENT_GUARD_NO_DOTENV": "1",
                "SKILLSPECTOR_PROVIDER": "openai",
                "OPENAI_API_KEY": "sk-openai-for-skillspector",
                "SKILLSPECTOR_MODEL": "openai-test-model",
            })
            importlib.reload(importlib.import_module("_skillspector"))
            scan_mcp = importlib.reload(importlib.import_module("scan_mcp"))

            self.assertEqual(scan_mcp.CISCO_LLM_KEY, "")
            self.assertEqual(scan_mcp.CISCO_LLM_MODEL, "")
            self.assertNotIn("MCP_SCANNER_LLM_MODEL", scan_mcp.cisco_env())
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("_skillspector"))
            importlib.reload(importlib.import_module("scan_mcp"))

    def test_cisco_remote_format_flag_precedes_subcommand(self):
        scan_mcp = importlib.import_module("scan_mcp")
        calls = []

        original_scanner = scan_mcp.MCP_SCANNER
        original_run_cisco = scan_mcp.run_cisco
        original_key = scan_mcp.CISCO_LLM_KEY
        try:
            scan_mcp.MCP_SCANNER = "mcp-scanner"
            scan_mcp.CISCO_LLM_KEY = ""
            scan_mcp.run_cisco = lambda cmd, label, env=None: calls.append(cmd) or 0

            self.assertEqual(scan_mcp.run_remote("https://api.example.com/mcp"), 0)
        finally:
            scan_mcp.MCP_SCANNER = original_scanner
            scan_mcp.CISCO_LLM_KEY = original_key
            scan_mcp.run_cisco = original_run_cisco

        self.assertEqual(
            calls[0],
            ["mcp-scanner", "--format", "summary", "remote", "--server-url",
             "https://api.example.com/mcp"],
        )

    def test_cisco_remote_passes_llm_key_via_env_not_cli(self):
        scan_mcp = importlib.import_module("scan_mcp")
        calls = []

        original_scanner = scan_mcp.MCP_SCANNER
        original_run_cisco = scan_mcp.run_cisco
        original_key = scan_mcp.CISCO_LLM_KEY
        try:
            scan_mcp.MCP_SCANNER = "mcp-scanner"
            scan_mcp.CISCO_LLM_KEY = "runtime-secret"

            def fake_run_cisco(cmd, label, env=None):
                calls.append((cmd, env))
                return 0

            scan_mcp.run_cisco = fake_run_cisco

            self.assertEqual(scan_mcp.run_remote("https://api.example.com/mcp"), 0)
        finally:
            scan_mcp.MCP_SCANNER = original_scanner
            scan_mcp.CISCO_LLM_KEY = original_key
            scan_mcp.run_cisco = original_run_cisco

        cmd, env = calls[0]
        self.assertNotIn("--llm-api-key", cmd)
        self.assertEqual(env["MCP_SCANNER_LLM_API_KEY"], "runtime-secret")

    def test_cisco_runtime_rejects_mismatched_key_and_model_provider(self):
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({
                "AGENT_GUARD_NO_DOTENV": "1",
                "MCP_SCANNER_LLM_API_KEY": "sk-ant-test",
                "MCP_SCANNER_LLM_MODEL": "gpt-5.4-nano",
            })
            scan_mcp = importlib.reload(importlib.import_module("scan_mcp"))

            with self.assertRaises(SystemExit) as cm:
                scan_mcp.validate_cisco_llm_config()
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("scan_mcp"))

        self.assertEqual(cm.exception.code, 2)

    def test_cisco_env_sets_native_anthropic_key_for_litellm(self):
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({
                "AGENT_GUARD_NO_DOTENV": "1",
                "MCP_SCANNER_LLM_API_KEY": "sk-ant-test",
                "MCP_SCANNER_LLM_MODEL": "claude-haiku-4-5",
            })
            scan_mcp = importlib.reload(importlib.import_module("scan_mcp"))

            env = scan_mcp.cisco_env()
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            importlib.reload(importlib.import_module("scan_mcp"))

        self.assertEqual(env["MCP_SCANNER_LLM_API_KEY"], "sk-ant-test")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-ant-test")

    def test_virustotal_wrapper_uses_analyzer_helper_not_broken_cli(self):
        scan_mcp = importlib.import_module("scan_mcp")
        calls = []
        old_env = os.environ.copy()

        class Result:
            returncode = 0
            stdout = (
                '{"summary": {"total_found": 1, "total_to_scan": 1, "scanned": 1, '
                '"clean": 1, "malicious": 0, "not_found": 0, "throttled": 0, '
                '"failed": 0, "skipped_by_limit": 0}, "findings": []}'
            )
            stderr = ""

        original_python = scan_mcp.mcpscanner_python
        original_run = scan_mcp.subprocess.run
        try:
            os.environ.clear()
            os.environ.update({"VIRUSTOTAL_API_KEY": "vt-test"})
            scan_mcp.mcpscanner_python = lambda: "python-with-mcpscanner"

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                return Result()

            scan_mcp.subprocess.run = fake_run

            self.assertEqual(scan_mcp.run_virustotal(ROOT / "README.md", max_files=1), 0)
        finally:
            scan_mcp.mcpscanner_python = original_python
            scan_mcp.subprocess.run = original_run
            os.environ.clear()
            os.environ.update(old_env)

        self.assertEqual(calls[0][0], "python-with-mcpscanner")
        self.assertEqual(calls[0][1], "-c")
        self.assertNotIn("mcp-scanner", calls[0])
        self.assertNotIn("virustotal", calls[0])

    def test_mcp_install_rejects_installer_flags_after_remainder_args(self):
        installer = importlib.import_module("install_skill")
        original_argv = sys.argv[:]
        try:
            sys.argv = [
                "install_skill.py", "mcp",
                "--name", "time-test",
                "--command", "uvx",
                "--args", "mcp-server-time", "--dry-run", "--tools", "codex",
            ]

            with self.assertRaises(SystemExit) as cm:
                installer.main()
        finally:
            sys.argv = original_argv

        self.assertIn("installer option appears after --args", str(cm.exception))

    def test_skillspector_retries_transient_llm_rate_limit(self):
        module = importlib.import_module("_skillspector")
        calls = []

        class Result:
            def __init__(self, stderr=""):
                self.returncode = 0
                self.stdout = ""
                self.stderr = stderr

        original_state = (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
                          module.SKILLSPECTOR, module.subprocess.run,
                          module.time.sleep, module.LLM_RETRIES)
        try:
            module.PROVIDER = "openai"
            module.LLM_READY = True
            module.LLM_REASON = "openai (API key)"
            module.SKILLSPECTOR = "skillspector"
            module.SKILLSPECTOR_CMD = ["skillspector"]
            module.LLM_RETRIES = 1
            module.time.sleep = lambda seconds: None

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                self.assertNotIn("--no-llm", cmd)
                report_path = Path(cmd[cmd.index("--output") + 1])
                if len(calls) == 1:
                    # Degraded run: SkillSpector still writes a report, but the
                    # metadata says the LLM layer did not complete.
                    self._write_report(report_path, metadata={
                        "llm_available": False,
                        "llm_error": "rate_limit_exceeded"})
                    return Result("Error code: 429 rate_limit_exceeded")
                self._write_report(report_path)
                return Result()

            module.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as src_dir:
                src = Path(src_dir)
                (src / "SKILL.md").write_text("---\nname: retry\n---\n",
                                               encoding="utf-8")

                self.assertEqual(module.run_skillspector(src), 0)
        finally:
            (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
             module.SKILLSPECTOR, module.subprocess.run,
             module.time.sleep, module.LLM_RETRIES) = original_state

        self.assertEqual(len(calls), 2)

    def test_skillspector_blocks_on_partial_llm_run_after_retries(self):
        module = importlib.import_module("_skillspector")
        calls = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        original_state = (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
                          module.SKILLSPECTOR, module.subprocess.run,
                          module.time.sleep, module.LLM_RETRIES)
        try:
            module.PROVIDER = "claude_cli"
            module.LLM_READY = True
            module.LLM_REASON = "claude CLI (local login)"
            module.SKILLSPECTOR = "skillspector"
            module.SKILLSPECTOR_CMD = ["skillspector"]
            module.LLM_RETRIES = 1
            module.time.sleep = lambda seconds: None

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                report_path = Path(cmd[cmd.index("--output") + 1])
                self._write_report(report_path, metadata={
                    "llm_calls_attempted": 4, "llm_calls_succeeded": 3})
                return Result()

            module.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as src_dir:
                src = Path(src_dir)
                (src / "SKILL.md").write_text("---\nname: partial\n---\n",
                                               encoding="utf-8")
                self.assertEqual(module.run_skillspector(src), 2)
        finally:
            (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
             module.SKILLSPECTOR, module.subprocess.run,
             module.time.sleep, module.LLM_RETRIES) = original_state

        self.assertEqual(len(calls), 2)

    def test_static_only_scan_passes_no_llm_flag(self):
        module = importlib.import_module("_skillspector")
        calls = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        original_state = (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
                          module.SKILLSPECTOR, module.subprocess.run)
        try:
            module.PROVIDER = ""
            module.LLM_READY = False
            module.LLM_REASON = "no LLM provider configured"
            module.SKILLSPECTOR = "skillspector"
            module.SKILLSPECTOR_CMD = ["skillspector"]

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                report_path = Path(cmd[cmd.index("--output") + 1])
                self._write_report(report_path, metadata={
                    "llm_requested": False, "llm_available": False})
                return Result()

            module.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as src_dir:
                src = Path(src_dir)
                (src / "SKILL.md").write_text("---\nname: static\n---\n",
                                               encoding="utf-8")
                self.assertEqual(module.run_skillspector(src), 0)
        finally:
            (module.PROVIDER, module.LLM_READY, module.LLM_REASON,
             module.SKILLSPECTOR, module.subprocess.run) = original_state

        self.assertEqual(len(calls), 1)
        self.assertIn("--no-llm", calls[0])

    def test_virustotal_verdict_fails_closed_on_throttled_or_failed_lookups(self):
        scan_mcp = importlib.import_module("scan_mcp")

        self.assertEqual(scan_mcp.virustotal_verdict({
            "summary": {"scanned": 1, "failed": 1, "throttled": 0},
            "findings": [],
        }), 2)
        self.assertEqual(scan_mcp.virustotal_verdict({
            "summary": {"scanned": 1, "failed": 0, "throttled": 1},
            "findings": [],
        }), 2)

    def test_virustotal_verdict_blocks_malicious_findings(self):
        scan_mcp = importlib.import_module("scan_mcp")

        self.assertEqual(scan_mcp.virustotal_verdict({
            "summary": {"scanned": 1, "failed": 0, "throttled": 0},
            "findings": [{"severity": "HIGH", "summary": "malicious file"}],
        }), 1)

    def test_cisco_verdict_fails_closed_on_llm_auth_errors_even_with_safe_summary(self):
        scan_mcp = importlib.import_module("scan_mcp")

        output = "\n".join([
            "LLM analysis failed for get_current_time: litellm.AuthenticationError",
            "Total tools scanned: 2",
            "Unsafe items: 0",
        ])

        self.assertEqual(scan_mcp.verdict(output, 0), 2)

    def test_legacy_skill_scanner_vars_are_no_longer_read(self):
        provider, ready, _reason, _env = self._resolve({
            "SKILL_SCANNER_LLM_PROVIDER": "openai",
            "SKILL_SCANNER_LLM_API_KEY": "sk-legacy",
        })
        self.assertEqual((provider, ready), ("", False))

    def test_agent_guard_env_file_autoloads_without_overriding_process_env(self):
        old_env = os.environ.copy()
        with tempfile.TemporaryDirectory() as env_dir:
            env_file = Path(env_dir) / ".env"
            env_file.write_text(
                "\n".join([
                    "SKILLSPECTOR_PROVIDER=openai   # inline comment",
                    "OPENAI_API_KEY=from-file",
                    'SKILLSPECTOR_MODEL="from-file-model"',
                ]),
                encoding="utf-8",
            )
            try:
                os.environ.clear()
                os.environ.update({
                    "AGENT_GUARD_ENV_FILE": str(env_file),
                    "OPENAI_API_KEY": "from-process",
                })
                module = importlib.reload(importlib.import_module("_skillspector"))

                self.assertEqual(module.PROVIDER, "openai")
                self.assertTrue(module.LLM_READY)
                self.assertEqual(os.environ["OPENAI_API_KEY"], "from-process")
                self.assertEqual(os.environ["SKILLSPECTOR_MODEL"], "from-file-model")
            finally:
                os.environ.clear()
                os.environ.update(old_env)
                importlib.reload(importlib.import_module("_skillspector"))

    def test_install_skill_rejects_directory_without_skill_manifest(self):
        installer = importlib.import_module("install_skill")
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as workspace:
            src = Path(src_dir)
            (src / "README.md").write_text("# Awesome list\n", encoding="utf-8")

            with self.assertRaises(SystemExit) as cm:
                installer.install_skill(src, "awesome-list", Path(workspace), dry=True,
                                        selected=[])

            self.assertIn("missing SKILL.md", str(cm.exception))

    def test_catalog_link_discovery_deduplicates_github_repos(self):
        scan_skill = importlib.import_module("scan_skill")
        with tempfile.TemporaryDirectory() as src_dir:
            src = Path(src_dir)
            (src / "README.md").write_text(
                "\n".join([
                    "- [one](https://github.com/example/skill/tree/main/skills/foo)",
                    "- [same](https://github.com/example/skill/blob/main/SKILL.md)",
                    "- [two](https://github.com/other/catalog)",
                ]),
                encoding="utf-8",
            )

            self.assertEqual(
                scan_skill.find_catalog_links(src),
                [
                    "https://github.com/example/skill/tree/main/skills/foo",
                    "https://github.com/other/catalog",
                ],
            )

    def test_url_resolver_parses_github_tree_urls(self):
        resolver = importlib.import_module("_url_resolver")

        owner, repo, ref, subpath = resolver.github_parts(
            "https://github.com/acme/project/tree/main/skills/example"
        )

        self.assertEqual((owner, repo, ref), ("acme", "project", "main"))
        self.assertEqual(subpath, ["skills", "example"])

    def test_url_resolver_compacts_html_catalog_pages(self):
        resolver = importlib.import_module("_url_resolver")
        html = """
        <!doctype html>
        <html>
          <head><script>window.__DATA__ = "x".repeat(100000)</script></head>
          <body>
            <h1>Agent transcript skill</h1>
            <a href="https://github.com/openclaw/openclaw/tree/main/.agents/skills/agent-transcript">Skill</a>
            https://github.com/anthropics/skills\\
            https://www.npmjs.com/package/@acme/example-mcp
            https://pypi.org/project/example-mcp/
          </body>
        </html>
        """

        markdown, links, remote_links, commands = resolver.compact_page_markdown(
            "https://skillsmp.example/skill", html
        )

        self.assertIn("Agent transcript skill", markdown)
        self.assertNotIn("window.__DATA__", markdown)
        self.assertIn(
            "https://github.com/openclaw/openclaw/tree/main/.agents/skills/agent-transcript",
            links,
        )
        self.assertIn("https://github.com/anthropics/skills", links)
        self.assertNotIn("https://github.com/anthropics/skills\\", links)
        self.assertIn("https://www.npmjs.com/package/@acme/example-mcp", links)
        self.assertIn("https://pypi.org/project/example-mcp/", links)
        self.assertEqual(remote_links, [])
        self.assertEqual(commands, [])

    def test_url_resolver_extracts_remote_mcp_and_install_commands(self):
        resolver = importlib.import_module("_url_resolver")
        text = """
        Remote: https://api.example.com/mcp
        SSE: https://stream.example.com/sse
        ```bash
        npx -y @acme/example-mcp
        uvx example-mcp
        ```
        """

        markdown, source_links, remote_links, commands = resolver.compact_page_markdown(
            "https://market.example/mcp", text
        )

        self.assertEqual(source_links, [])
        self.assertEqual(remote_links, [
            "https://api.example.com/mcp",
            "https://stream.example.com/sse",
        ])
        self.assertIn("npx -y @acme/example-mcp", commands)
        self.assertIn("uvx example-mcp", commands)
        self.assertIn("Extracted remote MCP candidate URLs", markdown)

    def test_url_resolver_filters_remote_mcp_docs_and_markdown_artifacts(self):
        resolver = importlib.import_module("_url_resolver")
        text = """
        Real remote: https://mcp.alphavantage.co/mcp?apikey=YOUR_API_KEY
        Also valid: https://mcp.alphavantage.co/mcp
        Docs only: https://docs.anthropic.com/en/docs/claude-code/mcp
        Docs only: https://docs.continue.dev/customize/deep-dives/mcp
        Broken markdown: https://mcp.alphavantage.co/mcp?apikey=YOUR_API_KEY\\n```\\n
        """

        source_links, remote_links = resolver.extract_candidate_links_from_text(text)

        self.assertEqual(source_links, [])
        self.assertEqual(remote_links, ["https://mcp.alphavantage.co/mcp"])

    def test_url_resolver_excludes_github_issue_links_as_sources(self):
        resolver = importlib.import_module("_url_resolver")
        text = "\n".join([
            "https://github.com/chatmcp/mcpso/issues",
            "https://github.com/worryzyy/HowToCook-mcp",
            "https://github.com/acme/repo/tree/main/server",
        ])

        source_links, remote_links = resolver.extract_candidate_links_from_text(text)

        self.assertEqual(source_links, [
            "https://github.com/worryzyy/HowToCook-mcp",
            "https://github.com/acme/repo/tree/main/server",
        ])
        self.assertEqual(remote_links, [])

    def test_url_resolver_excludes_github_markdown_docs_as_sources(self):
        resolver = importlib.import_module("_url_resolver")
        text = "\n".join([
            "https://github.com/alphavantage/alpha_vantage_mcp/blob/main/docs/progressive-discovery.md",
            "https://github.com/openai/codex",
            "https://github.com/acme/skill/blob/main/SKILL.md",
            "https://github.com/acme/mcp/blob/main/pyproject.toml",
        ])

        source_links, remote_links = resolver.extract_candidate_links_from_text(text)

        self.assertEqual(source_links, [
            "https://github.com/acme/skill/blob/main/SKILL.md",
            "https://github.com/acme/mcp/blob/main/pyproject.toml",
        ])
        self.assertEqual(remote_links, [])


    def test_url_resolver_detects_browser_security_checkpoint(self):
        resolver = importlib.import_module("_url_resolver")
        body = "Vercel Security Checkpoint\nWe're verifying your browser\nEnable JavaScript to continue"

        self.assertTrue(resolver.is_security_checkpoint(body))
        message = resolver.format_fetch_error("https://mcpmarket.example/skill", 429, body)
        self.assertIn("No scan verdict is possible", message)
        self.assertIn("direct GitHub", message)

    def test_url_resolver_command_args_resolves_executable(self):
        resolver = importlib.import_module("_url_resolver")
        args = resolver.command_args("python -m example {url}", "https://example.test")

        self.assertTrue(Path(args[0]).name.lower().startswith("python"))
        self.assertEqual(args[-1], "https://example.test")

    def test_url_resolver_uses_render_fetch_for_blocked_catalog_page(self):
        resolver = importlib.import_module("_url_resolver")
        with tempfile.TemporaryDirectory() as src_dir:
            original_http = resolver.http_bytes
            original_render = resolver.fetch_rendered_page
            try:
                resolver.http_bytes = lambda url: (_ for _ in ()).throw(
                    resolver.FetchError("blocked")
                )
                resolver.fetch_rendered_page = lambda url: (
                    "<html><body>Rendered Skill "
                    "https://github.com/example/skill/tree/main/foo</body></html>"
                )

                source = resolver.resolve_catalog_page("https://market.example/skill",
                                                       Path(src_dir))
            finally:
                resolver.http_bytes = original_http
                resolver.fetch_rendered_page = original_render

            self.assertEqual(source.kind, "catalog")
            self.assertEqual(source.urls, ["https://github.com/example/skill/tree/main/foo"])
            self.assertEqual(source.source_urls, ["https://github.com/example/skill/tree/main/foo"])
            self.assertEqual(source.remote_urls, [])
            self.assertIn("Rendered Skill", source.source_path.read_text(encoding="utf-8"))

    def test_url_resolver_renders_when_static_page_has_no_candidates(self):
        resolver = importlib.import_module("_url_resolver")
        with tempfile.TemporaryDirectory() as src_dir:
            original_http = resolver.http_bytes
            original_render = resolver.fetch_rendered_page
            try:
                resolver.http_bytes = lambda url: (
                    b"<html><body><div id='app'></div></body></html>"
                )
                resolver.fetch_rendered_page = lambda url: (
                    "<html><body>Rendered listing "
                    "https://github.com/example/server</body></html>"
                )

                source = resolver.resolve_catalog_page("https://market.example/js-shell",
                                                       Path(src_dir))
            finally:
                resolver.http_bytes = original_http
                resolver.fetch_rendered_page = original_render

            self.assertEqual(source.urls, ["https://github.com/example/server"])
            self.assertIn("Rendered listing", source.source_path.read_text(encoding="utf-8"))

    def test_url_resolver_keeps_static_page_when_render_adds_nothing(self):
        resolver = importlib.import_module("_url_resolver")
        with tempfile.TemporaryDirectory() as src_dir:
            original_http = resolver.http_bytes
            original_render = resolver.fetch_rendered_page
            try:
                resolver.http_bytes = lambda url: (
                    b"<html><body>Static page without links</body></html>"
                )
                resolver.fetch_rendered_page = lambda url: None

                source = resolver.resolve_catalog_page("https://market.example/plain",
                                                       Path(src_dir))
            finally:
                resolver.http_bytes = original_http
                resolver.fetch_rendered_page = original_render

            self.assertEqual(source.urls, [])
            self.assertIn("Static page without links",
                          source.source_path.read_text(encoding="utf-8"))

    def test_url_resolver_playwright_falls_back_to_npx_package(self):
        resolver = importlib.import_module("_url_resolver")
        calls = []

        class Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        original_which = resolver.shutil.which
        original_run = resolver.subprocess.run
        try:
            def fake_which(name):
                return {"node": "node", "npx": "npx"}.get(name)

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                if cmd[0] == "node":
                    return Result(1, stderr="Cannot find module 'playwright'")
                return Result(0, stdout="Rendered via npx")

            resolver.shutil.which = fake_which
            resolver.subprocess.run = fake_run

            self.assertEqual(
                resolver.fetch_rendered_page("https://market.example/listing"),
                "Rendered via npx",
            )
        finally:
            resolver.shutil.which = original_which
            resolver.subprocess.run = original_run

        self.assertEqual(calls[1][:4], ["npx", "--yes", "--package", "playwright"])

    def test_url_resolver_playwright_falls_back_to_temporary_npm_package(self):
        resolver = importlib.import_module("_url_resolver")
        calls = []

        class Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        original_which = resolver.shutil.which
        original_run = resolver.subprocess.run
        try:
            def fake_which(name):
                return {"node": "node", "npx": "npx", "npm": "npm"}.get(name)

            def fake_run(cmd, **kwargs):
                calls.append((cmd, kwargs))
                if cmd[0] == "node" and "cwd" not in kwargs:
                    return Result(1, stderr="Cannot find module 'playwright'")
                if cmd[0] == "npx":
                    return Result(1, stderr="Cannot find module 'playwright'")
                if cmd[0] == "npm":
                    return Result(0)
                return Result(0, stdout="Rendered via temporary npm")

            resolver.shutil.which = fake_which
            resolver.subprocess.run = fake_run

            self.assertEqual(
                resolver.fetch_rendered_page("https://market.example/listing"),
                "Rendered via temporary npm",
            )
        finally:
            resolver.shutil.which = original_which
            resolver.subprocess.run = original_run

        self.assertEqual(calls[2][0][:4], ["npm", "install", "--prefix", calls[2][0][3]])
        self.assertEqual(calls[3][0][0], "node")
        self.assertIn("cwd", calls[3][1])

    def test_url_resolver_uses_external_firecrawl_fetch_command_first(self):
        resolver = importlib.import_module("_url_resolver")
        old_env = os.environ.copy()
        calls = []

        class Result:
            returncode = 0
            stdout = "Rendered via firecrawl"
            stderr = ""

        original_run = resolver.subprocess.run
        try:
            os.environ["AGENT_GUARD_FETCH_COMMAND"] = (
                "npx firecrawl scrape --format markdown {url}"
            )
            resolver.subprocess.run = lambda cmd, **kwargs: calls.append(cmd) or Result()

            self.assertEqual(
                resolver.fetch_rendered_page("https://market.example/listing"),
                "Rendered via firecrawl",
            )
        finally:
            os.environ.clear()
            os.environ.update(old_env)
            resolver.subprocess.run = original_run

        self.assertTrue(Path(calls[0][0]).name.lower().startswith("npx"))
        self.assertEqual(calls[0][1:3], ["firecrawl", "scrape"])

    def test_scan_url_classifies_skill_collection(self):
        scan_url = importlib.import_module("scan_url")
        with tempfile.TemporaryDirectory() as src_dir:
            src = Path(src_dir)
            (src / "skills" / "one").mkdir(parents=True)
            (src / "skills" / "one" / "SKILL.md").write_text("---\nname: one\n---\n",
                                                              encoding="utf-8")
            source = scan_url.ResolvedSource(kind="github", source_path=src)

            self.assertEqual(scan_url.classify_source(source), "skill-collection")

    def test_scan_url_preserves_catalog_kind(self):
        scan_url = importlib.import_module("scan_url")
        source = scan_url.ResolvedSource(kind="catalog", source_path=Path("catalog-page.md"))

        self.assertEqual(scan_url.classify_source(source), "catalog")

    def test_scan_url_blocks_url_catalog_without_candidates(self):
        scan_url = importlib.import_module("scan_url")
        with tempfile.TemporaryDirectory() as src_dir:
            path = Path(src_dir) / "catalog-page.md"
            path.write_text("# Marketplace page\n\nNo source links.\n", encoding="utf-8")
            source = scan_url.ResolvedSource(kind="catalog", source_path=path, urls=[])
            original = scan_url.scan_catalog
            try:
                scan_url.scan_catalog = lambda p: 0

                self.assertEqual(scan_url.scan_resolved(source, "catalog", dry_run=True), 2)
            finally:
                scan_url.scan_catalog = original

    def test_scan_url_does_not_scan_candidates_after_blocked_catalog(self):
        scan_url = importlib.import_module("scan_url")
        with tempfile.TemporaryDirectory() as src_dir:
            path = Path(src_dir) / "catalog-page.md"
            path.write_text("# Marketplace page\n\nhttps://api.example.com/mcp\n",
                            encoding="utf-8")
            source = scan_url.ResolvedSource(
                kind="catalog",
                source_path=path,
                remote_urls=["https://api.example.com/mcp"],
            )
            calls = []
            original_catalog = scan_url.scan_catalog
            original_candidates = scan_url.scan_marketplace_candidates
            try:
                scan_url.scan_catalog = lambda p: 1
                scan_url.scan_marketplace_candidates = lambda *args, **kwargs: calls.append(
                    (args, kwargs)
                ) or 0

                self.assertEqual(scan_url.scan_resolved(source, "catalog", dry_run=True), 1)
            finally:
                scan_url.scan_catalog = original_catalog
                scan_url.scan_marketplace_candidates = original_candidates

        self.assertEqual(calls, [])

    def test_scan_url_derives_package_pages_from_install_commands(self):
        scan_url = importlib.import_module("scan_url")

        self.assertEqual(
            scan_url.package_page_from_command("npx -y @acme/example-mcp"),
            ("npm", "https://www.npmjs.com/package/@acme/example-mcp"),
        )
        self.assertEqual(
            scan_url.package_page_from_command("uvx example-mcp"),
            ("pypi", "https://pypi.org/project/example-mcp/"),
        )

    def test_scan_url_scans_marketplace_candidates_instead_of_only_printing(self):
        scan_url = importlib.import_module("scan_url")
        source = scan_url.ResolvedSource(
            kind="catalog",
            source_urls=["https://www.npmjs.com/package/example-mcp"],
            remote_urls=["https://api.example.com/mcp"],
            install_commands=["uvx example-mcp"],
        )
        calls = []
        original_source = scan_url.scan_candidate_source_url
        original_remote = scan_url.run_remote
        original_sandbox = scan_url.run_sandbox
        try:
            scan_url.scan_candidate_source_url = lambda url: calls.append(("source", url)) or 0
            scan_url.run_remote = lambda url: calls.append(("remote", url)) or 0
            scan_url.run_sandbox = lambda args: calls.append(("sandbox", args)) or 0

            self.assertEqual(scan_url.scan_marketplace_candidates(
                source, sandbox=False, max_candidates=10, dry_run=True
            ), 0)
        finally:
            scan_url.scan_candidate_source_url = original_source
            scan_url.run_remote = original_remote
            scan_url.run_sandbox = original_sandbox

        self.assertIn(("source", "https://www.npmjs.com/package/example-mcp"), calls)
        self.assertIn(("remote", "https://api.example.com/mcp"), calls)
        self.assertIn(("source", "https://pypi.org/project/example-mcp/"), calls)

    def test_scan_url_dry_run_install_command_does_not_install(self):
        scan_url = importlib.import_module("scan_url")
        calls = []
        original_scan = scan_url.scan_candidate_source_url
        original_install = scan_url.install_mcp
        try:
            scan_url.scan_candidate_source_url = lambda url: 0
            scan_url.install_mcp = lambda *args, **kwargs: calls.append((args, kwargs))

            self.assertEqual(scan_url.scan_install_command(
                "uvx example-mcp", sandbox=False, dry_run=True
            ), 0)
        finally:
            scan_url.scan_candidate_source_url = original_scan
            scan_url.install_mcp = original_install

        self.assertEqual(calls, [])

    def test_scan_url_noninteractive_safe_mcp_prints_install_command_only(self):
        scan_url = importlib.import_module("scan_url")
        calls = []
        original_interactive = scan_url.interactive
        original_install = scan_url.install_mcp
        try:
            scan_url.interactive = lambda: False
            scan_url.install_mcp = lambda *args, **kwargs: calls.append((args, kwargs))

            scan_url.offer_mcp_install("example-mcp", "uvx", ["example-mcp"], dry_run=False)
        finally:
            scan_url.interactive = original_interactive
            scan_url.install_mcp = original_install

        self.assertEqual(calls, [])

    def test_install_mcp_remote_writes_url_entries(self):
        installer = importlib.import_module("install_skill")
        calls = []
        original_detect = installer.detect_tools
        original_json = installer.add_to_json_config
        original_codex = installer.add_to_codex_toml
        original_claude = installer.add_to_claude_code
        try:
            installer.detect_tools = lambda selected=None: {
                "claude-code": True,
                "claude-desktop": True,
                "codex": True,
                "antigravity": True,
                "hermes": False,
                "openclaw": False,
            }
            installer.add_to_json_config = lambda path, name, entry, dry, include_disabled=False: calls.append(
                ("json", name, entry, include_disabled)
            )
            installer.add_to_codex_toml = lambda name, entry, dry: calls.append(
                ("codex", name, entry)
            )
            installer.add_to_claude_code = lambda name, entry, dry: calls.append(
                ("claude", name, entry)
            )

            installer.install_mcp("remote-api", {"url": "https://api.example.com/mcp"},
                                  dry=True)
        finally:
            installer.detect_tools = original_detect
            installer.add_to_json_config = original_json
            installer.add_to_codex_toml = original_codex
            installer.add_to_claude_code = original_claude

        self.assertIn(("claude", "remote-api", {"url": "https://api.example.com/mcp"}), calls)
        self.assertIn(("codex", "remote-api", {"url": "https://api.example.com/mcp"}), calls)
        self.assertIn(("json", "remote-api", {"url": "https://api.example.com/mcp"}, False), calls)
        self.assertIn(("json", "remote-api", {"url": "https://api.example.com/mcp"}, True), calls)

    def test_install_mcp_git_uses_uv_tool_executable(self):
        installer = importlib.import_module("install_skill")
        calls = []
        original_install = installer.install_mcp
        original_tool_dir = installer.uv_tool_dir
        try:
            with tempfile.TemporaryDirectory() as tools_dir:
                installer.uv_tool_dir = lambda: Path(tools_dir)
                installer.install_mcp = lambda name, entry, dry, selected=None: calls.append(
                    (name, entry, dry, selected)
                )

                installer.install_mcp_git(
                    "example-mcp",
                    "git+https://github.com/example/mcp@abc123",
                    "example-mcp",
                    dry=True,
                    selected=["codex"],
                    executable="example-server",
                )
        finally:
            installer.install_mcp = original_install
            installer.uv_tool_dir = original_tool_dir

        name, entry, dry, selected = calls[0]
        self.assertEqual(name, "example-mcp")
        self.assertIn("example-server", entry["command"])
        self.assertEqual(entry["args"], [])
        self.assertTrue(dry)
        self.assertEqual(selected, ["codex"])

    def test_scan_url_safe_remote_candidate_offers_remote_install(self):
        scan_url = importlib.import_module("scan_url")
        calls = []
        source = scan_url.ResolvedSource(
            kind="catalog",
            remote_urls=["https://api.example.com/mcp"],
        )
        original_remote = scan_url.run_remote
        original_offer = scan_url.offer_remote_mcp_install
        try:
            scan_url.run_remote = lambda url: 0
            scan_url.offer_remote_mcp_install = lambda name, url, dry_run: calls.append(
                (name, url, dry_run)
            )

            self.assertEqual(scan_url.scan_marketplace_candidates(
                source, sandbox=False, max_candidates=10, dry_run=True
            ), 0)
        finally:
            scan_url.run_remote = original_remote
            scan_url.offer_remote_mcp_install = original_offer

        self.assertEqual(calls, [("api-example-com", "https://api.example.com/mcp", True)])

    def test_scan_url_safe_github_python_mcp_offers_git_install(self):
        scan_url = importlib.import_module("scan_url")
        calls = []
        with tempfile.TemporaryDirectory() as src_dir:
            src = Path(src_dir)
            (src / "pyproject.toml").write_text(
                "\n".join([
                    "[project]",
                    'name = "example-mcp"',
                    "[project.scripts]",
                    'example-server = "example.server:main"',
                ]),
                encoding="utf-8",
            )
            source = scan_url.ResolvedSource(
                kind="github",
                source_path=src,
                install_hint="https://github.com/example/mcp@abc123",
            )
            original_static = scan_url.run_mcp_static
            original_offer = scan_url.install_mcp_git
            original_interactive = scan_url.interactive
            original_confirm = scan_url.confirm_install
            original_choose = scan_url.choose_install_tools
            try:
                scan_url.run_mcp_static = lambda path: 0
                scan_url.install_mcp_git = lambda *args, **kwargs: calls.append((args, kwargs))
                scan_url.interactive = lambda: True
                scan_url.confirm_install = lambda prompt: True
                scan_url.choose_install_tools = lambda: ["codex"]

                self.assertEqual(scan_url.scan_resolved(source, "mcp-source", dry_run=False), 0)
            finally:
                scan_url.run_mcp_static = original_static
                scan_url.install_mcp_git = original_offer
                scan_url.interactive = original_interactive
                scan_url.confirm_install = original_confirm
                scan_url.choose_install_tools = original_choose

        self.assertEqual(calls[0][0][:3], (
            "example-mcp",
            "git+https://github.com/example/mcp@abc123",
            "example-mcp",
        ))
        self.assertFalse(calls[0][1]["dry"])
        self.assertEqual(calls[0][1]["selected"], ["codex"])
        self.assertEqual(calls[0][1]["executable"], "example-server")

    def test_scan_url_allows_catalog_with_remote_candidate_but_not_final_verdict(self):
        scan_url = importlib.import_module("scan_url")
        with tempfile.TemporaryDirectory() as src_dir:
            path = Path(src_dir) / "catalog-page.md"
            path.write_text("# Marketplace page\n\nhttps://api.example.com/mcp\n",
                            encoding="utf-8")
            source = scan_url.ResolvedSource(
                kind="catalog",
                source_path=path,
                urls=[],
                remote_urls=["https://api.example.com/mcp"],
            )
            original = scan_url.scan_catalog
            original_remote = scan_url.run_remote
            try:
                scan_url.scan_catalog = lambda p: 0
                scan_url.run_remote = lambda url: 0

                self.assertEqual(scan_url.scan_resolved(source, "catalog", dry_run=True), 0)
            finally:
                scan_url.scan_catalog = original
                scan_url.run_remote = original_remote

    def test_scan_url_can_persist_resolved_source(self):
        scan_url = importlib.import_module("scan_url")
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as out_dir:
            src = Path(src_dir)
            (src / "SKILL.md").write_text("---\nname: one\n---\n", encoding="utf-8")
            target = Path(out_dir) / "persisted"
            source = scan_url.ResolvedSource(kind="github", source_path=src)

            stable = scan_url.persist_source(source, target)

            self.assertEqual(stable, target.resolve())
            self.assertTrue((target / "SKILL.md").is_file())

    def test_audit_installed_infers_uvx_git_mcp_scan_commands(self):
        audit = importlib.import_module("audit_installed")
        entry = {
            "command": "uvx",
            "args": [
                "--from",
                "git+https://github.com/example/mcp@abc123",
                "example-mcp",
            ],
        }

        self.assertEqual(
            audit.mcp_source_scan_command(entry),
            ["python", "scripts/scan_url.py", "https://github.com/example/mcp/tree/abc123"],
        )
        self.assertEqual(
            audit.mcp_sandbox_command(entry),
            [
                "python",
                "scripts/scan_mcp.py",
                "sandbox",
                "--",
                "uvx",
                "--from",
                "git+https://github.com/example/mcp@abc123",
                "example-mcp",
            ],
        )

    def test_audit_installed_ignores_codex_env_subsections(self):
        audit = importlib.import_module("audit_installed")
        with tempfile.TemporaryDirectory() as src_dir:
            cfg = Path(src_dir) / "config.toml"
            cfg.write_text(
                "\n".join([
                    "[mcp_servers.example]",
                    'command = "uvx"',
                    'args = ["pkg"]',
                    "[mcp_servers.example.env]",
                    'TOKEN = "secret"',
                ]),
                encoding="utf-8",
            )

            servers = audit.read_codex_mcp_servers(cfg)

            self.assertEqual(list(servers), ["example"])
            self.assertEqual(servers["example"]["command"], "uvx")

    def test_audit_installed_reads_remote_codex_url(self):
        audit = importlib.import_module("audit_installed")
        with tempfile.TemporaryDirectory() as src_dir:
            cfg = Path(src_dir) / "config.toml"
            cfg.write_text(
                "\n".join([
                    "[mcp_servers.remote]",
                    'enabled = true',
                    'url = "https://api.example.com/mcp"',
                ]),
                encoding="utf-8",
            )

            servers = audit.read_codex_mcp_servers(cfg)

            self.assertEqual(servers["remote"]["url"], "https://api.example.com/mcp")
            self.assertEqual(
                audit.mcp_source_scan_command(servers["remote"]),
                ["python", "scripts/scan_mcp.py", "remote", "https://api.example.com/mcp"],
            )
            self.assertIsNone(audit.mcp_sandbox_command(servers["remote"]))

    def test_audit_installed_infers_windows_launcher_packages(self):
        audit = importlib.import_module("audit_installed")

        self.assertEqual(
            audit.mcp_source_scan_command({
                "command": "C:/Users/me/.local/bin/uvx.exe",
                "args": ["markitdown-mcp"],
            }),
            ["python", "scripts/scan_mcp.py", "pypi", "markitdown-mcp"],
        )
        self.assertEqual(
            audit.mcp_source_scan_command({
                "command": "C:/nvm4w/nodejs/npx.cmd",
                "args": ["-y", "n8n-mcp@2.36.1"],
            }),
            ["python", "scripts/scan_mcp.py", "npm", "n8n-mcp@2.36.1"],
        )

    def test_audit_installed_uses_node_modules_package_root(self):
        audit = importlib.import_module("audit_installed")
        path = Path("C:/repo/node_modules/pkg/build/main/cli.js")

        self.assertEqual(audit.package_root_for_file(path), Path("C:/repo/node_modules/pkg"))

    def test_docs_use_scan_skill_wrapper_for_skill_scans(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

        self.assertIn("python scripts/scan_skill.py", readme)
        self.assertIn("python \"$SKILL_DIR/scripts/scan_skill.py\"", skill)
        self.assertNotIn("PYTHONUTF8=1 skillspector scan", readme)
        self.assertNotIn("PYTHONUTF8=1 skillspector scan", skill)
        self.assertNotIn("fast + cheap for scanning", readme)
        self.assertNotIn("OpenAI or NVIDIA key is required", readme)
        self.assertNotIn("OpenAI or NVIDIA", skill)
        self.assertIn("`claude_cli`", readme)
        self.assertIn("AGENT_GUARD_STATIC_ONLY", readme)
        self.assertIn("SKILLSPECTOR_PROVIDER=claude_cli", env_example)
        self.assertIn("MCP_SCANNER_LLM_MODEL", readme)
        self.assertIn("VirusTotal is optional but useful for private users", readme)
        self.assertIn("python scripts/scan_mcp.py virustotal", readme)
        self.assertNotIn("mcp-scanner virustotal", readme)
        self.assertIn("agent-guard does not require this", env_example)

        # Install examples must use repeated --arg: the legacy --args REMAINDER
        # form swallows --env/--dry-run and the installer rejects that order.
        for doc in (readme, skill):
            self.assertNotIn('--args "', doc)
            self.assertNotIn("--args bar", doc)
            self.assertNotIn("--args ARG", doc)


class ClaudeDesktopConfigPathTests(unittest.TestCase):
    def test_windows_uses_appdata(self):
        installer = importlib.import_module("install_skill")
        path = installer.claude_desktop_config_path("win32")
        self.assertEqual(
            path, installer.APPDATA / "Claude" / "claude_desktop_config.json"
        )

    def test_macos_uses_application_support(self):
        installer = importlib.import_module("install_skill")
        path = installer.claude_desktop_config_path("darwin")
        self.assertEqual(
            path,
            installer.HOME / "Library" / "Application Support" / "Claude"
            / "claude_desktop_config.json",
        )

    def test_linux_uses_xdg_config_home_with_fallback(self):
        installer = importlib.import_module("install_skill")
        old = os.environ.get("XDG_CONFIG_HOME")
        try:
            os.environ["XDG_CONFIG_HOME"] = "/custom/config"
            self.assertEqual(
                installer.claude_desktop_config_path("linux"),
                Path("/custom/config") / "Claude" / "claude_desktop_config.json",
            )
            del os.environ["XDG_CONFIG_HOME"]
            self.assertEqual(
                installer.claude_desktop_config_path("linux"),
                installer.HOME / ".config" / "Claude"
                / "claude_desktop_config.json",
            )
        finally:
            if old is not None:
                os.environ["XDG_CONFIG_HOME"] = old
            else:
                os.environ.pop("XDG_CONFIG_HOME", None)


class ScanMcpCliParsingTests(unittest.TestCase):
    def test_split_launch_command_extracts_tokens_after_double_dash(self):
        scan_mcp = importlib.import_module("scan_mcp")
        argv, command = scan_mcp._split_launch_command(
            ["pypi", "mcp-server-time", "--sandbox", "--", "uvx", "mcp-server-time"]
        )
        self.assertEqual(argv, ["pypi", "mcp-server-time", "--sandbox"])
        self.assertEqual(command, ["uvx", "mcp-server-time"])

    def test_split_launch_command_without_double_dash_is_passthrough(self):
        scan_mcp = importlib.import_module("scan_mcp")
        argv, command = scan_mcp._split_launch_command(
            ["sandbox", "uvx", "mcp-server-time"]
        )
        self.assertEqual(argv, ["sandbox", "uvx", "mcp-server-time"])
        self.assertEqual(command, [])

    def test_split_launch_command_splits_only_at_first_double_dash(self):
        scan_mcp = importlib.import_module("scan_mcp")
        argv, command = scan_mcp._split_launch_command(
            ["sandbox", "--", "npx", "-y", "some-server", "--", "--flag"]
        )
        self.assertEqual(argv, ["sandbox"])
        self.assertEqual(command, ["npx", "-y", "some-server", "--", "--flag"])


class ScanCliRouterTests(unittest.TestCase):
    def setUp(self):
        self.scan_cli = importlib.import_module("scan_cli")

    # -- spec parsing ----------------------------------------------------------

    def test_split_version_plain_and_versioned(self):
        self.assertEqual(self.scan_cli._split_version("ripgrep", ("@",)),
                         ("ripgrep", None))
        self.assertEqual(self.scan_cli._split_version("ripgrep@14.1.0", ("@",)),
                         ("ripgrep", "14.1.0"))

    def test_split_version_pypi_double_equals(self):
        self.assertEqual(
            self.scan_cli._split_version("requests==2.32.0", ("==", "@")),
            ("requests", "2.32.0"))

    def test_split_version_keeps_npm_scope(self):
        self.assertEqual(
            self.scan_cli._split_version("@scope/pkg@1.2.3", ("@",)),
            ("@scope/pkg", "1.2.3"))
        self.assertEqual(
            self.scan_cli._split_version("@scope/pkg", ("@",)),
            ("@scope/pkg", None))

    # -- JSON extraction -------------------------------------------------------

    def test_extract_json_tolerates_surrounding_noise(self):
        text = 'pulling image...\n{"issues": 0, "results": {}}\ndone'
        self.assertEqual(self.scan_cli._extract_json(text),
                         {"issues": 0, "results": {}})

    def test_extract_json_returns_none_on_garbage(self):
        self.assertIsNone(self.scan_cli._extract_json("no json here"))
        self.assertIsNone(self.scan_cli._extract_json(""))

    # -- GuardDog verdict mapping (fail closed) --------------------------------

    def test_guarddog_verdict_safe_on_zero_issues(self):
        self.assertEqual(
            self.scan_cli.guarddog_verdict({"issues": 0, "results": {}}), 0)

    def test_guarddog_verdict_blocks_on_findings(self):
        self.assertEqual(
            self.scan_cli.guarddog_verdict(
                {"issues": 2, "results": {"exfiltrate": ["bad"]}}), 1)

    def test_guarddog_verdict_counts_results_when_issue_count_missing(self):
        self.assertEqual(
            self.scan_cli.guarddog_verdict(
                {"results": {"exec-base64": ["hit"], "clean-rule": []}}), 1)
        self.assertEqual(
            self.scan_cli.guarddog_verdict({"results": {"clean-rule": []}}), 0)

    def test_guarddog_verdict_capability_rules_alone_do_not_block(self):
        # GuardDog 3.0 capability-* rules are transparency notes that fire on
        # nearly every real library (e.g. `requests` reads files). They must
        # not turn every ordinary package into a BLOCK.
        self.assertEqual(
            self.scan_cli.guarddog_verdict({"results": {
                "capability-filesystem-read": [{"match": ".read("}],
                "capability-process-spawn": [{"match": "system("}],
            }}), 0)

    def test_guarddog_verdict_install_hook_capability_blocks(self):
        # Distilled from a REAL malicious sample (DataDog
        # malicious-software-packages-dataset, pypi/malicious_intent/0wneg):
        # GuardDog 3.0 fires ONLY capability rules on it. An install-time hook
        # executes code at `pip install` -- it must block, or the pure
        # capability/heuristic split waves real malware through.
        self.assertEqual(
            self.scan_cli.guarddog_verdict({"results": {
                "capability-process-hooks": [{
                    "location": "0wneg-0.9.0/setup.py:86",
                    "match": "cmdclass={'develop': ..., 'install':",
                    "message": "has_python_hook rule matched",
                }],
                "capability-filesystem-read": [{"match": ".read("}],
                "threat-runtime-obfuscation-pyarmor": {},
            }}), 1)

    def test_guarddog_verdict_malware_heuristic_blocks_despite_capabilities(self):
        self.assertEqual(
            self.scan_cli.guarddog_verdict({"results": {
                "capability-filesystem-read": [{"match": ".read("}],
                "exfiltrate-sensitive-data": [{"match": "curl"}],
            }}), 1)

    def test_guarddog_verdict_issue_count_without_results_blocks(self):
        # No per-rule results to classify -> conservative: any finding blocks.
        self.assertEqual(self.scan_cli.guarddog_verdict({"issues": 3}), 1)

    def test_guarddog_verdict_fails_closed_on_empty_report(self):
        self.assertEqual(self.scan_cli.guarddog_verdict({}), 2)

    def test_guarddog_verdict_fails_closed_on_errors_without_findings(self):
        self.assertEqual(
            self.scan_cli.guarddog_verdict(
                {"issues": 0, "results": {}, "errors": {"rule": "boom"}}), 2)

    # -- GuardDog invocation ---------------------------------------------------

    def test_guarddog_command_prefers_native_binary(self):
        original = self.scan_cli.shutil.which
        try:
            self.scan_cli.shutil.which = lambda name: (
                "/usr/bin/guarddog" if name == "guarddog" else None)
            cmd = self.scan_cli.guarddog_command("pypi", "requests", "2.32.0")
        finally:
            self.scan_cli.shutil.which = original
        self.assertEqual(cmd, ["/usr/bin/guarddog", "pypi", "scan", "requests",
                               "--output-format", "json",
                               "--version", "2.32.0"])

    def test_guarddog_command_falls_back_to_docker(self):
        original = self.scan_cli.shutil.which
        try:
            self.scan_cli.shutil.which = lambda name: (
                "docker" if name == "docker" else None)
            cmd = self.scan_cli.guarddog_command("npm", "left-pad")
        finally:
            self.scan_cli.shutil.which = original
        self.assertEqual(cmd[:4], ["docker", "run", "--rm",
                                   self.scan_cli.GUARDDOG_IMAGE])
        self.assertEqual(cmd[4:], ["npm", "scan", "left-pad",
                                   "--output-format", "json"])

    def test_guarddog_command_dies_without_guarddog_or_docker(self):
        original = self.scan_cli.shutil.which
        try:
            self.scan_cli.shutil.which = lambda name: None
            with self.assertRaises(SystemExit) as ctx:
                self.scan_cli.guarddog_command("pypi", "requests")
        finally:
            self.scan_cli.shutil.which = original
        self.assertEqual(ctx.exception.code, 2)

    # -- malcontent verdict ----------------------------------------------------

    def test_malcontent_verdict_blocks_on_high_or_critical(self):
        self.assertEqual(self.scan_cli.malcontent_verdict(
            {"Files": {"tool.exe": {"RiskLevel": "HIGH"}}}), 1)
        self.assertEqual(self.scan_cli.malcontent_verdict(
            {"Files": {"tool.exe": {"RiskLevel": "CRITICAL"}}}), 1)

    def test_malcontent_verdict_safe_on_low_risk(self):
        self.assertEqual(self.scan_cli.malcontent_verdict(
            {"Files": {"tool.exe": {"RiskLevel": "LOW"}}}), 0)

    def test_malcontent_verdict_fails_closed_without_files(self):
        self.assertEqual(self.scan_cli.malcontent_verdict({"Files": {}}), 2)
        self.assertEqual(self.scan_cli.malcontent_verdict({}), 2)

    # -- binary flow -----------------------------------------------------------

    def test_run_binary_hashes_then_delegates_to_virustotal(self):
        calls = {}
        original_download = self.scan_cli._download
        original_vt = self.scan_cli.run_virustotal
        try:
            def fake_download(url, dest):
                Path(dest).write_bytes(b"binary-bytes")
                calls["url"] = url
                return Path(dest)

            self.scan_cli._download = fake_download
            self.scan_cli.run_virustotal = (
                lambda path, max_files=10: calls.setdefault("vt", Path(path)) and 0)
            rc = self.scan_cli.run_binary(
                "https://example.com/releases/tool.exe", deep=False)
        finally:
            self.scan_cli._download = original_download
            self.scan_cli.run_virustotal = original_vt
        self.assertEqual(rc, 0)
        self.assertEqual(calls["url"], "https://example.com/releases/tool.exe")
        self.assertEqual(calls["vt"].name, "tool.exe")

    def test_run_binary_deep_combines_verdicts_fail_closed(self):
        original_download = self.scan_cli._download
        original_vt = self.scan_cli.run_virustotal
        original_mal = self.scan_cli.run_malcontent
        try:
            self.scan_cli._download = (
                lambda url, dest: Path(dest).write_bytes(b"x") or Path(dest))
            self.scan_cli.run_virustotal = lambda path, max_files=10: 0
            self.scan_cli.run_malcontent = lambda path: 1
            rc = self.scan_cli.run_binary("https://example.com/t.exe", deep=True)
        finally:
            self.scan_cli._download = original_download
            self.scan_cli.run_virustotal = original_vt
            self.scan_cli.run_malcontent = original_mal
        self.assertEqual(rc, 1)

    # -- cargo (GuardDog crates + static) -------------------------------------

    def _run_cargo_with(self, guarddog_rc: int, skillspector_rc: int):
        import contextlib
        import io as _io

        original_fetch = self.scan_cli.fetch_crate
        original_scan = self.scan_cli.run_skillspector
        original_gd = self.scan_cli.run_guarddog
        calls = {}
        try:
            self.scan_cli.fetch_crate = (
                lambda spec, dest: calls.setdefault("spec", spec)
                and ("ripgrep", "14.1.0"))
            self.scan_cli.run_skillspector = (
                lambda src: (calls.setdefault("scanned", Path(src)), skillspector_rc)[1])
            self.scan_cli.run_guarddog = (
                lambda eco, spec: calls.setdefault("guarddog", (eco, spec)) and guarddog_rc)
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.scan_cli.run_cargo("ripgrep@14.1.0")
        finally:
            self.scan_cli.fetch_crate = original_fetch
            self.scan_cli.run_skillspector = original_scan
            self.scan_cli.run_guarddog = original_gd
        return rc, calls, buf.getvalue()

    def test_run_cargo_runs_guarddog_crates_and_static_scan(self):
        rc, calls, out = self._run_cargo_with(0, 0)
        self.assertEqual(rc, 0)
        self.assertEqual(calls["guarddog"], ("crates", "ripgrep@14.1.0"))
        self.assertEqual(calls["spec"], "ripgrep@14.1.0")
        self.assertIn("scanned", calls)
        self.assertIn("GuardDog crates scan", out)
        self.assertIn("sfw cargo install", out)
        self.assertIn("[SAFE] cargo combined verdict", out)

    def test_run_cargo_combines_verdicts_fail_closed(self):
        self.assertEqual(self._run_cargo_with(0, 1)[0], 1)
        self.assertEqual(self._run_cargo_with(1, 2)[0], 1)
        self.assertEqual(self._run_cargo_with(2, 0)[0], 2)
        self.assertEqual(self.scan_cli.combine_verdicts(0, 0), 0)
        self.assertEqual(self.scan_cli.combine_verdicts(2, 1), 1)

    # -- script flow -----------------------------------------------------------

    def test_run_script_documents_static_limit_and_scans_download(self):
        import contextlib
        import io as _io

        original_download = self.scan_cli._download
        original_scan = self.scan_cli.run_skillspector
        calls = {}
        try:
            def fake_download(url, dest):
                Path(dest).write_text("echo hi", encoding="utf-8")
                return Path(dest)

            self.scan_cli._download = fake_download
            self.scan_cli.run_skillspector = (
                lambda src: calls.setdefault("scanned", Path(src)) and 0)
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.scan_cli.run_script("https://example.com/install.sh")
        finally:
            self.scan_cli._download = original_download
            self.scan_cli.run_skillspector = original_scan
        self.assertEqual(rc, 0)
        self.assertEqual(calls["scanned"].name, "install.sh")
        self.assertIn("STATIC scan", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
