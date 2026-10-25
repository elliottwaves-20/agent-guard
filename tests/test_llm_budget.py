"""Budget failures must stop dispatch, not turn into clean scanner results."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
from _llm_budget import Budget, Paused, atomic_json, exclusive_lock, policy_from_profile
from _llm_profile import ProfileError

CAMPAIGN = {"kind": "api", "protocol": "openai", "base_url": "https://api.cerebras.ai/v1",
            "model": "gpt-oss-120b", "key_env": "CEREBRAS_API_KEY", "max_output": 4096,
            "price": {"input_usd_per_mtok": 0.35, "output_usd_per_mtok": 0.75},
            "budget": {"total_usd": 4, "step_usd": 0.5, "probe_usd": 0.1, "step_requests": 10},
            "limits": {"rpm": 3, "tpm": 30000}}
POLICY = policy_from_profile("test", CAMPAIGN, "2.12.0")
from _llm_adapter import Model, ProviderError, strict_schema
from llm_scan import new_session, validate_session


class BudgetTests(unittest.TestCase):
    def test_http_client_identifies_guard(self):
        from _llm_adapter import http_json
        with patch("_llm_adapter.urllib.request.build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{}'
            response.headers = {}
            http_json("https://api.cerebras.ai/public/v1/models/gpt-oss-120b")
            request = factory.return_value.open.call_args.args[0]
            version = (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
            self.assertEqual(request.get_header("User-agent"), f"agent-guard/{version}")
            self.assertIsNone(request.get_header("Authorization"))

    def test_preflight_failure_writes_incomplete_progress(self):
        import llm_scan
        target = self.root / "fixture"
        target.mkdir()
        (target / "SKILL.md").write_text("Say hello")
        campaign = self.root / "campaign"
        session = new_session(target, campaign, POLICY)
        with patch("_llm_adapter.install"), patch("_llm_adapter.live_transport", side_effect=ProviderError(403)):
            self.assertEqual(llm_scan.scan(session, campaign, False, POLICY), 2)
        result = json.loads((session / "progress.json").read_text())
        self.assertFalse(result["complete"])
        self.assertEqual(result["requests_total"], 0)
        self.assertIn("403", result["pause_reason"])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.session = self.root / "session"
        self.session.mkdir()
        self.sent = []
        self.now = 1000.0

    def sleep(self, seconds):
        self.now += seconds

    def transport(self, payload):
        self.sent.append(payload)
        return {"choices": [{"finish_reason": "stop", "message": {"content": '{"findings":[]}'}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 10}}, {}

    def budget(self, **kwargs):
        return Budget(self.root, self.session, kwargs.pop("identity", "snapshot"),
                      policy=kwargs.pop("policy", POLICY), transport=self.transport,
                      clock=lambda: self.now, sleep=self.sleep, **kwargs)

    def call(self, budget, prompt="a", analyzer="security"):
        return budget.call({"messages": [{"role": "user", "content": prompt}]},
                           {"analyzer": analyzer}, json.loads)

    def test_preview_never_dispatches_and_remains_incomplete(self):
        budget = self.budget(preview=True)
        for prompt in ("one", "two", "three"):
            with self.assertRaises(Paused):
                self.call(budget, prompt)
        self.assertEqual(self.sent, [])
        self.assertEqual(len(budget.summary()["prompts"]), 3)
        self.assertFalse(budget.summary()["complete"])

    def test_probe_one_call_and_resume_cache(self):
        first = self.budget()
        self.call(first)
        with self.assertRaises(Paused):
            self.call(first, "b")
        resumed = self.budget()
        self.call(resumed)
        self.assertEqual(len(self.sent), 1)
        self.call(resumed, "b")
        self.assertEqual(len(self.sent), 2)
        self.assertGreaterEqual(self.now, 1020)
        self.assertEqual(resumed.summary()["requests_total"], 2)

    def test_timeout_reserved_and_not_retried_after_restart(self):
        budget = self.budget()
        def timeout(payload):
            self.sent.append(payload)
            # Verify reservation was flushed before the first byte could be sent.
            ledger = json.loads((self.root / "budget.json").read_text())
            self.assertEqual(ledger["attempts"][0]["state"], "reserved")
            raise TimeoutError()
        budget.transport = timeout
        with self.assertRaises(Paused):
            self.call(budget)
        reserved = budget.data["attempts"][0]["charged_nusd"]
        with self.assertRaises(Paused):
            self.call(self.budget())
        self.assertEqual(len(self.sent), 1)
        self.assertGreater(reserved, 0)

    def test_campaign_limit_shared_across_sessions(self):
        budget = self.budget()
        self.call(budget)
        budget.data["attempts"][0]["charged_nusd"] = POLICY["total_nusd"] - 1
        budget.save()
        self.session = self.root / "different-session"
        self.session.mkdir()
        with self.assertRaises(Paused):
            self.call(self.budget(), "new")
        self.assertEqual(len(self.sent), 1)

    def test_429_is_single_attempt_and_can_resume_after_reset(self):
        budget = self.budget()
        def limited(payload):
            self.sent.append(payload)
            raise ProviderError(429, 120)
        budget.transport = limited
        with self.assertRaises(Paused):
            self.call(budget)
        with self.assertRaises(Paused):
            self.call(self.budget())
        self.assertEqual(len(self.sent), 1)
        self.now += 121
        self.call(self.budget())
        self.assertEqual(len(self.sent), 2)

    def test_invalid_or_truncated_output_is_never_cached(self):
        for reason, content in (("length", '{}'), ("stop", 'invalid')):
            with self.subTest(reason=reason):
                budget = self.budget(identity=reason)
                budget.transport = lambda p: ({"choices": [{"finish_reason": reason,
                                                           "message": {"content": content}}]}, {})
                with self.assertRaises(Paused):
                    self.call(budget)
                self.assertFalse((self.session / "responses").exists())

    def test_missing_usage_retains_full_reservation(self):
        budget = self.budget()
        budget.transport = lambda p: ({"choices": [{"finish_reason": "stop", "message": {"content": '{}'}}]}, {})
        self.call(budget)
        attempt = budget.data["attempts"][0]
        self.assertEqual(attempt["charged_nusd"], attempt["reserved_nusd"])
        self.assertGreater(attempt["charged_nusd"], 0)

    def test_oversized_prompt_not_sent(self):
        with self.assertRaises(Paused):
            self.call(self.budget(), "z" * 30000)
        self.assertEqual(self.sent, [])

    def test_lower_provider_quota_pauses_before_dispatch(self):
        budget = self.budget()
        self.call(budget)
        budget.quota_headers({"x-ratelimit-remaining-tokens-minute": "1",
                              "x-ratelimit-reset-tokens-minute": "60s"})
        budget.save()
        with self.assertRaises(Paused):
            self.call(self.budget(), "next")
        self.assertEqual(len(self.sent), 1)

    def test_stage_stops_after_ten_requests(self):
        self.call(self.budget(), "probe")
        budget = self.budget()
        for index in range(10):
            self.call(budget, str(index))
        with self.assertRaises(Paused):
            self.call(budget, "eleventh")
        self.assertEqual(len(self.sent), 11)

    def test_payload_change_does_not_reuse_answer(self):
        self.call(self.budget(), "before")
        self.call(self.budget(), "after")
        self.assertEqual(len(self.sent), 2)

    def test_schema_and_snapshot_invalidate_cache(self):
        self.call(self.budget())
        self.call(self.budget(identity="changed"))
        self.assertEqual(len(self.sent), 2)

    def test_prerequisite_failure_defers_meta(self):
        budget = self.budget()
        budget.observed["previous"] = {"state": "pending", "analyzer": "security"}
        with self.assertRaises(Paused):
            self.call(budget, analyzer="meta_analyzer")
        self.assertEqual(self.sent, [])

    def test_cross_process_lock(self):
        script = "from pathlib import Path; from _llm_budget import exclusive_lock; "
        script += "\nwith exclusive_lock(Path(__import__('sys').argv[1])): print('acquired')"
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "scripts"))
        with exclusive_lock(self.root / "lock"):
            child = subprocess.run([sys.executable, "-c", script, str(self.root / "lock")],
                                   env=env, capture_output=True, timeout=10)
            self.assertNotEqual(child.returncode, 0)
        with exclusive_lock(self.root / "lock"):
            pass

    def test_snapshot_detects_change_and_excludes_local_key_file(self):
        target = self.root / "target"
        target.mkdir()
        (target / "SKILL.md").write_text("Read-only skill")
        (target / ".env").write_text("CEREBRAS_API_KEY=test-not-real")
        campaign = self.root / "campaign"
        session = new_session(target, campaign, POLICY)
        info = validate_session(session, campaign, POLICY)
        self.assertNotIn(".env", info["files"])
        self.assertEqual(info["excluded"][0]["path"], ".env")
        (session / "snapshot/SKILL.md").write_text("Changed")
        with self.assertRaises(Paused):
            validate_session(session, campaign, POLICY)

    def test_structured_payload_has_no_tools_and_preserves_prompt(self):
        class Schema:
            @staticmethod
            def model_json_schema():
                return {"type": "object", "properties": {"findings": {"type": "array", "items": {"type": "string"}}}}
            model_validate_json = staticmethod(json.loads)
        result = Model(self.budget()).with_structured_output(Schema).invoke("Untrusted complete prompt")
        self.assertEqual(result, {"findings": []})
        payload = self.sent[0]
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["messages"][0]["content"], "Untrusted complete prompt")
        self.assertEqual(payload["max_completion_tokens"], 4096)
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])

    def test_policy_converts_profile_prices_and_caps_to_nano_dollars(self):
        self.assertEqual((POLICY["input_nusd"], POLICY["output_nusd"]), (350, 750))
        self.assertEqual((POLICY["total_nusd"], POLICY["step_nusd"], POLICY["probe_nusd"]),
                         (4_000_000_000, 500_000_000, 100_000_000))
        self.assertEqual((POLICY["output_tokens"], POLICY["input_tokens"]), (4096, 8192))
        self.assertEqual(POLICY["model"], "gpt-oss-120b")

    def test_policy_requires_price_budget_and_output_cap(self):
        for field in ("price", "budget", "max_output"):
            with self.subTest(field=field), self.assertRaises(ProfileError):
                policy_from_profile("t", {k: v for k, v in CAMPAIGN.items() if k != field}, "2.12.0")

    def test_request_spacing_follows_profile_rpm(self):
        policy = policy_from_profile("t", dict(CAMPAIGN, limits={"rpm": 6}), "2.12.0")
        self.call(self.budget(policy=policy), "probe")
        start = self.now
        self.call(self.budget(policy=policy), "second")
        self.assertGreaterEqual(self.now - start, 10.0)
        self.assertLess(self.now - start, 11.0)

    def test_profile_without_limits_does_not_pace(self):
        policy = policy_from_profile("t", {k: v for k, v in CAMPAIGN.items() if k != "limits"}, "2.12.0")
        self.call(self.budget(policy=policy), "probe")
        self.call(self.budget(policy=policy), "second")
        self.assertEqual(self.now, 1000.0)

    def test_changed_policy_pauses_existing_campaign(self):
        self.call(self.budget(), "probe")
        other = policy_from_profile("t", dict(CAMPAIGN, model="other-model"), "2.12.0")
        with self.assertRaises(Paused):
            self.budget(policy=other)

    def test_live_transport_skips_pricing_check_without_pricing_url(self):
        import _llm_adapter
        calls = []
        def fake(url, payload=None, key=None):
            calls.append((url, key))
            return {"choices": []}, {}
        with patch.object(_llm_adapter, "http_json", fake),                 patch.dict(os.environ, {"CEREBRAS_API_KEY": "csk-test"}):
            send = _llm_adapter.live_transport(POLICY)
            self.assertEqual(calls, [])
            send({"model": "gpt-oss-120b"})
        self.assertEqual(calls, [("https://api.cerebras.ai/v1/chat/completions", "csk-test")])

    def test_live_transport_needs_the_profile_key(self):
        import _llm_adapter
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(Paused):
            _llm_adapter.live_transport(POLICY)

    def test_campaign_policy_comes_from_the_campaign_profile(self):
        import llm_scan
        config = self.root / "config.toml"
        config.write_text(chr(10).join([
            '[llm.use]', 'campaign = "c"', '[llm.profiles.c]', 'kind = "api"',
            'protocol = "openai"', 'base_url = "https://api.example.test/v1"',
            'model = "m-1"', 'key_env = "EXAMPLE_KEY"', 'max_output = 2048',
            'price = { input_usd_per_mtok = 0.1, output_usd_per_mtok = 0.2 }',
            'budget = { total_usd = 1, step_usd = 0.25 }', '']), encoding="utf-8")
        policy = llm_scan.campaign_policy({"AGENT_GUARD_CONFIG": str(config)})
        self.assertEqual((policy["model"], policy["base_url"], policy["key_env"]),
                         ("m-1", "https://api.example.test/v1", "EXAMPLE_KEY"))
        self.assertEqual((policy["input_nusd"], policy["output_nusd"]), (100, 200))

    def test_campaign_without_profile_is_paused(self):
        import llm_scan
        with self.assertRaises(Paused):
            llm_scan.campaign_policy({"AGENT_GUARD_NO_USER_CONFIG": "1"})


class FakeBudget:
    """Stands in for Budget so scan() can be driven through its verdict paths."""
    observed = {"call": {"state": "done"}}
    transport = None
    stopped = ""

    def __init__(self, *args, **kwargs):
        self.observed = dict(type(self).observed)

    def summary(self):
        return {"prompts": [], "requests_total": 1}


def clean_report(**metadata):
    return {"risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE",
                                "max_issue_severity": "NONE"},
            "issues": [],
            "metadata": {"llm_requested": True, "llm_available": True,
                         "llm_calls_attempted": 4, "llm_calls_succeeded": 4, **metadata},
            "execution_successful": True,
            "analysis_completeness": {"is_complete": True, "execution_successful": True,
                                      "coverage_percent": 100.0,
                                      "entirely_uninspected_files": 0,
                                      "partially_inspected_files": 0,
                                      "ledger_exceptions": []}}


class ScanFailureTests(unittest.TestCase):
    """llm_scan.scan returns a verdict code; every failure path must be 2, never 0."""

    def setUp(self):
        import llm_scan
        self.llm_scan = llm_scan
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = root / "fixture"
        target.mkdir()
        (target / "SKILL.md").write_text("Say hello")
        self.campaign = root / "campaign"
        self.session = new_session(target, self.campaign, POLICY)

    def _scan(self, app, preview=False, observed=None):
        import types
        fake_cli = types.ModuleType("skillspector.cli")
        fake_cli.app = app
        fake_pkg = types.ModuleType("skillspector")
        fake_pkg.cli = fake_cli
        budget = type("B", (FakeBudget,), {"observed": FakeBudget.observed
                                           if observed is None else observed})
        with patch.object(self.llm_scan, "Budget", budget),              patch("_llm_adapter.install"),              patch.dict(sys.modules, {"skillspector": fake_pkg, "skillspector.cli": fake_cli}),              patch.dict(os.environ, {}),              contextlib.redirect_stdout(io.StringIO()):
            return self.llm_scan.scan(self.session, self.campaign, preview, POLICY)

    def _app_writing(self, report, exit_code=None, returns=None):
        def app(args, standalone_mode):
            if report is not None:
                Path(args[args.index("--output") + 1]).write_text(
                    json.dumps(report), encoding="utf-8")
            if exit_code is not None:
                raise SystemExit(exit_code)
            return returns   # click returns typer.Exit(code=N) in non-standalone mode
        return app

    def test_control_complete_clean_run_is_safe(self):
        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(self._app_writing(clean_report())), 0)

    def test_returned_exit_code_of_the_scanner_is_never_lost(self):
        # standalone_mode=False returns the code of typer.Exit instead of raising.
        with patch("_llm_adapter.live_transport"):
            for returned in (None, 0):
                self.assertEqual(self._scan(self._app_writing(clean_report(), returns=returned)), 0)
            self.assertNotEqual(self._scan(self._app_writing(clean_report(), returns=1)), 0)
            for returned in (2, 3, -1, True, "0", "1", 1.0, [0]):
                self.assertEqual(self._scan(self._app_writing(clean_report(), returns=returned)),
                                 2, returned)
            # SystemExit codes that are not 0/None get the same treatment.
            self.assertEqual(self._scan(self._app_writing(clean_report(), exit_code="boom")), 2)

    def test_scanner_without_report_is_no_verdict(self):
        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(self._app_writing(None)), 2)
            self.assertEqual(self._scan(self._app_writing(None, exit_code=1)), 2)
            self.assertEqual(self._scan(self._app_writing(None, exit_code=0)), 2)

    def test_unreadable_report_is_no_verdict(self):
        def app(args, standalone_mode):
            Path(args[args.index("--output") + 1]).write_text("{broken", encoding="utf-8")

        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(app), 2)

    def test_incomplete_llm_run_is_no_verdict(self):
        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(self._app_writing(
                clean_report(llm_calls_succeeded=3))), 2)
            self.assertEqual(self._scan(self._app_writing(
                clean_report(llm_available=False, llm_error="rate_limit_exceeded"))), 2)

    def test_no_observed_call_or_a_pending_one_is_no_verdict(self):
        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(self._app_writing(clean_report()), observed={}), 2)
            self.assertEqual(self._scan(self._app_writing(clean_report()),
                                        observed={"call": {"state": "pending"}}), 2)

    def test_preview_is_never_a_verdict(self):
        self.assertEqual(self._scan(self._app_writing(clean_report()), preview=True), 2)

    def test_changed_snapshot_is_no_verdict(self):
        def app(args, standalone_mode):
            (self.session / "snapshot" / "SKILL.md").write_text("changed during the scan")
            self._app_writing(clean_report())(args, standalone_mode)

        with patch("_llm_adapter.live_transport"):
            self.assertEqual(self._scan(app), 2)

    def test_scanner_crash_is_not_swallowed_into_a_verdict(self):
        def app(args, standalone_mode):
            raise RuntimeError("scanner crashed")

        with patch("_llm_adapter.live_transport"), self.assertRaises(RuntimeError):
            self._scan(app)

    def test_exit_of_the_campaign_wrapper_with_a_failed_child_is_not_zero(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("python", 700)

        with patch.object(self.llm_scan.importlib.metadata, "version",
                          side_effect=self.llm_scan.importlib.metadata.PackageNotFoundError),              patch.object(sys, "argv", ["llm_scan.py", "run", str(self.session)]),              patch("_skillspector.skillspector_python", return_value="python"),              patch.dict(os.environ, {}):
            # A hung child ends the run with an exception, which the entry point maps to 2.
            with patch("_skillspector.run_bounded", timeout), self.assertRaises(subprocess.TimeoutExpired):
                self.llm_scan.main()
            # A child that fails keeps its failing exit code.
            failed = subprocess.CompletedProcess([], 2, "", "boom")
            with patch("_skillspector.run_bounded", return_value=failed),                  contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.llm_scan.main(), 2)
        # No tool Python to re-exec into: paused, not run.
        with patch.object(self.llm_scan.importlib.metadata, "version",
                          side_effect=self.llm_scan.importlib.metadata.PackageNotFoundError),              patch.object(sys, "argv", ["llm_scan.py", "run", str(self.session)]),              patch("_skillspector.skillspector_python", return_value=None),              patch.dict(os.environ, {}), self.assertRaises(Paused):
            self.llm_scan.main()


if __name__ == "__main__":
    unittest.main()
