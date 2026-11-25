"""Egress capture of the MCP sandbox: evaluation of recorded tcpdump output.

The sample lines were recorded from the pinned capture image (Alpine 3.24,
tcpdump 4.99.6) with a target that fetched from pypi.org, looked up an unknown
name, connected to a bare IP and sent a ping. No test here touches Docker.
"""
import http.client
import importlib
import io
import os
import shutil
import platform
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest.mock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

eg = importlib.import_module("_egress")

LOCAL = "172.17.0.2"
HEADER = [
    "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode",
    "listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes",
]
FOOTER = ["18 packets captured", "18 packets received by filter",
          "0 packets dropped by kernel"]
PYPI = [
    "17:35:12.642526 IP 172.17.0.2.42175 > 192.168.65.7.53: 31002+ A? pypi.org. (26)",
    "17:35:12.642664 IP 172.17.0.2.42175 > 192.168.65.7.53: 31486+ AAAA? pypi.org. (26)",
    "17:35:12.648810 IP 192.168.65.7.53 > 172.17.0.2.42175: 31002 4/0/0 A 151.101.192.223, "
    "A 151.101.0.223, A 151.101.64.223, A 151.101.128.223 (122)",
    "17:35:12.649474 IP 192.168.65.7.53 > 172.17.0.2.42175: 31486 4/0/0 AAAA 2a04:4e42:400::223, "
    "AAAA 2a04:4e42:600::223, AAAA 2a04:4e42::223, AAAA 2a04:4e42:200::223 (170)",
    "17:35:12.652506 IP 172.17.0.2.35450 > 151.101.192.223.443: Flags [S], seq 200491489, "
    "win 64240, options [mss 1460,sackOK,TS val 2194639165 ecr 0,nop,wscale 10], length 0",
]
EXFIL_DNS = [
    "17:35:18.258128 IP 172.17.0.2.50928 > 192.168.65.7.53: 41011+ A? evil-exfil-test.example.com. (45)",
    "17:35:18.258252 IP 172.17.0.2.50928 > 192.168.65.7.53: 41012+ AAAA? evil-exfil-test.example.com. (45)",
    "17:35:18.329911 IP 192.168.65.7.53 > 172.17.0.2.50928: 41012 NXDomain 0/0/0 (45)",
    "17:35:18.354120 IP 192.168.65.7.53 > 172.17.0.2.50928: 41011 NXDomain 0/0/0 (45)",
]
BARE_IP = [
    "17:35:18.358137 IP 172.17.0.2.44712 > 1.1.1.1.80: Flags [S], seq 4220694466, win 64240, "
    "options [mss 1460,sackOK,TS val 3105212761 ecr 0,nop,wscale 10], length 0",
]
RESOLVED_ELSEWHERE = [
    "17:35:18.529465 IP 172.17.0.2.47443 > 192.168.65.7.53: 33775+ A? one.one.one.one. (33)",
    "17:35:18.545734 IP 192.168.65.7.53 > 172.17.0.2.47443: 33775 2/0/0 A 1.0.0.1, A 1.1.1.1 (95)",
    "17:35:18.547476 IP 172.17.0.2.53402 > 1.0.0.1.443: Flags [S], seq 2491493689, win 64240, "
    "options [mss 1460,sackOK,TS val 346997552 ecr 0,nop,wscale 10], length 0",
]
PING = [
    "17:35:18.685578 IP 172.17.0.2 > 9.9.9.9: ICMP echo request, id 14, seq 0, length 64",
    "17:35:18.700630 IP 9.9.9.9 > 172.17.0.2: ICMP echo reply, id 14, seq 0, length 64",
]


def analyse(packets, allow=eg.DEFAULT_ALLOW, header=HEADER, footer=FOOTER):
    return eg.analyse(header + packets + footer, LOCAL, eg.parse_allow(allow))


class AllowListTests(unittest.TestCase):
    def test_default_port_is_https(self):
        self.assertEqual(eg.parse_allow(["Example.org", "10.0.0.5:8080"]),
                         {("example.org", 443), ("10.0.0.5", 8080)})

    def test_registries_are_allowed_by_default(self):
        self.assertIn(("pypi.org", 443), eg.parse_allow(eg.DEFAULT_ALLOW))
        self.assertIn(("registry.npmjs.org", 443), eg.parse_allow(eg.DEFAULT_ALLOW))

    def test_invalid_entries_are_refused(self):
        for bad in ["", "exa mple.org", "example.org:0", "example.org:70000",
                    "example.org:http", "*.example.org", "https://example.org"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                eg.parse_allow([bad])


class AnalysisTests(unittest.TestCase):
    def test_registry_download_is_clean(self):
        report = analyse(PYPI)
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.names, ["pypi.org"])

    def test_lookup_of_an_unknown_name_is_a_finding_even_without_answer(self):
        report = analyse(EXFIL_DNS)
        self.assertEqual(report.findings,
                         ["DNS lookup of a host that is not allowed: evil-exfil-test.example.com"])

    def test_dns_query_to_a_public_resolver_is_a_finding(self):
        with patch.dict(os.environ):
            os.environ.pop("AGENT_GUARD_DNS_RESOLVERS", None)
            self._dns_query_to_a_public_resolver_is_a_finding()

    def _dns_query_to_a_public_resolver_is_a_finding(self):
        report = analyse(["17:35:18.258128 IP 172.17.0.2.50928 > 1.1.1.1.53: 41011+ A? pypi.org. (45)"])
        self.assertEqual(report.findings, ["DNS traffic to a public address: 1.1.1.1 (not listed in AGENT_GUARD_DNS_RESOLVERS)"])

    def test_configured_resolver_address_counts_as_the_resolver(self):
        packets = ["17:35:18.258128 IP 172.17.0.2.50928 > 1.1.1.1.53: 41011+ A? pypi.org. (45)"]
        with patch.dict(os.environ, {"AGENT_GUARD_DNS_RESOLVERS": "1.1.1.1, ::1"}):
            self.assertEqual(analyse(packets).findings, [])
        with patch.dict(os.environ, {"AGENT_GUARD_DNS_RESOLVERS": "9.9.9.9"}):
            self.assertEqual(analyse(packets).findings,
                             ["DNS traffic to a public address: 1.1.1.1 (not listed in AGENT_GUARD_DNS_RESOLVERS)"])
        env = {k: v for k, v in os.environ.items() if k != "AGENT_GUARD_DNS_RESOLVERS"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(analyse(packets).findings,
                             ["DNS traffic to a public address: 1.1.1.1 (not listed in AGENT_GUARD_DNS_RESOLVERS)"])

    def test_invalid_resolver_entries_are_ignored_with_a_warning(self):
        err = io.StringIO()
        with patch.dict(os.environ, {"AGENT_GUARD_DNS_RESOLVERS": "nonsense,1.1.1.1"}), \
                unittest.mock.patch.object(sys, "stderr", err):
            self.assertEqual(eg.dns_resolvers(), {"1.1.1.1"})
        self.assertIn("nonsense", err.getvalue())

    def test_tcp_syn_to_port_53_on_a_public_address_is_a_finding(self):
        with patch.dict(os.environ):
            os.environ.pop("AGENT_GUARD_DNS_RESOLVERS", None)
            report = analyse(["17:35:18.358137 IP 172.17.0.2.44712 > 8.8.8.8.53: Flags [S], "
                              "seq 1, win 64240, length 0"])
        self.assertEqual(report.findings, ["DNS traffic to a public address: 8.8.8.8 (not listed in AGENT_GUARD_DNS_RESOLVERS)"])

    def test_tcp_to_port_53_of_a_configured_resolver_is_still_a_finding(self):
        # The configured resolver is exempt for UDP queries whose name is checked;
        # DNS over TCP is not parsed, so it must not slip through.
        packets = [
            "17:35:18.358137 IP 172.17.0.2.44712 > 1.1.1.1.53: Flags [S], seq 1, "
            "win 64240, length 0",
            "17:35:18.358999 IP 172.17.0.2.44712 > 1.1.1.1.53: Flags [P.], seq 1:40, "
            "ack 1, win 502, length 39",
        ]
        with patch.dict(os.environ, {"AGENT_GUARD_DNS_RESOLVERS": "1.1.1.1"}):
            report = analyse(packets)
        self.assertEqual(report.findings,
                         ["TCP traffic to port 53 of a configured resolver: 1.1.1.1"])
        # a UDP query to the same resolver stays exempt, its name is still judged
        with patch.dict(os.environ, {"AGENT_GUARD_DNS_RESOLVERS": "1.1.1.1"}):
            report = analyse(["17:35:18.258128 IP 172.17.0.2.50928 > 1.1.1.1.53: "
                              "41011+ A? evil.example.com. (45)"])
        self.assertEqual(report.findings,
                         ["DNS lookup of a host that is not allowed: evil.example.com"])

    def test_dns_to_the_private_sandbox_resolver_is_fine(self):
        self.assertEqual(analyse(PYPI[:2]).findings, [])

    def test_private_address_helper(self):
        for address in ["127.0.0.11", "10.0.0.2", "192.168.65.7", "172.17.0.1", "fd00::1"]:
            self.assertTrue(eg.private_address(address), address)
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "not-an-address"]:
            self.assertFalse(eg.private_address(address), address)

    def test_connection_to_a_bare_ip_is_a_finding(self):
        report = analyse(BARE_IP)
        self.assertEqual(report.findings,
                         ["TCP connection to 1.1.1.1:80 (no DNS lookup)"])

    def test_connection_to_an_address_of_an_unlisted_name_is_a_finding(self):
        report = analyse(RESOLVED_ELSEWHERE)
        self.assertIn("TCP connection to 1.0.0.1:443 (one.one.one.one)", report.findings)
        self.assertIn("DNS lookup of a host that is not allowed: one.one.one.one",
                      report.findings)

    def test_allowed_name_on_another_port_is_a_finding(self):
        lines = PYPI[:3] + [PYPI[4].replace("151.101.192.223.443", "151.101.192.223.22")]
        report = analyse(lines)
        self.assertEqual(report.findings, ["TCP connection to 151.101.192.223:22 (pypi.org)"])

    def test_extra_allowed_host_is_honoured(self):
        report = analyse(RESOLVED_ELSEWHERE, allow=[*eg.DEFAULT_ALLOW, "one.one.one.one"])
        self.assertEqual(report.findings, [])
        report = analyse(BARE_IP, allow=["1.1.1.1:80"])
        self.assertEqual(report.findings, [])

    def test_outgoing_ping_is_a_finding_and_the_reply_is_ignored(self):
        self.assertEqual(analyse(PING).findings, ["ICMP to 9.9.9.9 (echo request)"])

    def test_other_outgoing_udp_is_a_finding(self):
        line = "17:35:19.000001 IP 172.17.0.2.40000 > 203.0.113.9.4444: UDP, length 32"
        self.assertEqual(analyse([line]).findings, ["UDP to 203.0.113.9:4444 (no DNS lookup)"])

    def test_ipv6_connection_to_an_allowed_name(self):
        lines = PYPI[:4] + [
            "17:35:12.652506 IP6 fd00::2.35450 > 2a04:4e42:400::223.443: Flags [S], seq 1, "
            "win 64240, length 0"]
        report = eg.analyse(HEADER + lines + FOOTER, {LOCAL, "fd00::2"},
                            eg.parse_allow(eg.DEFAULT_ALLOW))
        self.assertEqual(report.findings, [])

    def test_unrecognised_outgoing_packet_is_a_finding(self):
        line = "17:35:19.000002 IP 172.17.0.2 > 203.0.113.9: GRE, length 40"
        findings = analyse([line]).findings
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].startswith("unrecognised traffic:"), findings)

    def test_findings_are_deduplicated_in_order(self):
        report = analyse(BARE_IP + BARE_IP + PING)
        self.assertEqual(report.findings, ["TCP connection to 1.1.1.1:80 (no DNS lookup)",
                                           "ICMP to 9.9.9.9 (echo request)"])

    def test_capture_that_never_started_is_incomplete(self):
        report = analyse(PYPI, header=[])
        self.assertFalse(report.complete)
        self.assertIn("did not start", report.problem)

    def test_dropped_packets_make_the_capture_incomplete(self):
        report = analyse(PYPI, footer=["5 packets captured", "9 packets received by filter",
                                       "4 packets dropped by kernel"])
        self.assertFalse(report.complete)
        self.assertIn("dropped", report.problem)

    def test_missing_summary_is_incomplete(self):
        report = analyse(PYPI, footer=[])
        self.assertFalse(report.complete)
        self.assertIn("summary", report.problem)


class VerdictTests(unittest.TestCase):
    def verdict(self, report):
        out = io.StringIO()
        with redirect_stdout(out):
            code = eg.verdict(report)
        return code, out.getvalue()

    def test_clean_capture_passes(self):
        code, out = self.verdict(analyse(PYPI))
        self.assertEqual(code, 0)
        self.assertIn("pypi.org", out)

    def test_findings_block(self):
        code, out = self.verdict(analyse(EXFIL_DNS + BARE_IP))
        self.assertEqual(code, 1)
        self.assertIn("[BLOCK]", out)
        self.assertIn("evil-exfil-test.example.com", out)
        self.assertIn("--allow-host", out)

    def test_incomplete_capture_has_no_verdict(self):
        code, out = self.verdict(analyse(PYPI, header=[]))
        self.assertEqual(code, 2)
        self.assertIn("NO VERDICT", out)


class CaptureLifecycleTests(unittest.TestCase):
    """Docker argv of the capture container; Docker itself is faked."""

    def test_capture_container_is_minimal_and_pinned(self):
        argv = eg.capture_run_argv("agent-guard-net-x", "img:tag")
        joined = " ".join(argv)
        self.assertEqual(argv[:3], ["docker", "run", "-d"])
        self.assertEqual(eg.NO_CAPABILITIES.partition("=")[2], "ALL")
        self.assertIn(eg.NO_CAPABILITIES, argv)
        self.assertIn("--cap-add NET_RAW", joined)
        self.assertIn("--read-only", joined)
        self.assertIn("no-new-privileges", joined)
        self.assertIn("--network bridge", joined)
        self.assertNotIn("-v", argv)
        self.assertIn(eg.CAPTURE_FILTER, argv)
        self.assertIn("@sha256:", eg.CAPTURE_DOCKERFILE)
        self.assertRegex(eg.CAPTURE_DOCKERFILE, r"tcpdump=\d")

    def test_image_tag_follows_the_dockerfile(self):
        self.assertTrue(eg.capture_image().startswith("agent-guard-net-capture:"))
        with patch.object(eg, "CAPTURE_DOCKERFILE", eg.CAPTURE_DOCKERFILE + "# x\n"):
            changed = eg.capture_image()
        self.assertNotEqual(changed, eg.capture_image())

    def test_start_waits_for_listening_and_reads_the_address(self):
        calls = []
        logs = iter(["", HEADER[1]])

        def fake(argv, **kw):
            calls.append(argv)
            if argv[1] == "logs":
                return subprocess.CompletedProcess(argv, 0, "", next(logs))
            if argv[1] == "inspect":
                # Docker 29 renders an unset IPv6 address as "invalid IP".
                return subprocess.CompletedProcess(argv, 0, LOCAL + " invalid IP \n", "")
            return subprocess.CompletedProcess(argv, 0, "abc\n", "")

        with patch.object(eg.subprocess, "run", side_effect=fake), \
             patch.object(eg, "ensure_capture_image", return_value="img"), \
             patch.object(eg.time, "sleep"):
            cap = eg.Capture.start()
        self.assertTrue(cap.name.startswith("agent-guard-net-"))
        self.assertEqual(cap.local_ips, [LOCAL])
        self.assertEqual([c[1] for c in calls], ["run", "logs", "logs", "inspect"])

    def test_start_failure_removes_the_container(self):
        calls = []

        def fake(argv, **kw):
            calls.append(argv)
            if argv[1] == "logs":
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, "abc\n", "")

        with patch.object(eg.subprocess, "run", side_effect=fake), \
             patch.object(eg, "ensure_capture_image", return_value="img"), \
             patch.object(eg.time, "sleep"), patch.object(eg, "START_TIMEOUT", 0.5), \
             patch.object(eg.time, "monotonic", side_effect=[0, 0.1, 0.2, 1.0, 2.0]), \
             self.assertRaises(eg.CaptureError):
            eg.Capture.start()
        self.assertEqual(calls[-1][:3], ["docker", "rm", "--force"])

    def test_finish_stops_reads_and_removes(self):
        calls = []

        def fake(argv, **kw):
            calls.append(argv)
            if argv[1] == "logs":
                return subprocess.CompletedProcess(argv, 0, "\n".join(PYPI),
                                                   "\n".join(HEADER + FOOTER))
            return subprocess.CompletedProcess(argv, 0, "", "")

        cap = eg.Capture("agent-guard-net-x", LOCAL)
        with patch.object(eg.subprocess, "run", side_effect=fake):
            report = cap.finish(eg.parse_allow(eg.DEFAULT_ALLOW))
        self.assertEqual([c[1] for c in calls], ["stop", "logs", "rm"])
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])


class SandboxIntegrationTests(unittest.TestCase):
    """run_sandbox() wires the capture around the Cisco run. Docker is faked."""

    def setUp(self):
        self.scan_mcp = importlib.import_module("scan_mcp")
        sm = self.scan_mcp
        self.capture = unittest.mock.MagicMock(name="capture")
        self.capture.name = "agent-guard-net-test"
        self.capture.finish.return_value = eg.analyse(HEADER + PYPI + FOOTER, LOCAL,
                                                      eg.parse_allow(eg.DEFAULT_ALLOW))
        self.docker_reply = subprocess.CompletedProcess(["docker"], 0, "true\n", "")
        self.docker_calls = []
        real_run = subprocess.run
        real_which = shutil.which

        def run_or_fake_docker(argv, *args, **kwargs):
            if argv and argv[0] == "docker":
                self.docker_calls.append((list(argv), dict(kwargs)))
                if isinstance(self.docker_reply, BaseException):
                    raise self.docker_reply
                return self.docker_reply
            return real_run(argv, *args, **kwargs)

        self.patches = [
            patch.object(sm, "need_mcp_scanner"),
            patch.object(sm, "build_sandbox_image", return_value="sandbox:tag"),
            patch.object(sm.shutil, "which", side_effect=lambda name: "docker" if name == "docker" else real_which(name)),
            patch.object(sm, "cisco_llm_problem", return_value=None),
            patch.object(sm, "cisco_env", return_value={}),
            patch.object(sm, "cisco_command", return_value=["mcp-scanner"]),
            patch.object(sm.subprocess, "run", side_effect=run_or_fake_docker),
        ]
        for p in self.patches:
            p.start()
        # Only the network (registry JSON) is replaced; launch_runtime_problem and
        # runtime_parity_warnings run for real. Full Docker checks live in test_sandbox_image.py.
        self.http = patch.object(
            sm, "http_json",
            return_value={"info": {}, "dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}},
        )
        self.http_mock = self.http.start()
        self.patches.append(self.http)
        self.start = patch.object(sm._egress.Capture, "start", return_value=self.capture)
        self.start_mock = self.start.start()
        self.cisco = patch.object(sm, "run_cisco", return_value=0)
        self.cisco_mock = self.cisco.start()

    def tearDown(self):
        self.cisco.stop()
        self.start.stop()
        for p in self.patches:
            p.stop()

    def sandbox(self, command=None, **kw):
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.scan_mcp.run_sandbox(command or ["uvx", "some-mcp"], **kw)
        return code, out.getvalue()

    def docker_args(self):
        argv = self.cisco_mock.call_args.args[0]
        return [a.split("=", 1)[1] for a in argv if a.startswith("--stdio-arg=")]

    def test_runtime_mismatch_gives_no_verdict_and_no_target_run(self):
        self.http_mock.return_value = {"info": {"version": "1.0", "requires_python": ">=3.8,<3.12"}}
        self.docker_reply = subprocess.CompletedProcess(["docker"], 0, "false\n", "")
        code, out = self.sandbox()
        self.assertEqual(code, 2)
        self.assertIn("NO VERDICT -- some-mcp needs python >=3.8,<3.12", out)
        self.assertIn(self.scan_mcp.SANDBOX_PYTHON, out)
        self.cisco_mock.assert_not_called()
        self.start_mock.assert_not_called()

    def test_parity_warning_is_printed_and_keeps_the_verdict(self):
        with patch.object(self.scan_mcp, "SANDBOX_NODE", "1.0.0"):
            code, out = self.sandbox(command=["npx", "-y", "some-mcp@1.0.0"])
        self.assertEqual(code, 0)
        self.assertIn("[WARN]", out)
        self.assertIn("node 1.0.0", out)
        if shutil.which("node"):
            self.assertIn("this machine runs node ", out)
        else:
            self.assertIn("node not found on this machine", out)

    def test_runtime_check_errors_fail_closed_with_no_verdict(self):
        # HTTPException (not a subclass of OSError) and malformed JSON shapes for
        # both PyPI and npm must produce exit 2 (NO VERDICT), never exit 0 or 1.
        cases = (
            (["uvx", "some-mcp"], http.client.RemoteDisconnected("closed")),
            (["uvx", "some-mcp"], ["not-a-dict"]),
            (["uvx", "some-mcp"], {}),
            (["uvx", "some-mcp"], {"info": []}),
            (["uvx", "some-mcp"], {"info": {"requires_python": 314}}),
            (["npx", "-y", "some-mcp"], ["not-a-dict"]),
            (["npx", "-y", "some-mcp"], {"versions": {}}),
            (["npx", "-y", "some-mcp"], {"dist-tags": [], "versions": {}}),
            (["npx", "-y", "some-mcp@1.0.0"], {"dist-tags": {"latest": "1.0.0"}}),
            (["npx", "-y", "some-mcp@1.0.0"], {"versions": []}),
            (["npx", "-y", "some-mcp@1.0.0"], {"versions": {"1.0.0": []}}),
            (["npx", "-y", "some-mcp@1.0.0"], {"versions": {"1.0.0": {"engines": []}}}),
            (["npx", "-y", "some-mcp@1.0.0"], {"versions": {"1.0.0": {"engines": {"node": 26}}}}),
        )
        for cmd, bad_net in cases:
            with self.subTest(cmd=cmd, bad_net=bad_net):
                if isinstance(bad_net, Exception):
                    self.http_mock.side_effect = bad_net
                else:
                    self.http_mock.side_effect = None
                    self.http_mock.return_value = bad_net
                code, out = self.sandbox(command=cmd)
                self.assertEqual(code, 2, out)
                self.assertIn("NO VERDICT", out)
                self.assertIn("from the registry", out)
                self.cisco_mock.assert_not_called()
                self.start_mock.assert_not_called()

    def test_uncheckable_runtime_in_image_gives_no_verdict_and_no_target_run(self):
        self.http_mock.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"engines": {"node": ">=24"}}},
        }
        replies = (
            subprocess.CompletedProcess(["docker"], 125, "true\n", "daemon error"),
            subprocess.CompletedProcess(["docker"], 0, "error\n", ""),
            subprocess.TimeoutExpired(["docker"], 120),
            OSError("docker vanished"),
        )
        for reply in replies:
            with self.subTest(reply=reply):
                self.docker_reply = reply
                code, out = self.sandbox(command=["npx", "-y", "some-mcp@1.0.0"])
                self.assertEqual(code, 2, out)
                self.assertIn("NO VERDICT", out)
                self.cisco_mock.assert_not_called()
                self.start_mock.assert_not_called()

    def test_image_satisfies_passes_spec_on_stdin_with_hardened_container(self):
        self.http_mock.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"engines": {"node": "--eval=console.log(true)"}}},
        }
        self.docker_reply = subprocess.CompletedProcess(["docker"], 0, "error\n", "")
        code, _out = self.sandbox(command=["npx", "-y", "some-mcp@1.0.0"])
        self.assertEqual(code, 2)
        run_calls = [(argv, kw) for argv, kw in self.docker_calls if argv[:2] == ["docker", "run"]]
        self.assertEqual(len(run_calls), 1)
        argv, kw = run_calls[0]
        self.assertNotIn("--eval=console.log(true)", argv)
        self.assertEqual(kw.get("input"), "--eval=console.log(true)")
        for flag in ("-i", "--read-only", "no-new-privileges", "--cap-drop=ALL", "--pids-limit"):
            self.assertIn(flag, argv)

    def test_image_satisfies_timeout_or_oserror_returns_none(self):
        sm = self.scan_mcp
        for exc in (subprocess.TimeoutExpired(["docker"], 120), OSError("docker vanished")):
            with self.subTest(exc=type(exc).__name__), \
                    patch.object(sm.subprocess, "run", side_effect=exc):
                self.assertIsNone(sm.image_satisfies("sandbox:tag", "node", ">=24"))
        self.assertIsNone(sm.image_satisfies("sandbox:tag", "ruby", ">=3"))
        self.assertIsNone(sm.image_satisfies("sandbox:tag", "node", "   "))
        self.assertIsNone(sm.image_satisfies("sandbox:tag", "python", "   "))

    def test_sandbox_environment_makes_npm_strict_about_engines(self):
        self.sandbox()
        args = self.docker_args()
        self.assertIn("NPM_CONFIG_ENGINE_STRICT=true", args)

    def test_target_joins_the_capture_namespace(self):
        code, _ = self.sandbox()
        self.assertEqual(code, 0)
        args = self.docker_args()
        i = args.index("--network")
        self.assertEqual(args[i + 1], "container:agent-guard-net-test")
        self.assertNotIn("bridge", args)
        self.assertIn("sandbox:tag", args)
        self.assertIn("UV_PYTHON_DOWNLOADS=never", args)
        allow = self.capture.finish.call_args.args[0]
        self.assertIn(("pypi.org", 443), allow)

    def test_egress_findings_block_a_clean_cisco_run(self):
        self.capture.finish.return_value = eg.analyse(
            HEADER + EXFIL_DNS + FOOTER, LOCAL, eg.parse_allow(eg.DEFAULT_ALLOW))
        code, out = self.sandbox()
        self.assertEqual(code, 1)
        self.assertIn("evil-exfil-test.example.com", out)

    def test_incomplete_capture_has_no_verdict(self):
        self.capture.finish.return_value = eg.analyse(
            PYPI + FOOTER, LOCAL, eg.parse_allow(eg.DEFAULT_ALLOW))
        self.assertEqual(self.sandbox()[0], 2)

    def test_cisco_block_is_kept(self):
        self.cisco_mock.return_value = 1
        self.assertEqual(self.sandbox()[0], 1)

    def test_extra_hosts_from_option_and_environment(self):
        with patch.dict(os.environ, {"AGENT_GUARD_SANDBOX_ALLOW": "api.example.com, 10.0.0.5:8080"}):
            self.sandbox(allow_hosts=["other.example.org:8443"])
        allow = self.capture.finish.call_args.args[0]
        for entry in [("api.example.com", 443), ("10.0.0.5", 8080), ("other.example.org", 8443)]:
            self.assertIn(entry, allow)

    def test_invalid_extra_host_stops_before_anything_runs(self):
        with self.assertRaises(SystemExit):
            self.sandbox(allow_hosts=["https://x"])
        self.start_mock.assert_not_called()
        self.cisco_mock.assert_not_called()

    def test_no_network_skips_the_capture_and_online_runtime_lookup(self):
        self.http_mock.side_effect = OSError("offline")
        code, out = self.sandbox(network=False)
        self.assertEqual(code, 0, out)
        self.http_mock.assert_not_called()
        self.start_mock.assert_not_called()
        args = self.docker_args()
        self.assertEqual(args[args.index("--network") + 1], "none")

    def test_capture_start_failure_gives_no_verdict_and_no_target_run(self):
        self.start_mock.side_effect = eg.CaptureError("no tcpdump")
        code, out = self.sandbox()
        self.assertEqual(code, 2)
        self.assertIn("no tcpdump", out)
        self.cisco_mock.assert_not_called()

    def test_capture_is_removed_when_the_scan_crashes(self):
        self.cisco_mock.side_effect = RuntimeError("handshake")
        with self.assertRaises(RuntimeError):
            self.sandbox()
        self.capture.remove.assert_called_once()
        self.capture.finish.assert_not_called()

    def test_capture_finish_docker_failure_gives_no_verdict_not_block(self):
        for exc in (OSError("docker down"), subprocess.TimeoutExpired(["docker"], 60)):
            with self.subTest(exc=type(exc).__name__):
                self.capture.finish.side_effect = exc
                code, out = self.sandbox()
                self.assertEqual(code, 2, out)
                self.assertIn("NO VERDICT", out)

    def test_capture_remove_failure_still_propagates_scan_error(self):
        self.cisco_mock.side_effect = RuntimeError("handshake")
        self.capture.remove.side_effect = OSError("docker vanished")
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(RuntimeError):
            self.sandbox()
        self.assertIn("could not remove capture container", err.getvalue())


class SandboxImageTests(unittest.TestCase):
    def test_image_does_not_carry_the_scanner_and_is_tagged_by_content(self):
        sm = importlib.import_module("scan_mcp")
        self.assertNotIn("cisco-ai-mcp-scanner", sm.SANDBOX_DOCKERFILE)
        self.assertTrue(sm.sandbox_image().startswith(sm.DOCKER_IMAGE + ":"))


class RuntimeParityTests(unittest.TestCase):
    """The sandbox should run the runtime line this machine runs the server on."""

    def setUp(self):
        self.sm = importlib.import_module("scan_mcp")

    def test_same_node_major_is_quiet(self):
        self.assertIsNone(self.sm.parity_warning("node", "26.13.1", "26.9.0"))

    def test_other_node_major_warns_with_both_versions(self):
        text = self.sm.parity_warning("node", "26.13.1", "24.22.3")
        self.assertIn("26.13.1", text)
        self.assertIn("24.22.3", text)

    def test_python_compares_major_and_minor(self):
        self.assertIsNone(self.sm.parity_warning("python", "3.14.10", "3.14.2"))
        self.assertIn("3.13.18", self.sm.parity_warning("python", "3.14.10", "3.13.18"))

    def test_missing_host_runtime_is_said_not_hidden(self):
        self.assertIn("not found", self.sm.parity_warning("node", "26.13.1", None))

    def test_launcher_picks_the_runtime_it_needs(self):
        with patch.object(self.sm, "SANDBOX_NODE", "1.0.0"):
            warnings = self.sm.runtime_parity_warnings(["npx", "-y", "pkg@1"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("node 1.0.0", warnings[0])
        if shutil.which("node"):
            self.assertIn("this machine runs node ", warnings[0])
        with patch.object(self.sm, "SANDBOX_PYTHON", "3.1.0"):
            py_warnings = self.sm.runtime_parity_warnings(["uvx", "pkg"])
        self.assertEqual(len(py_warnings), 1)
        self.assertIn("python 3.1.0", py_warnings[0])
        if shutil.which("uv"):
            self.assertIn("this machine runs python ", py_warnings[0])
        self.assertEqual(self.sm.runtime_parity_warnings(["docker", "run", "x"]), [])

    def test_host_runtime_version_ignores_failing_subprocess(self):
        failed = subprocess.CompletedProcess(["node", "--version"], 1, "not a version\n", "err")
        with patch.object(self.sm.shutil, "which", return_value="node"), \
                patch.object(self.sm.subprocess, "run", return_value=failed):
            self.assertIsNone(self.sm.host_runtime_version("node"))
        garbage = subprocess.CompletedProcess(["node", "--version"], 0, "garbage output\n", "")
        with patch.object(self.sm.shutil, "which", return_value="node"), \
                patch.object(self.sm.subprocess, "run", return_value=garbage):
            self.assertIsNone(self.sm.host_runtime_version("node"))
        with patch.object(self.sm.shutil, "which", return_value=None):
            self.assertIsNone(self.sm.host_runtime_version("python"))
        with patch.object(self.sm.shutil, "which", return_value="uv"), \
                patch.object(self.sm.subprocess, "run",
                             return_value=subprocess.CompletedProcess(["uv"], 1, "", "err")):
            self.assertIsNone(self.sm.host_runtime_version("python"))
        with patch.object(self.sm.shutil, "which", return_value="uv"), \
                patch.object(self.sm.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess(["uv"], 0, "C:\\py.exe\n", ""),
                    subprocess.CompletedProcess(["C:\\py.exe"], 1, "", "err"),
                ]):
            self.assertIsNone(self.sm.host_runtime_version("python"))
        with patch.object(self.sm.shutil, "which", return_value="uv"), \
                patch.object(self.sm.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess(["uv"], 0, "C:\\py.exe\n", ""),
                    subprocess.CompletedProcess(["C:\\py.exe"], 0, "not-a-version\n", ""),
                ]):
            self.assertIsNone(self.sm.host_runtime_version("python"))
        with patch.object(self.sm.shutil, "which", return_value="uv"), \
                patch.object(self.sm.subprocess, "run",
                             side_effect=subprocess.TimeoutExpired(["uv"], 60)):
            self.assertIsNone(self.sm.host_runtime_version("python"))
        with self.assertRaises(ValueError):
            self.sm.host_runtime_version("ruby")

    def test_host_python_ignores_a_planted_module_in_the_working_directory(self):
        """F2: the version probe must not import platform.py from the current directory."""
        real_run = subprocess.run
        probes = []

        def run(cmd, *args, **kwargs):
            if cmd[0] == "uv":
                return subprocess.CompletedProcess(cmd, 0, sys.executable + "\n", "")
            cwd = kwargs.get("cwd")
            probes.append((cmd, cwd, sorted(os.listdir(cwd)) if cwd else None))
            return real_run(cmd, *args, **kwargs)

        with tempfile.TemporaryDirectory() as work:
            planted = Path(work) / "platform.py"
            planted.write_text('import pathlib\npathlib.Path(__file__).with_suffix(".ran").touch()\n',
                               encoding="utf-8")
            old = os.getcwd()
            os.chdir(work)
            try:
                with patch.object(self.sm.shutil, "which", return_value="uv"), \
                        patch.object(self.sm.subprocess, "run", side_effect=run):
                    version = self.sm.host_runtime_version("python")
            finally:
                os.chdir(old)
            self.assertFalse((Path(work) / "platform.ran").exists())
        self.assertEqual(version, platform.python_version())
        # -I also drops PYTHONPATH and the user site, which the cwd alone does not.
        self.assertEqual([cmd[1] for cmd, _, _ in probes], ["-I"])
        # And the probe starts in an empty directory, not in the caller's one.
        [(_, cwd, listing)] = probes
        self.assertIsNotNone(cwd)
        self.assertNotEqual(os.path.normcase(os.path.abspath(cwd)), os.path.normcase(work))
        self.assertEqual(listing, [])


class CommandLineTests(unittest.TestCase):
    def test_allow_host_and_no_network_reach_the_sandbox(self):
        sm = importlib.import_module("scan_mcp")
        with patch.object(sm, "run_sandbox", return_value=0) as run, \
             patch.object(sys, "argv", ["scan_mcp.py", "sandbox", "--allow-host", "a.example",
                                        "--allow-host", "b.example:8443", "--no-network",
                                        "--", "uvx", "pkg"]), \
             self.assertRaises(SystemExit):
            sm.main()
        run.assert_called_once_with(["uvx", "pkg"], allow_hosts=["a.example", "b.example:8443"],
                                    network=False)


if __name__ == "__main__":
    unittest.main()
