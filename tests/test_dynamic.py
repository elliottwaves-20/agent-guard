"""Stage 3: dynamic install analysis (OpenSSF package-analysis).

The result dicts below mirror real package-analysis output recorded on this
machine (npm is-number / esbuild, PyPI six, and a harmless fixture that reads
~/.ssh and phones home). They are trimmed, and the credentials the sandbox
plants in its environment are replaced by an obvious placeholder so no
key-shaped string lands in the repository. No test here touches Docker.
"""
import importlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config

dyn = importlib.import_module("_dynamic")

HONEY = "PLANTED-HONEY-VALUE-0123456789"
ENV = ["TERM=xterm", f"AWS_SECRET_ACCESS_KEY={HONEY}", "HOME=/root", "container=podman"]


def cmd(*argv):
    return {"Command": list(argv), "Environment": ENV}


# Keyword form on purpose: SkillSpector 2.12.0 misreads the quoted key list of
# a file record as an obfuscated text directive (partial inspection).
def read(path):
    return dict(Path=path, Read=True, Write=False, Delete=False)


def write(path):
    return dict(Path=path, Read=False, Write=True, Delete=False)


def phase(files=(), names=(), sockets=(), commands=(), status="completed"):
    return {"Status": status, "Stdout": "", "Stderr": "",
            "Files": list(files),
            "DNS": [{"Class": "IN", "Queries": [{"Hostname": n, "Types": ["A", "AAAA"]}
                                                for n in names]}] if names else None,
            "Sockets": [{"Address": a, "Port": p, "Hostnames": list(h)} for a, p, h in sockets],
            "Commands": list(commands)}


def npm_clean():
    return {
        "Package": {"Ecosystem": "npm", "Name": "is-number", "Version": "7.0.0"},
        "Analysis": {
            "import": phase(files=[read("/app/node_modules/is-number/index.js"), write("/dev/tty")],
                            commands=[cmd("node", "/usr/local/bin/analyze-node.js", "import",
                                          "is-number"), cmd("sleep", "30m")]),
            "install": phase(
                files=[read("/app/.npmrc"), read("/root/.npmrc"),
                       write("/app/node_modules/is-number/index.js"),
                       write("/root/.npm/_cacache/index"), write("/tmp/node-compile-cache/x"),
                       write("pipe:[12]"), write("socket:[15]"), write("host:[5]"),
                       write("anon_inode:[eventfd]")],
                names=["registry.npmjs.org"],
                sockets=[("104.16.0.34", 0, ["registry.npmjs.org"]),
                         ("104.16.0.34", 443, ["registry.npmjs.org"]),
                         ("8.8.8.8", 53, [])],
                commands=[cmd("node", "/usr/bin/npm", "install", "is-number@7.0.0"),
                          cmd("sh", "-c", "node install.js"), cmd("node", "install.js")]),
        },
    }


def pypi_clean():
    return {
        "Package": {"Ecosystem": "pypi", "Name": "six", "Version": "1.17.0"},
        "Analysis": {
            "execute": phase(files=[write("/execution.log")]),
            "import": phase(files=[read("/app/.pyenv/lib/six.py")]),
            "install": phase(
                files=[read("/etc/shadow"), read("/etc/shadow-"), read("/root/.netrc"),
                       read("/etc/sudoers"), read("/etc/sudoers.d"),
                       write("/app/.pyenv/lib/six.py"), write("/root/.cache/pip/x"),
                       write("/tmp/pip-unpack-abc"), write("/dev/null")],
                names=["pypi.org", "files.pythonhosted.org"],
                sockets=[("151.101.0.223", 443, ["files.pythonhosted.org", "pypi.org"]),
                         ("2a04:4e42::223", 443, ["pypi.org"]), ("8.8.8.8", 53, [])],
                commands=[cmd("/app/.pyenv/bin/python3", "-m", "pip", "install", "six==1.17.0"),
                          cmd("uname", "-rs"), cmd("lsb_release", "-a"), cmd("rustc", "--version")]),
        },
    }


def analyse(result, ecosystem="npm", allow=()):
    return dyn.analyse(result, ecosystem, allow_hosts=allow)


class CleanBaselineTests(unittest.TestCase):
    def test_clean_npm_package_has_no_findings(self):
        report = analyse(npm_clean())
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])

    def test_clean_pypi_package_has_no_findings(self):
        report = analyse(pypi_clean(), "pypi")
        self.assertTrue(report.complete, report.problem)
        self.assertEqual(report.findings, [])


class FindingTests(unittest.TestCase):
    def test_reading_ssh_keys_during_install_is_a_finding(self):
        result = npm_clean()
        result["Analysis"]["install"]["Files"].append(read("/root/.ssh/id_rsa"))
        self.assertEqual(analyse(result).findings,
                         ["install: reads sensitive file /root/.ssh/id_rsa"])

    def test_manager_baseline_applies_only_to_its_own_ecosystem_and_to_install(self):
        result = npm_clean()
        result["Analysis"]["install"]["Files"].append(read("/root/.netrc"))
        result["Analysis"]["import"]["Files"].append(read("/root/.npmrc"))
        self.assertEqual(analyse(result).findings,
                         ["install: reads sensitive file /root/.netrc",
                          "import: reads sensitive file /root/.npmrc"])

    def test_sensitive_paths(self):
        for path in ["/root/.aws/credentials", "/root/.docker/config.json", "/root/.kube/config",
                     "/root/.git-credentials", "/root/.config/gh/hosts.yml", "/root/.gnupg/x",
                     "/root/.pypirc", "/app/.env", "/root/.bash_history"]:
            result = npm_clean()
            result["Analysis"]["import"]["Files"].append(read(path))
            with self.subTest(path=path):
                self.assertEqual(analyse(result).findings,
                                 [f"import: reads sensitive file {path}"])

    def test_writes_outside_the_package_areas_are_findings(self):
        result = npm_clean()
        for path in ["/root/.bashrc", "/etc/cron.d/x", "/root/.ssh/authorized_keys",
                     "/usr/local/bin/node"]:
            result["Analysis"]["install"]["Files"].append(write(path))
        self.assertEqual(analyse(result).findings, [
            "install: writes /root/.bashrc", "install: writes /etc/cron.d/x",
            "install: writes /root/.ssh/authorized_keys", "install: writes /usr/local/bin/node"])

    def test_foreign_dns_and_connection_are_findings(self):
        result = npm_clean()
        inst = result["Analysis"]["install"]
        inst["DNS"][0]["Queries"].append({"Hostname": "phone-home.example.net", "Types": ["A"]})
        inst["Sockets"].append({"Address": "104.20.23.154", "Port": 443,
                                "Hostnames": ["example.com"]})
        inst["Sockets"].append({"Address": "203.0.113.7", "Port": 4444, "Hostnames": []})
        self.assertEqual(analyse(result).findings, [
            "install: DNS lookup of phone-home.example.net",
            "install: connection to 104.20.23.154:443 (example.com)",
            "install: connection to 203.0.113.7:4444 (no DNS name)"])

    def test_registry_of_the_other_ecosystem_is_not_allowed(self):
        result = npm_clean()
        result["Analysis"]["install"]["DNS"][0]["Queries"].append(
            {"Hostname": "pypi.org", "Types": ["A"]})
        self.assertEqual(analyse(result).findings, ["install: DNS lookup of pypi.org"])

    def test_extra_allowed_host(self):
        result = npm_clean()
        inst = result["Analysis"]["install"]
        inst["DNS"][0]["Queries"].append({"Hostname": "api.example.com", "Types": ["A"]})
        inst["Sockets"].append({"Address": "192.0.2.1", "Port": 443,
                                "Hostnames": ["api.example.com"]})
        self.assertEqual(analyse(result, allow=["api.example.com"]).findings, [])

    def test_network_tools_are_findings(self):
        result = npm_clean()
        result["Analysis"]["install"]["Commands"] += [
            cmd("curl", "-s", "https://x"), cmd("/usr/bin/wget", "x"), cmd("sh", "-c", "nc x 1")]
        self.assertEqual(analyse(result).findings, [
            "install: runs curl -s https://x", "install: runs /usr/bin/wget x",
            "install: runs sh -c nc x 1"])

    def test_planted_credential_in_dns_or_arguments_is_exfiltration(self):
        result = npm_clean()
        inst = result["Analysis"]["install"]
        inst["DNS"][0]["Queries"].append({"Hostname": f"{HONEY.lower()}.evil.example",
                                          "Types": ["A"]})
        inst["Commands"].append(cmd("node", "-e", f"send('{HONEY}')"))
        findings = analyse(result).findings
        self.assertIn("install: planted credential leaves in a DNS lookup", findings)
        self.assertIn("install: planted credential passed to a command (node)", findings)

    def test_findings_are_deduplicated(self):
        result = npm_clean()
        for _ in range(2):
            result["Analysis"]["install"]["Files"].append(read("/root/.ssh/id_rsa"))
        self.assertEqual(len(analyse(result).findings), 1)


class CompletenessTests(unittest.TestCase):
    def test_failed_phase_is_incomplete(self):
        result = npm_clean()
        result["Analysis"]["install"]["Status"] = "error"
        report = analyse(result)
        self.assertFalse(report.complete)
        self.assertIn("install", report.problem)

    def test_missing_install_phase_is_incomplete(self):
        result = npm_clean()
        del result["Analysis"]["install"]
        self.assertFalse(analyse(result).complete)

    def test_wrong_package_is_incomplete(self):
        result = npm_clean()
        result["Package"]["Name"] = "other"
        report = dyn.analyse(result, "npm", expect_name="is-number")
        self.assertFalse(report.complete)
        self.assertIn("other", report.problem)


class VerdictTests(unittest.TestCase):
    def verdict(self, report):
        out = io.StringIO()
        with redirect_stdout(out):
            code = dyn.verdict(report)
        return code, out.getvalue()

    def test_clean_is_ok(self):
        code, out = self.verdict(analyse(npm_clean()))
        self.assertEqual(code, 0)
        self.assertIn("is-number 7.0.0", out)

    def test_findings_block(self):
        result = npm_clean()
        result["Analysis"]["install"]["Files"].append(read("/root/.ssh/id_rsa"))
        code, out = self.verdict(analyse(result))
        self.assertEqual(code, 1)
        self.assertIn("[BLOCK]", out)
        self.assertIn("/root/.ssh/id_rsa", out)

    def test_incomplete_has_no_verdict(self):
        result = npm_clean()
        result["Analysis"]["install"]["Status"] = "error"
        self.assertEqual(self.verdict(analyse(result))[0], 2)


class RunTests(unittest.TestCase):
    """Docker invocation, faked."""

    def test_argv_is_pinned_and_writes_only_to_a_temp_dir(self):
        argv = dyn.docker_argv("npm", "is-number", "7.0.0", Path("/tmp/out"))
        joined = " ".join(argv)
        self.assertIn("@sha256:", dyn.IMAGE)
        self.assertIn(dyn.IMAGE, argv)
        self.assertIn("--privileged", argv)
        self.assertIn("--rm", argv)
        self.assertIn(f"{dyn.CACHE_VOLUME}:/var/lib/containers", joined)
        self.assertEqual(argv[argv.index("-ecosystem") + 1], "npm")
        self.assertEqual(argv[argv.index("-package") + 1], "is-number")
        self.assertEqual(argv[argv.index("-version") + 1], "7.0.0")
        self.assertNotIn("-ti", argv)
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
        for m in mounts:
            source = m.rsplit(":", 1)[0]
            self.assertTrue(source.startswith(str(Path("/tmp/out"))) or source in (
                dyn.CACHE_VOLUME, "/tmp"), m)

    def test_without_version_no_version_flag(self):
        argv = dyn.docker_argv("pypi", "six", None, Path("/tmp/out"))
        self.assertNotIn("-version", argv)

    def test_missing_docker_gives_no_verdict_with_hint(self):
        out = io.StringIO()
        with patch.object(dyn.shutil, "which", return_value=None), redirect_stdout(out):
            code = dyn.run("npm", "is-number@7.0.0")
        self.assertEqual(code, 2)
        self.assertIn("--no-dynamic", out.getvalue())

    def test_run_reads_the_result_and_judges_it(self):
        import json

        def fake(argv, **kw):
            mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
            results = next(Path(m[:-len(":/results")]) for m in mounts
                           if m.endswith(":/results"))
            (results / "7.0.0.json").write_text(json.dumps(npm_clean()), encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "log", "")

        out = io.StringIO()
        with patch.object(dyn.shutil, "which", return_value="docker"), \
             patch.object(dyn, "run_bounded", side_effect=fake), redirect_stdout(out):
            code = dyn.run("npm", "is-number@7.0.0")
        self.assertEqual(code, 0, out.getvalue())

    def test_failed_container_gives_no_verdict(self):
        out = io.StringIO()
        with patch.object(dyn.shutil, "which", return_value="docker"), \
             patch.object(dyn, "run_bounded",
                          return_value=subprocess.CompletedProcess([], 1, "", "boom")), \
             redirect_stdout(out):
            self.assertEqual(dyn.run("npm", "is-number@7.0.0"), 2)
        self.assertIn("boom", out.getvalue())

    def test_timeout_gives_no_verdict(self):
        out = io.StringIO()
        with patch.object(dyn.shutil, "which", return_value="docker"), \
             patch.object(dyn, "run_bounded", side_effect=subprocess.TimeoutExpired([], 5)), \
             patch.object(dyn, "_remove") as remove, redirect_stdout(out):
            self.assertEqual(dyn.run("npm", "is-number"), 2)
        self.assertTrue(remove.call_args.args[0].startswith("agent-guard-dynamic-"))

    def test_version_spec_is_split_per_ecosystem(self):
        self.assertEqual(dyn.split_spec("npm", "@scope/pkg@1.2.3"), ("@scope/pkg", "1.2.3"))
        self.assertEqual(dyn.split_spec("npm", "@scope/pkg"), ("@scope/pkg", None))
        self.assertEqual(dyn.split_spec("pypi", "six==1.17.0"), ("six", "1.17.0"))
        self.assertEqual(dyn.split_spec("pypi", "six@1.17.0"), ("six", "1.17.0"))
        self.assertEqual(dyn.split_spec("pypi", "six"), ("six", None))


if __name__ == "__main__":
    unittest.main()


class WiringTests(unittest.TestCase):
    """Stage 3 runs by default after the static stage of npm/PyPI scans."""

    def main(self, module, argv):
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as ctx, \
             redirect_stdout(io.StringIO()):
            module.main()
        return ctx.exception.code

    def test_scan_cli_runs_the_dynamic_stage_and_the_worse_verdict_wins(self):
        cli = importlib.import_module("scan_cli")
        with patch.object(cli, "run_guarddog", return_value=0), \
             patch.object(cli._dynamic, "run", return_value=1) as run:
            code = self.main(cli, ["scan_cli.py", "npm", "pkg@1.0.0",
                                   "--allow-host", "api.example.com"])
        self.assertEqual(code, 1)
        run.assert_called_once_with("npm", "pkg@1.0.0", allow_hosts=["api.example.com"])

    def test_scan_cli_static_block_is_kept(self):
        cli = importlib.import_module("scan_cli")
        with patch.object(cli, "run_guarddog", return_value=1), \
             patch.object(cli._dynamic, "run", return_value=0):
            self.assertEqual(self.main(cli, ["scan_cli.py", "pypi", "six"]), 1)

    def test_scan_cli_no_dynamic_skips_the_stage(self):
        cli = importlib.import_module("scan_cli")
        with patch.object(cli, "run_guarddog", return_value=0), \
             patch.object(cli._dynamic, "run") as run:
            self.assertEqual(self.main(cli, ["scan_cli.py", "pypi", "six", "--no-dynamic"]), 0)
        run.assert_not_called()

    def test_scan_cli_go_has_no_dynamic_stage(self):
        cli = importlib.import_module("scan_cli")
        with patch.object(cli, "run_guarddog", return_value=0), \
             patch.object(cli._dynamic, "run") as run:
            self.assertEqual(self.main(cli, ["scan_cli.py", "go", "example.com/m"]), 0)
        run.assert_not_called()

    def test_scan_mcp_stage_one_includes_the_dynamic_stage(self):
        sm = importlib.import_module("scan_mcp")
        with patch.object(sm, "fetch_pypi"), \
             patch.object(sm, "run_skillspector", return_value=0), \
             patch.object(sm._dynamic, "run", return_value=1) as run:
            code = self.main(sm, ["scan_mcp.py", "pypi", "mcp-server-time"])
        self.assertEqual(code, 1)
        run.assert_called_once_with("pypi", "mcp-server-time", allow_hosts=[])

    def test_scan_mcp_no_dynamic(self):
        sm = importlib.import_module("scan_mcp")
        with patch.object(sm, "fetch_npm"), \
             patch.object(sm, "run_skillspector", return_value=0), \
             patch.object(sm._dynamic, "run") as run:
            self.assertEqual(self.main(sm, ["scan_mcp.py", "npm", "x", "--no-dynamic"]), 0)
        run.assert_not_called()


class UrlScanTests(unittest.TestCase):
    """scan_url offers an install after a package scan -- only after both stages."""

    def scan(self, kind, spec, pinned, dynamic_rc, **kw):
        su = importlib.import_module("scan_url")
        rs = importlib.import_module("_url_resolver")
        source = rs.ResolvedSource(kind=kind, install_hint=spec, label=spec)
        fetch = "fetch_pypi" if kind == "pypi" else "fetch_npm"
        with patch.object(su, fetch, return_value=pinned), \
             patch.object(su, "run_mcp_static", return_value=0), \
             patch.object(su._dynamic, "run", return_value=dynamic_rc) as run, \
             patch.object(su, "offer_mcp_install") as offer, \
             redirect_stdout(io.StringIO()):
            code = su.scan_resolved(source, "auto", dry_run=True, **kw)
        return code, run, offer

    def test_pypi_package_is_analysed_at_the_scanned_version(self):
        code, run, offer = self.scan("pypi", "mcp-server-time", "mcp-server-time==1.2.3", 0)
        self.assertEqual(code, 0)
        run.assert_called_once_with("pypi", "mcp-server-time==1.2.3")
        offer.assert_called_once()

    def test_dynamic_block_suppresses_the_install_offer(self):
        code, run, offer = self.scan("npm", "some-mcp", "some-mcp@2.0.0", 1)
        self.assertEqual(code, 1)
        run.assert_called_once_with("npm", "some-mcp@2.0.0")
        offer.assert_not_called()

    def test_no_dynamic_is_honoured(self):
        code, run, offer = self.scan("npm", "some-mcp", "some-mcp@2.0.0", 1, dynamic=False)
        self.assertEqual(code, 0)
        run.assert_not_called()
        offer.assert_called_once()
