"""Offline checks for the read-only watcher of installed MCP trees."""

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_check_lock import INTEGRITY, OfflineNetwork, npm_network, pypi_network
from tests.test_lockcheck import FakeNet, NOW, github_advisory, npm_lock, npm_pkg
from tests.test_mcp_uv import GIT_PKG, GIT_URL, git_lock, uv_lock

import _fastlane
import _lockcheck
import _mcp_locked
from _mcp_uv import project_name
import _user_config
import install_skill


ROOT = Path(__file__).resolve().parents[1]
GIT_SCOPE = "registry entries; the git commit itself has no advisory source"
REGISTRY_SCOPE = "all locked entries"
VERSION = "1.0.0"
TREE_FIELDS = {"name", "kind", "path", "status", "scope", "findings", "error"}


class McpAuditTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT))) / "mcp"
        self.root.mkdir()

    def tree(self, kind="npm", *, name=None, metadata=None, subdirectory=""):
        path = self.root / (name if name is not None else kind)
        path.mkdir()
        if kind == "npm":
            package = "srv"
            lock_name = "package-lock.json"
            text = json.dumps(npm_lock({"node_modules/srv": npm_pkg(
                package, VERSION, integrity=INTEGRITY)}))
        elif kind == "pypi":
            package = "demo"
            lock_name = "uv.lock"
            text = uv_lock(project_name(path.name), package, VERSION)
        else:
            package = GIT_PKG
            lock_name = "uv.lock"
            query = f"subdirectory={subdirectory}&" if subdirectory else ""
            text = git_lock(project_name(path.name), query_extra=query)
        lock_bytes = text.encode("utf-8")
        (path / lock_name).write_bytes(lock_bytes)
        data = {"kind": kind, "package": package, "version": VERSION,
                "lockfile_sha256": hashlib.sha256(lock_bytes).hexdigest()}
        if kind == "git":
            data["source"] = GIT_URL + (f"#subdirectory={subdirectory}" if subdirectory else "")
        if metadata:
            data.update(metadata)
        (path / _mcp_locked.METADATA).write_text(json.dumps(data), encoding="utf-8")
        return path

    def audit(self, fetch=None, *, root=None, policy=None):
        return _mcp_locked.audit_trees(
            self.root if root is None else root,
            policy=_fastlane.policy(None, None, False) if policy is None else policy,
            fetch=FakeNet() if fetch is None else fetch, now=NOW)

    def run_cli(self, *args, fetch=None, config=None, as_json=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        config = {"mcp": {"install_dir": str(self.root)}} if config is None else config
        fetch = FakeNet() if fetch is None else fetch
        argv = ["install_skill.py", "mcp-audit", *args] + (["--json"] if as_json else [])
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(_lockcheck, "http_fetch", fetch))
            if isinstance(config, Exception):
                stack.enter_context(mock.patch.object(_user_config, "load_config", side_effect=config))
            else:
                stack.enter_context(mock.patch.object(_user_config, "load_config", return_value=config))
            try:
                code = install_skill.main()
            except SystemExit as exc:
                code = exc.code
        if not as_json:
            return code, stdout.getvalue() + stderr.getvalue()
        result = json.loads(stdout.getvalue())
        self.assertIsInstance(result, dict)
        self.assertEqual(code or 0, result["code"])
        return result

    def assert_status(self, result, code, *statuses):
        self.assertEqual(result["code"], code, result)
        self.assertEqual([tree["status"] for tree in result["trees"]], list(statuses), result)

    def assert_no_verdict(self, result):
        self.assert_status(result, 2, "no_verdict")
        self.assertTrue(result["trees"][0]["error"], result)

    def test_audit_clean_trees_exit_0(self):
        for kind in ("npm", "pypi", "git"):
            self.tree(kind)
        fetch = FakeNet()
        result = self.audit(fetch)
        self.assert_status(result, 0, "clean", "clean", "clean")
        self.assertEqual({tree["kind"] for tree in result["trees"]}, {"npm", "pypi", "git"})
        self.assertTrue(fetch.calls)
        for url in fetch.calls:
            self.assertTrue(url.startswith((_lockcheck.OSV_BATCH_URL,
                                            _lockcheck.GITHUB_ADVISORIES_URL)), url)

    def test_audit_finds_advisory_and_gives_decision(self):
        self.tree()
        result = self.audit(npm_network())
        self.assert_status(result, 1, "finding")
        finding, = result["trees"][0]["findings"]
        self.assertEqual((finding["package"], finding["version"]), ("srv", VERSION))
        self.assertEqual(finding["advisories"], ["GHSA-review"])
        self.assertEqual(finding["decision"]["action"], "install")
        self.assertFalse((self.root / ".receipts").exists())

    def test_audit_finds_pypi_and_git_registry_advisories(self):
        self.tree("pypi")
        self.tree("git")
        fetch = pypi_network()
        fetch.ghsa[("reviewed", "anyio@4.0.0")] = [github_advisory(
            "GHSA-git-dependency", "anyio", "= 4.0.0", None, "pip")]
        result = self.audit(fetch)
        self.assert_status(result, 1, "finding", "finding")
        by_kind = {tree["kind"]: tree for tree in result["trees"]}
        self.assertEqual(by_kind["pypi"]["findings"][0]["advisories"], ["GHSA-review"])
        finding, = by_kind["git"]["findings"]
        self.assertEqual(finding["package"], "anyio")
        self.assertEqual(finding["advisories"], ["GHSA-git-dependency"])
        self.assertIsNotNone(finding["decision"])

    def test_audit_never_installs(self):
        self.tree()
        with ExitStack() as stack:
            guards = [stack.enter_context(mock.patch(target, side_effect=AssertionError(target)))
                      for target in ("_mcp_locked.run_tool", "_mcp_locked.deliver",
                                     "_mcp_locked.replace_tree", "_mcp_locked.rerun_register",
                                     "_mcp_npm.npm_install", "_mcp_uv.pypi_install",
                                     "_mcp_uv.git_install", "_fastlane.require_receipt")]
            result = self.run_cli(fetch=npm_network())
        self.assert_status(result, 1, "finding")
        self.assertEqual(result["trees"][0]["findings"][0]["decision"]["action"], "install")
        for guard in guards:
            guard.assert_not_called()

    def test_audit_skips_receipts_and_leftovers(self):
        self.tree()
        leftovers = {".npm.staging-abcd1234", ".npm.old-1234abcd", ".former.staging-1234abcd"}
        for name in {".receipts", ".ignored"} | leftovers:
            (self.root / name).mkdir()
        (self.root / "notes.txt").write_text("ignored", encoding="utf-8")
        result = self.audit()
        self.assert_status(result, 0, "clean")
        self.assertEqual(set(result["leftovers"]), leftovers)

    def test_audit_tree_without_metadata_has_no_verdict(self):
        (self.root / "missing").mkdir()
        self.assert_no_verdict(self.audit())

    def test_audit_rejects_invalid_metadata(self):
        for index, invalid in enumerate(("{", "[]", {"kind": "other"}, {"package": None},
                                         {"package": ""}, {"package": "  "})):
            path = self.tree(name=f"tree-{index}") / _mcp_locked.METADATA
            if isinstance(invalid, str):
                text = invalid
            else:
                data = json.loads(path.read_text(encoding="utf-8"))
                for key, value in invalid.items():
                    if value is None:
                        del data[key]
                    else:
                        data[key] = value
                text = json.dumps(data)
            path.write_text(text, encoding="utf-8")
        result = self.audit()
        self.assert_status(result, 2, *(["no_verdict"] * 6))
        self.assertTrue(all(tree["error"] for tree in result["trees"]))

    def test_audit_unreadable_metadata_has_no_verdict(self):
        self.tree()
        with mock.patch("builtins.open", side_effect=PermissionError("cannot read")):
            self.assert_no_verdict(self.audit())

    def test_audit_rejects_invalid_tree_name(self):
        self.tree(name="invalid name")
        self.assert_no_verdict(self.audit())

    def test_audit_rejects_missing_lockfile(self):
        for kind, lockfile in (("npm", "package-lock.json"), ("pypi", "uv.lock"), ("git", "uv.lock")):
            (self.tree(kind) / lockfile).unlink()
        self.assert_status(self.audit(), 2, "no_verdict", "no_verdict", "no_verdict")

    def test_audit_rejects_missing_empty_or_changed_lockfile_hash(self):
        for name, digest in (("missing", None), ("empty", ""), ("changed", "f" * 64)):
            path = self.tree(name=name)
            metadata = path / _mcp_locked.METADATA
            data = json.loads(metadata.read_text(encoding="utf-8"))
            if digest is None:
                del data["lockfile_sha256"]
            else:
                data["lockfile_sha256"] = digest
            metadata.write_text(json.dumps(data), encoding="utf-8")
        self.assert_status(self.audit(), 2, "no_verdict", "no_verdict", "no_verdict")

    def test_audit_parser_failure_has_no_verdict(self):
        path = self.tree()
        lock_bytes = b"{}"
        (path / "package-lock.json").write_bytes(lock_bytes)
        metadata = path / _mcp_locked.METADATA
        data = json.loads(metadata.read_text(encoding="utf-8"))
        data["lockfile_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
        metadata.write_text(json.dumps(data), encoding="utf-8")
        self.assert_no_verdict(self.audit())

    def test_audit_git_tree_with_subdirectory_is_read(self):
        self.tree("git", subdirectory="pkg")
        result = self.audit()
        self.assert_status(result, 0, "clean")
        self.assertEqual(result["trees"][0]["scope"], GIT_SCOPE)

    def test_audit_git_tree_without_source_has_no_verdict(self):
        path = self.tree("git") / _mcp_locked.METADATA
        data = json.loads(path.read_text(encoding="utf-8"))
        del data["source"]
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assert_no_verdict(self.audit())

    def test_audit_git_tree_with_invalid_source_has_no_verdict(self):
        self.tree("git", metadata={"source": "https://github.com/example/mcp@main"})
        self.assert_no_verdict(self.audit())

    def test_audit_lookup_failure_exits_2(self):
        self.tree()
        result = self.audit(FakeNet(fail="api.osv.dev"))
        self.assert_no_verdict(result)
        self.assertIn("simulated failure", result["trees"][0]["error"])

    def test_audit_finding_wins_over_other_unchecked_tree(self):
        self.tree()
        (self.root / "unknown").mkdir()
        result = self.audit(npm_network())
        self.assertEqual(result["code"], 1)
        self.assertEqual({tree["name"]: tree["status"] for tree in result["trees"]},
                         {"npm": "finding", "unknown": "no_verdict"})

    def test_audit_same_tree_keeps_findings_and_lookup_failures(self):
        self.tree()
        result = self.audit(npm_network(fail="api.osv.dev"))
        self.assert_status(result, 1, "finding")
        tree, = result["trees"]
        self.assertIn("simulated failure", tree["error"])
        self.assertEqual(tree["findings"][0]["decision"]["action"], "no_verdict")

    def test_audit_malware_is_a_finding(self):
        self.tree()
        result = self.audit(OfflineNetwork(ghsa={
            ("malware", "srv@1.0.0"): ["GHSA-malware"],
        }))
        self.assert_status(result, 1, "finding")
        self.assertEqual(result["trees"][0]["findings"][0]["advisories"], ["GHSA-malware"])

    def test_audit_unmatched_advisory_has_no_decision(self):
        self.tree()
        advisory = github_advisory("GHSA-unmatched", "other")
        result = self.audit(OfflineNetwork(ghsa={("reviewed", "srv@1.0.0"): [advisory]}))
        self.assert_status(result, 1, "finding")
        finding, = result["trees"][0]["findings"]
        self.assertEqual(finding["advisories"], ["GHSA-unmatched"])
        self.assertIsNone(finding["decision"])

    def test_audit_blocking_finding_without_advisory(self):
        self.tree()
        check = _lockcheck.Result(1, ["[BLOCK] lockfile finding: blocked entry"],
                                  blocking=["blocked entry"])
        with mock.patch.object(_lockcheck, "check", return_value=check):
            self.assert_status(self.audit(), 1, "finding")

    def test_audit_osv_detail_failure_retains_the_finding(self):
        self.tree()
        fetch = FakeNet(osv={("srv", VERSION): ["OSV-example"]}, fail="/v1/vulns/")
        result = self.audit(fetch)
        self.assert_status(result, 1, "finding")
        self.assertIn("OSV-example", result["trees"][0]["error"])

    def test_audit_osv_hit_without_id_remains_a_finding(self):
        self.tree()
        fetch = FakeNet(osv={("srv", VERSION): [None]})
        result = self.audit(fetch)
        self.assert_status(result, 1, "finding")
        self.assertIn("OSV batch hit ID", result["trees"][0]["error"])

    def test_audit_check_exception_has_no_verdict(self):
        self.tree()
        with mock.patch.object(_lockcheck, "check", side_effect=RuntimeError("check broke")):
            result = self.audit()
        self.assert_no_verdict(result)
        self.assertIn("check broke", result["trees"][0]["error"])

    def test_audit_kev_unavailable_keeps_the_finding(self):
        self.tree()
        result = self.audit(npm_network(fail="cisa.gov"))
        self.assert_status(result, 1, "finding")
        tree, = result["trees"]
        self.assertIn("KEV feed unavailable", tree["error"])
        self.assertEqual(tree["findings"][0]["decision"]["action"], "no_verdict")

    def test_audit_finding_tree_modified_during_lookup_stays_finding(self):
        lock = self.tree() / "package-lock.json"
        network = npm_network()

        def fetch(url, payload=None):
            if not network.calls:
                lock.write_bytes(lock.read_bytes() + b" ")
            return network(url, payload)

        result = self.audit(fetch)
        self.assert_status(result, 1, "finding")
        self.assertIn("changed", result["trees"][0]["error"])

    def test_audit_empty_or_missing_root_is_clean(self):
        self.assert_status(self.audit(), 0)
        self.assert_status(self.audit(root=self.root / "missing"), 0)

    def test_audit_lock_modified_during_lookup_has_no_verdict(self):
        lock = self.tree() / "package-lock.json"
        network = FakeNet()

        def fetch(url, payload=None):
            if not network.calls:
                lock.write_bytes(lock.read_bytes() + b" ")
            return network(url, payload)

        self.assert_no_verdict(self.audit(fetch))

    def test_audit_tree_added_during_lookup_has_no_verdict(self):
        self.tree()
        network = FakeNet()

        def fetch(url, payload=None):
            if not network.calls:
                self.tree(name="added")
            return network(url, payload)

        self.assertEqual(self.audit(fetch)["code"], 2)

    def test_audit_rejects_file_or_unlistable_root(self):
        path = self.root / "file"
        path.touch()
        self.assert_status(self.audit(root=path), 2)
        with mock.patch.object(Path, "iterdir", side_effect=PermissionError("cannot list")):
            self.assert_status(self.audit(), 2)

    def test_audit_rejects_link_child_and_root(self):
        self.tree()
        link = self.tree(name="link")
        lstat = Path.lstat
        for mode, attributes in ((stat.S_IFLNK, 0),
                                 (stat.S_IFDIR, stat.FILE_ATTRIBUTE_REPARSE_POINT)):
            with self.subTest(mode=mode, attributes=attributes):
                def inspect(path):
                    if path == link:
                        return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                    return lstat(path)

                with mock.patch.object(Path, "lstat", inspect):
                    result = self.audit()
                    self.assertEqual(result["code"], 2)
                    linked = next(tree for tree in result["trees"] if tree["name"] == "link")
                    self.assertEqual(linked["status"], "no_verdict")
                    self.assertRegex(linked["error"].lower(), "link|junction")
                    self.assert_status(self.audit(root=link), 2)

    def test_audit_refuses_linked_metadata_and_lockfile(self):
        path = self.tree()
        lstat = Path.lstat
        for name in (_mcp_locked.METADATA, "package-lock.json"):
            with self.subTest(name=name):
                def inspect(candidate):
                    if candidate == path / name:
                        return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
                    return lstat(candidate)

                with mock.patch.object(Path, "lstat", inspect):
                    self.assert_no_verdict(self.audit())

    def test_audit_json_shape(self):
        path = self.tree()
        result = self.run_cli(fetch=npm_network())
        self.assert_status(result, 1, "finding")
        tree, = result["trees"]
        self.assertEqual(set(tree), TREE_FIELDS)
        self.assertEqual((tree["name"], tree["kind"], Path(tree["path"]), tree["scope"]),
                         ("npm", "npm", path, REGISTRY_SCOPE))
        finding, = tree["findings"]
        self.assertEqual(set(finding), {"package", "version", "advisories", "decision"})

    def test_audit_config_error_is_one_json_no_verdict(self):
        for config in ({"mcp": []}, _user_config.ConfigError("broken config")):
            with self.subTest(config=config):
                self.assert_status(self.run_cli(config=config), 2)

    def test_audit_script_reports_config_parse_failure_as_json(self):
        config = self.root.parent / "invalid.toml"
        config.write_text("[mcp", encoding="utf-8")
        environment = {"AGENT_GUARD_CONFIG": str(config)}
        for name in ("SystemRoot", "USERPROFILE", "HOME"):
            if name in os.environ:
                environment[name] = os.environ[name]
        child = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "install_skill.py"),
                                "mcp-audit", "--json"], capture_output=True, text=True,
                               **{"env": environment})
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assert_status(json.loads(child.stdout), 2)

    def test_audit_unexpected_exception_has_no_verdict(self):
        def broken(*args, **kwargs):
            print("diagnostic")
            raise RuntimeError("unexpected audit failure")

        with mock.patch.object(_mcp_locked, "audit_trees", side_effect=broken):
            self.assert_status(self.run_cli(), 2)
            code, output = self.run_cli(as_json=False)
        self.assertEqual(code, 2)
        self.assertIn("NO VERDICT", output)
        self.assertIn("unexpected audit failure", output)

    def test_audit_invalid_policy_options_exit_2(self):
        for args in (("--min-age-days", "-1"), ("--trusted-days", "bad"),
                     ("--min-age-days", "1", "--trusted-days", "2")):
            with self.subTest(args=args):
                self.assert_status(self.run_cli(*args), 2)

    def test_audit_no_fast_lane_changes_decision_only(self):
        self.tree()
        enabled = self.run_cli(fetch=npm_network())
        disabled = self.run_cli("--no-fast-lane", fetch=npm_network())
        self.assert_status(enabled, 1, "finding")
        self.assert_status(disabled, 1, "finding")
        self.assertEqual(enabled["trees"][0]["findings"][0]["decision"]["action"], "install")
        self.assertEqual(disabled["trees"][0]["findings"][0]["decision"]["action"], "report")

    def test_audit_human_output_shows_tree_and_decision(self):
        self.tree()
        code, output = self.run_cli(fetch=npm_network(), as_json=False)
        self.assertEqual(code, 1)
        self.assertRegex(output, r"(?im)^.*npm.*finding|^.*finding.*npm")
        self.assertRegex(output, r"(?im)^.*srv.*install")

    def test_audit_does_not_write_installed_tree(self):
        self.tree()
        self.tree("pypi")
        (self.root / ".receipts").mkdir()
        (self.root / ".receipts" / "ignored").write_bytes(b"receipt")

        def snapshot():
            return {path: (path.stat().st_mtime_ns, path.read_bytes() if path.is_file() else None)
                    for path in [self.root, *self.root.rglob("*")]}

        before = snapshot()
        self.assertEqual(self.run_cli(fetch=npm_network())["code"], 1)
        self.assertEqual(snapshot(), before)
