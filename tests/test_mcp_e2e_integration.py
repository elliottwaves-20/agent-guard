"""Real end-to-end integration tests for locked MCP installers and checkers (#48).

Runs against real npm, real node, real uv, real git and live APIs (OSV, GitHub
Advisories, CISA KEV, npm and PyPI registries, npm SLSA attestations, PyPI
integrity provenance) behind AGENT_GUARD_INTEGRATION=1 without self-mocks.

Honest limits documented with the suite:
- SAFE scan receipts are pre-written with live registry integrity or SHA-256
  values rather than produced by scan_url.py here; the live scan_url.py to
  receipt roundtrip is covered in tests/test_scan_hint_roundtrip.py.
- Live fast-lane rebuilds (_rebuild_with_fixes) are not triggered here because
  fixing a vulnerable tree requires a live fast-lane-eligible advisory; live
  KEV, provenance and fast-lane decision evaluation run in LiveApiContractTests
  and mcp-audit, while rebuild mechanics are covered in unit/contract suites.
- PyPI provenance checks the publisher and artifact identity reported by the
  PyPI integrity API without independent cryptographic signature verification.
- Real npm SLSA cryptographic verification runs via `npm audit signatures`
  during the S1 update test (requires npm >= 11.17).
- Live LLM scans (--live) and the Windows admin symlink test remain outside
  this module. Unauthenticated GitHub API lookups share the 60/hour IP quota
  unless GITHUB_TOKEN or GH_TOKEN is set.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")

_fastlane = importlib.import_module("_fastlane")
_lockcheck = importlib.import_module("_lockcheck")
_mcp_locked = importlib.import_module("_mcp_locked")
_mcp_npm = importlib.import_module("_mcp_npm")
_mcp_receipts = importlib.import_module("_mcp_receipts")

# Settled commit on modelcontextprotocol/servers main (2026-11-18) with
# subdirectory src/time (static pyproject.toml, mcp-server-time entry point).
GIT_REPO = "modelcontextprotocol/servers"
GIT_SUBDIR = "src/time"
GIT_SHA = "c799c8552b0f27b7a33a7b9233773da144dddcf5"
GIT_URL = f"https://github.com/{GIT_REPO}@{GIT_SHA}#subdirectory={GIT_SUBDIR}"
GIT_PACKAGE = "mcp-server-time"

INTEGRATION_REASON = "set AGENT_GUARD_INTEGRATION=1 for live MCP installer and API E2E tests"
IS_INTEGRATION = os.environ.get("AGENT_GUARD_INTEGRATION") == "1"


def _run_cmd(argv: list[str], *, cwd: Path | None = None,
             env: dict[str, str] | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess:
    merged = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    if env:
        merged.update(env)
    return subprocess.run(
        argv, cwd=cwd, env=merged, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


def _run_python(script: str, args: list[str], *, env: dict[str, str] | None = None,
                timeout: int = 240) -> subprocess.CompletedProcess:
    base_env = {"AGENT_GUARD_CONFIG": "", "AGENT_GUARD_NO_USER_CONFIG": "1"}
    if env:
        base_env.update(env)
    return _run_cmd([sys.executable, str(SCRIPTS / script), *args],
                    cwd=ROOT, env=base_env, timeout=timeout)


def _write_register_config(base: Path) -> tuple[Path, Path, Path]:
    """Create isolated [mcp] config with a real register handoff recorder script."""
    root = base / "mcp"
    record_file = base / "registered.jsonl"
    recorder = base / "register_recorder.py"
    recorder.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        f"out = Path({str(record_file)!r})\n"
        "payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        "with out.open('a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(payload) + '\\n')\n",
        encoding="utf-8",
    )
    config = base / "config.toml"
    config.write_text(
        f"[mcp]\ninstall_dir = {json.dumps(str(root))}\n"
        f"register = [{json.dumps(sys.executable)}, {json.dumps(str(recorder))}]\n",
        encoding="utf-8",
    )
    return root, config, record_file


def _npm_receipt(root: Path, package: str, version: str) -> dict:
    """Fetch live registry metadata for package@version and write a matching SAFE receipt."""
    doc, _ = _lockcheck.http_fetch(f"{_lockcheck.NPM_REGISTRY_URL}{package}")
    integrity = doc["versions"][version]["dist"]["integrity"]
    _mcp_receipts.write_receipt(
        root,
        _mcp_receipts.Receipt(
            kind="npm", package=package, version=version,
            archive_sha256="0" * 64, integrity=integrity, verdict="SAFE",
            at="2026-11-25T00:00:00+00:00", agent_guard=_mcp_locked.agent_guard_version(),
        ),
    )
    return doc


def _pypi_receipt(root: Path, package: str, version: str) -> tuple[str, str]:
    """Fetch live PyPI pure wheel SHA-256 and write a matching SAFE receipt."""
    doc, _ = _lockcheck.http_fetch(f"{_lockcheck.PYPI_JSON_URL}{package}/{version}/json")
    wheels = [u for u in doc["urls"] if u["filename"].endswith("-none-any.whl")]
    if len(wheels) != 1:
        raise AssertionError(f"expected one pure wheel for {package}=={version}, got {wheels}")
    filename = wheels[0]["filename"]
    sha256 = wheels[0]["digests"]["sha256"]
    _mcp_receipts.write_receipt(
        root,
        _mcp_receipts.Receipt(
            kind="pypi", package=package, version=version,
            archive_sha256=sha256, integrity="", verdict="SAFE",
            at="2026-11-25T00:00:00+00:00", agent_guard=_mcp_locked.agent_guard_version(),
        ),
    )
    return filename, sha256


@unittest.skipUnless(IS_INTEGRATION, INTEGRATION_REASON)
class LiveApiContractTests(unittest.TestCase):
    """Live API contracts for CISA KEV, npm SLSA provenance and PyPI provenance."""

    def test_cisa_kev_live_feed_parses_known_cve(self):
        cves = _fastlane.kev_cves(_lockcheck.http_fetch)
        self.assertIsInstance(cves, frozenset)
        self.assertGreater(len(cves), 1000)
        self.assertIn("CVE-2021-44228", cves)
        for sample in list(cves)[:20]:
            self.assertRegex(sample, r"^CVE-\d{4}-\d{4,}$")

    def test_npm_provenance_and_continuity_live(self):
        pkg = "@modelcontextprotocol/server-filesystem"
        self.assertEqual(
            _fastlane.npm_provenance(pkg, "2.3.0", _lockcheck.http_fetch),
            "github.com/modelcontextprotocol/servers",
        )
        self.assertEqual(
            _fastlane.continuity("npm", pkg, "2.3.0", "2.4.0", _lockcheck.http_fetch),
            "same",
        )
        self.assertEqual(
            _fastlane.npm_provenance("lodash", "4.17.20", _lockcheck.http_fetch),
            "missing",
        )

    def test_pypi_provenance_and_pure_wheel_live(self):
        is_pure, sha256 = _fastlane.pure_wheel("sigstore", "4.5.1", _lockcheck.http_fetch)
        self.assertTrue(is_pure)
        self.assertRegex(sha256, r"^[0-9a-f]{64}$")
        doc, _ = _lockcheck.http_fetch(f"{_lockcheck.PYPI_JSON_URL}sigstore/4.5.1/json")
        wheel = [u for u in doc["urls"] if u["filename"].endswith("-none-any.whl")][0]
        self.assertEqual(
            _fastlane.pypi_provenance(
                "sigstore", "4.5.1",
                ((wheel["filename"], wheel["digests"]["sha256"]),),
                _lockcheck.http_fetch,
            ),
            "github:sigstore/sigstore-python",
        )
        cowsay_doc, _ = _lockcheck.http_fetch(f"{_lockcheck.PYPI_JSON_URL}cowsay/6.1/json")
        cowsay_whl = [u for u in cowsay_doc["urls"] if u["filename"].endswith("-none-any.whl")][0]
        self.assertEqual(
            _fastlane.pypi_provenance(
                "cowsay", "6.1",
                ((cowsay_whl["filename"], cowsay_whl["digests"]["sha256"]),),
                _lockcheck.http_fetch,
            ),
            "missing",
        )


@unittest.skipUnless(IS_INTEGRATION, INTEGRATION_REASON)
class LiveCheckLockTests(unittest.TestCase):
    """Subprocess E2E tests for scripts/check_lock.py against live OSV, GitHub and registries."""

    def test_package_mode_npm_vulnerable_and_clean(self):
        vuln = _run_python("check_lock.py", ["--package", "npm:lodash@4.17.20", "--json"])
        self.assertEqual(vuln.returncode, 1, vuln.stdout + vuln.stderr)
        data = json.loads(vuln.stdout)
        self.assertEqual(data["code"], 1)
        sources = {row["source"] for row in data["findings"]}
        ids = {row["id"] for row in data["findings"]}
        self.assertIn("osv", sources)
        self.assertIn("github-reviewed", sources)
        self.assertIn("GHSA-35jh-r3h4-6jhm", ids)

        clean = _run_python("check_lock.py", ["--package", "npm:is-number@7.0.0", "--json"])
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        clean_data = json.loads(clean.stdout)
        self.assertEqual(clean_data["code"], 0)
        self.assertEqual(clean_data["findings"], [])

    def test_package_mode_pypi_vulnerable_and_clean(self):
        vuln = _run_python("check_lock.py", ["--package", "pypi:urllib3@1.26.5", "--json"])
        self.assertEqual(vuln.returncode, 1, vuln.stdout + vuln.stderr)
        data = json.loads(vuln.stdout)
        self.assertEqual(data["code"], 1)
        sources = {row["source"] for row in data["findings"]}
        ids = {row["id"] for row in data["findings"]}
        self.assertIn("osv", sources)
        self.assertIn("github-reviewed", sources)
        self.assertIn("PYSEC-2023-192", ids)
        self.assertFalse(any(line.startswith("NO VERDICT") for line in data["lines"]), data["lines"])

        clean = _run_python("check_lock.py", ["--package", "pypi:cowsay@6.1", "--json"])
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        clean_data = json.loads(clean.stdout)
        self.assertEqual(clean_data["code"], 0)
        self.assertEqual(clean_data["findings"], [])

    def test_file_mode_hashed_requirements_clean_and_tampered_hash(self):
        doc, _ = _lockcheck.http_fetch(f"{_lockcheck.PYPI_JSON_URL}cowsay/6.1/json")
        wheel = [u for u in doc["urls"] if u["filename"].endswith("-none-any.whl")][0]
        real_sha = wheel["digests"]["sha256"]
        tampered = ("0" if real_sha[0] != "0" else "1") + real_sha[1:]

        with tempfile.TemporaryDirectory() as tmp:
            req_clean = Path(tmp) / "requirements-clean.txt"
            req_clean.write_text(f"cowsay==6.1 --hash=sha256:{real_sha}\n", encoding="utf-8")
            ok = _run_python("check_lock.py", [str(req_clean), "--json"])
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            ok_data = json.loads(ok.stdout)
            self.assertEqual(ok_data["code"], 0)
            self.assertEqual(ok_data["advisories"], [])
            self.assertEqual(ok_data["young"], [])

            req_bad = Path(tmp) / "requirements-bad.txt"
            req_bad.write_text(f"cowsay==6.1 --hash=sha256:{tampered}\n", encoding="utf-8")
            bad = _run_python("check_lock.py", [str(req_bad), "--json"])
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            bad_data = json.loads(bad.stdout)
            self.assertEqual(bad_data["code"], 1)
            joined = "\n".join(bad_data["lines"])
            self.assertIn("hash differs", joined)
            self.assertNotIn("NO VERDICT", joined)
            self.assertNotIn("(also unchecked:", joined)


@unittest.skipUnless(IS_INTEGRATION, INTEGRATION_REASON)
class LiveLockedInstallersAndAuditTests(unittest.TestCase):
    """Real E2E tests for mcp-npm, mcp-pypi, mcp-git, check_lock file mode and mcp-audit."""

    @classmethod
    def setUpClass(cls):
        for tool in ("npm", "node", "uv", "git"):
            if not shutil.which(tool):
                raise AssertionError(f"AGENT_GUARD_INTEGRATION=1 requires {tool} on PATH")
        ver_proc = _run_cmd([shutil.which("npm"), "--version"], timeout=30)
        match = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", ver_proc.stdout or "")
        if ver_proc.returncode != 0 or not match:
            raise AssertionError(f"cannot read npm version: {ver_proc.stdout}{ver_proc.stderr}")
        npm_ver = (int(match.group(1)), int(match.group(2)))
        if npm_ver < _mcp_npm.MIN_NPM_FAST_LANE:
            raise AssertionError(
                f"AGENT_GUARD_INTEGRATION=1 S1 test requires npm >= "
                f"{_mcp_npm.MIN_NPM_FAST_LANE[0]}.{_mcp_npm.MIN_NPM_FAST_LANE[1]}, "
                f"found {match.group(0)}"
            )

        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.base = Path(cls._tmp.name)
        cls.root, cls.config, cls.record_file = _write_register_config(cls.base)
        cls.env = {"AGENT_GUARD_CONFIG": str(cls.config), "AGENT_GUARD_NO_USER_CONFIG": ""}

        # 1. mcp-npm: install semver@7.7.0 (s2), then S1 update to semver@7.7.1
        # with min-age-days above 7.7.1 age so real --min-release-age-exclude
        # and real `npm audit signatures --json --include-attestations` run.
        sem_doc = _npm_receipt(cls.root, "semver", "7.7.0")
        _npm_receipt(cls.root, "semver", "7.7.1")
        p_npm_old = _run_python(
            "install_skill.py",
            ["mcp-npm", "--package", "semver", "--version", "7.7.0", "--json"],
            env=cls.env,
        )
        if p_npm_old.returncode != 0:
            raise AssertionError(f"mcp-npm 7.7.0 failed: {p_npm_old.stdout}\n{p_npm_old.stderr}")
        cls.npm_old_json = json.loads(p_npm_old.stdout)

        pub_771 = dt.datetime.fromisoformat(sem_doc["time"]["7.7.1"].replace("Z", "+00:00"))
        age_771 = (dt.datetime.now(dt.timezone.utc) - pub_771).days
        p_npm_s1 = _run_python(
            "install_skill.py",
            ["mcp-npm", "--package", "semver", "--version", "7.7.1",
             "--min-age-days", str(age_771 + 10), "--trusted-days", "2", "--json"],
            env=cls.env,
        )
        if p_npm_s1.returncode != 0:
            raise AssertionError(f"mcp-npm S1 7.7.1 failed: {p_npm_s1.stdout}\n{p_npm_s1.stderr}")
        cls.npm_s1_json = json.loads(p_npm_s1.stdout)

        # 2. mcp-pypi: install cowsay==6.1 (pure wheel, console_scripts entry point)
        _pypi_receipt(cls.root, "cowsay", "6.1")
        p_pypi = _run_python(
            "install_skill.py",
            ["mcp-pypi", "--package", "cowsay", "--version", "6.1", "--json"],
            env=cls.env,
        )
        if p_pypi.returncode != 0:
            raise AssertionError(f"mcp-pypi cowsay failed: {p_pypi.stdout}\n{p_pypi.stderr}")
        cls.pypi_json = json.loads(p_pypi.stdout)

        # 3. mcp-git: install modelcontextprotocol/servers#src/time at settled SHA
        _mcp_receipts.write_receipt(
            cls.root,
            _mcp_receipts.Receipt(
                kind="git", package=GIT_REPO, version=GIT_SHA,
                archive_sha256="0" * 64, integrity="", verdict="SAFE",
                at="2026-11-25T00:00:00+00:00", agent_guard=_mcp_locked.agent_guard_version(),
            ),
        )
        p_git = _run_python(
            "install_skill.py",
            ["mcp-git", "--name", "time-git", "--git-url", GIT_URL,
             "--package", GIT_PACKAGE, "--json"],
            env=cls.env,
        )
        if p_git.returncode != 0:
            raise AssertionError(f"mcp-git time-git failed: {p_git.stdout}\n{p_git.stderr}")
        cls.git_json = json.loads(p_git.stdout)

    def _recorded_handoffs(self) -> list[dict]:
        self.assertTrue(self.record_file.is_file(), "register handoff recorder never ran")
        return [json.loads(line) for line in self.record_file.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def test_mcp_npm_s1_tree_runs_with_node_and_passes_check_lock(self):
        self.assertEqual(self.npm_old_json["tier"], "s2")
        self.assertEqual(self.npm_s1_json["code"], 0)
        self.assertEqual(self.npm_s1_json["tier"], "s1")

        tree = self.root / "semver"
        meta = json.loads((tree / _mcp_locked.METADATA).read_text(encoding="utf-8"))
        lock_bytes = (tree / "package-lock.json").read_bytes()
        self.assertEqual(meta["kind"], "npm")
        self.assertEqual(meta["package"], "semver")
        self.assertEqual(meta["version"], "7.7.1")
        self.assertEqual(meta["tier"], "s1")
        self.assertEqual(meta["lockfile_sha256"], hashlib.sha256(lock_bytes).hexdigest())

        reg = json.loads((tree / _mcp_locked.REGISTER_FILE).read_text(encoding="utf-8"))
        handoffs = [r for r in self._recorded_handoffs() if r["name"] == "semver"]
        self.assertEqual([r["requested"] for r in handoffs], ["7.7.0", "7.7.1"])
        self.assertEqual(handoffs[-1], reg)
        self.assertFalse(_mcp_locked.is_adhoc_launch(reg["command"], reg["args"]))
        self.assertIn("node", Path(reg["command"]).name.lower())
        self.assertTrue(Path(reg["args"][0]).is_file())

        exec_proc = _run_cmd([reg["command"], *reg["args"], "-r", ">=7.0.0", "7.7.1"], timeout=30)
        self.assertEqual(exec_proc.returncode, 0, exec_proc.stdout + exec_proc.stderr)
        self.assertEqual(exec_proc.stdout.strip(), "7.7.1")

        checked = _run_python("check_lock.py", [str(tree / "package-lock.json"), "--json"])
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["code"], 0)

        npm = shutil.which("npm")
        _mcp_npm._audit_signatures(_mcp_locked.run_tool, npm, tree, [("semver", "7.7.1")])
        with self.assertRaises(_mcp_locked.Refused) as wrong_ver:
            _mcp_npm._audit_signatures(_mcp_locked.run_tool, npm, tree, [("semver", "7.7.0")])
        self.assertEqual(wrong_ver.exception.code, 2)
        self.assertIn("verified no provenance attestation", str(wrong_ver.exception))

    def test_mcp_pypi_tree_runs_with_uv_locked_and_passes_check_lock(self):
        self.assertEqual(self.pypi_json["code"], 0)
        tree = self.root / "cowsay"
        meta = json.loads((tree / _mcp_locked.METADATA).read_text(encoding="utf-8"))
        lock_bytes = (tree / "uv.lock").read_bytes()
        self.assertEqual(meta["kind"], "pypi")
        self.assertEqual(meta["package"], "cowsay")
        self.assertEqual(meta["version"], "6.1")
        self.assertEqual(meta["lockfile_sha256"], hashlib.sha256(lock_bytes).hexdigest())

        reg = json.loads((tree / _mcp_locked.REGISTER_FILE).read_text(encoding="utf-8"))
        handoffs = [r for r in self._recorded_handoffs() if r["name"] == "cowsay"]
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0], reg)
        self.assertFalse(_mcp_locked.is_adhoc_launch(reg["command"], reg["args"]))
        self.assertIn("uv", Path(reg["command"]).name.lower())
        self.assertEqual(reg["args"][:2], ["run", "--project"])
        self.assertIn("--locked", reg["args"])
        self.assertEqual(reg["args"][-1], "cowsay")

        exec_proc = _run_cmd([reg["command"], *reg["args"], "-t", "locked-ok"], timeout=60)
        self.assertEqual(exec_proc.returncode, 0, exec_proc.stdout + exec_proc.stderr)
        self.assertIn("locked-ok", exec_proc.stdout)

        checked = _run_python(
            "check_lock.py",
            [str(tree / "uv.lock"), "--root-name", "mcp-cowsay", "--json"],
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["code"], 0)

    def test_mcp_git_tree_runs_with_uv_locked_and_pins_commit(self):
        self.assertEqual(self.git_json["code"], 0)
        tree = self.root / "time-git"
        meta = json.loads((tree / _mcp_locked.METADATA).read_text(encoding="utf-8"))
        lock_bytes = (tree / "uv.lock").read_bytes()
        lock_text = lock_bytes.decode("utf-8")
        self.assertEqual(meta["kind"], "git")
        self.assertEqual(meta["package"], GIT_PACKAGE)
        self.assertEqual(meta["version"], GIT_SHA)
        self.assertEqual(meta["source"], GIT_URL)
        self.assertEqual(meta["lockfile_sha256"], hashlib.sha256(lock_bytes).hexdigest())
        parsed_lock = tomllib.loads(lock_text)
        git_pkgs = [p for p in parsed_lock["package"] if "git" in (p.get("source") or {})]
        self.assertEqual(len(git_pkgs), 1)
        git_parts = urllib.parse.urlsplit(git_pkgs[0]["source"]["git"])
        git_query = urllib.parse.parse_qs(git_parts.query)
        self.assertEqual(git_query.get("rev"), [GIT_SHA])
        self.assertEqual(git_parts.fragment, GIT_SHA)
        self.assertEqual(git_query.get("subdirectory"), [GIT_SUBDIR])

        reg = json.loads((tree / _mcp_locked.REGISTER_FILE).read_text(encoding="utf-8"))
        handoffs = [r for r in self._recorded_handoffs() if r["name"] == "time-git"]
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0], reg)
        self.assertFalse(_mcp_locked.is_adhoc_launch(reg["command"], reg["args"]))
        self.assertEqual(reg["args"][-1], "mcp-server-time")

        exec_proc = _run_cmd([reg["command"], *reg["args"], "--help"], timeout=60)
        self.assertEqual(exec_proc.returncode, 0, exec_proc.stdout + exec_proc.stderr)
        self.assertIn("mcp-server-time", exec_proc.stdout)

    def test_mcp_audit_clean_across_npm_pypi_and_git_trees(self):
        proc = _run_python("install_skill.py", ["mcp-audit", "--json"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["code"], 0)
        self.assertIsNone(data.get("error"))
        self.assertEqual(data["leftovers"], [])
        by_name = {tree["name"]: tree for tree in data["trees"]}
        self.assertEqual(set(by_name), {"cowsay", "semver", "time-git"})
        for name, kind in (("semver", "npm"), ("cowsay", "pypi"), ("time-git", "git")):
            self.assertEqual(by_name[name]["kind"], kind)
            self.assertEqual(by_name[name]["status"], "clean", by_name[name])
            self.assertEqual(by_name[name]["findings"], [])
            self.assertIsNone(by_name[name]["error"])
        self.assertIn("git commit itself has no advisory source", by_name["time-git"]["scope"])


@unittest.skipUnless(IS_INTEGRATION, INTEGRATION_REASON)
class LiveLockedRefusalAndAuditFindingTests(unittest.TestCase):
    """Independent negative E2E tests for mcp-npm, mcp-pypi, mcp-git and mcp-audit."""

    @classmethod
    def setUpClass(cls):
        for tool in ("npm", "node", "uv"):
            if not shutil.which(tool):
                raise AssertionError(f"AGENT_GUARD_INTEGRATION=1 requires {tool} on PATH")

    def test_mcp_npm_blocks_vulnerable_package_and_keeps_existing_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, config, record_file = _write_register_config(Path(tmp))
            env = {"AGENT_GUARD_CONFIG": str(config), "AGENT_GUARD_NO_USER_CONFIG": ""}
            sentinel = root / "sentinel"
            sentinel.mkdir(parents=True)
            marker = sentinel / "keep.txt"
            marker.write_text("previous-tree", encoding="utf-8")

            missing = _run_python(
                "install_skill.py",
                ["mcp-npm", "--name", "sentinel", "--package", "lodash",
                 "--version", "4.17.20", "--json"],
                env=env,
            )
            self.assertEqual(missing.returncode, 2, missing.stdout + missing.stderr)
            missing_data = json.loads(missing.stdout)
            self.assertEqual(
                missing_data["needs_scan"],
                [{"kind": "npm", "package": "lodash", "version": "4.17.20"}],
            )
            self.assertFalse(record_file.exists())

            _npm_receipt(root, "lodash", "4.17.20")
            blocked = _run_python(
                "install_skill.py",
                ["mcp-npm", "--name", "sentinel", "--package", "lodash",
                 "--version", "4.17.20", "--no-fast-lane", "--json"],
                env=env,
            )
            self.assertEqual(blocked.returncode, 1, blocked.stdout + blocked.stderr)
            self.assertEqual(json.loads(blocked.stdout)["code"], 1)
            self.assertIn("GHSA-35jh-r3h4-6jhm", blocked.stderr)
            self.assertNotIn("(also unchecked:", blocked.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "previous-tree")
            self.assertFalse(record_file.exists())

    def test_mcp_pypi_blocks_vulnerable_package_and_keeps_existing_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, config, record_file = _write_register_config(Path(tmp))
            env = {"AGENT_GUARD_CONFIG": str(config), "AGENT_GUARD_NO_USER_CONFIG": ""}
            sentinel = root / "sentinel"
            sentinel.mkdir(parents=True)
            marker = sentinel / "keep.txt"
            marker.write_text("previous-tree", encoding="utf-8")

            _pypi_receipt(root, "urllib3", "1.26.5")
            blocked = _run_python(
                "install_skill.py",
                ["mcp-pypi", "--name", "sentinel", "--package", "urllib3",
                 "--version", "1.26.5", "--no-fast-lane", "--json"],
                env=env,
            )
            self.assertEqual(blocked.returncode, 1, blocked.stdout + blocked.stderr)
            self.assertEqual(json.loads(blocked.stdout)["code"], 1)
            self.assertIn("PYSEC-2023-192", blocked.stderr)
            self.assertNotIn("(also unchecked:", blocked.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "previous-tree")
            self.assertFalse(record_file.exists())

    def test_mcp_git_refuses_missing_receipt_without_registering(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, config, record_file = _write_register_config(Path(tmp))
            env = {"AGENT_GUARD_CONFIG": str(config), "AGENT_GUARD_NO_USER_CONFIG": ""}
            missing = _run_python(
                "install_skill.py",
                ["mcp-git", "--name", "time-git", "--git-url", GIT_URL,
                 "--package", GIT_PACKAGE, "--json"],
                env=env,
            )
            self.assertEqual(missing.returncode, 2, missing.stdout + missing.stderr)
            data = json.loads(missing.stdout)
            self.assertEqual(data["code"], 2)
            self.assertIn("scan first:", data["message"])
            self.assertIn(f"https://github.com/{GIT_REPO}/tree/{GIT_SHA} --kind mcp-source",
                          data["message"])
            self.assertFalse(record_file.exists())

    def test_mcp_audit_and_check_lock_report_live_finding_and_tampered_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, config, _ = _write_register_config(Path(tmp))
            env = {"AGENT_GUARD_CONFIG": str(config), "AGENT_GUARD_NO_USER_CONFIG": ""}
            tree = root / "old-lodash"
            tree.mkdir(parents=True)
            (tree / "package.json").write_text(
                json.dumps({"name": "mcp-old-lodash", "private": True,
                            "dependencies": {"lodash": "4.17.20"}}),
                encoding="utf-8",
            )
            npm = shutil.which("npm")
            lock_proc = _run_cmd(
                [npm, "install", "--package-lock-only", "--ignore-scripts",
                 "--registry=https://registry.npmjs.org/", "--no-audit", "--no-fund"],
                cwd=tree, timeout=120,
            )
            self.assertEqual(lock_proc.returncode, 0, lock_proc.stdout + lock_proc.stderr)
            lock_bytes = (tree / "package-lock.json").read_bytes()
            (tree / _mcp_locked.METADATA).write_text(
                json.dumps({
                    "kind": "npm", "package": "lodash", "version": "4.17.20",
                    "overrides": {}, "override_reason": None,
                    "lockfile_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                    "at": "2026-11-25T00:00:00+00:00",
                    "agent_guard": _mcp_locked.agent_guard_version(),
                    "tier": "s2", "fast_lane": [], "source": "",
                }),
                encoding="utf-8",
            )

            # File-mode check_lock.py on the real vulnerable package-lock.json
            lock_check = _run_python("check_lock.py", [str(tree / "package-lock.json"), "--json"])
            self.assertEqual(lock_check.returncode, 1, lock_check.stdout + lock_check.stderr)
            lock_data = json.loads(lock_check.stdout)
            self.assertEqual(lock_data["code"], 1)
            self.assertIn("GHSA-35jh-r3h4-6jhm", {a["id"] for a in lock_data["advisories"]})
            self.assertFalse(any(line.startswith("NO VERDICT") for line in lock_data["lines"]),
                             lock_data["lines"])

            # mcp-audit on the same real tree: must report finding + live decision, zero lookup errors
            audit = _run_python("install_skill.py", ["mcp-audit", "--json"], env=env)
            self.assertEqual(audit.returncode, 1, audit.stdout + audit.stderr)
            data = json.loads(audit.stdout)
            self.assertEqual(data["code"], 1)
            self.assertIsNone(data.get("error"))
            self.assertEqual(len(data["trees"]), 1)
            row = data["trees"][0]
            self.assertEqual(row["status"], "finding")
            self.assertIsNone(row["error"])
            self.assertEqual(len(row["findings"]), 1)
            finding = row["findings"][0]
            self.assertEqual(finding["package"], "lodash")
            self.assertEqual(finding["version"], "4.17.20")
            self.assertIn("GHSA-35jh-r3h4-6jhm", finding["advisories"])
            decision = finding["decision"]
            self.assertIsNotNone(decision)
            self.assertEqual(decision["action"], "report")
            self.assertIn("GHSA-35jh-r3h4-6jhm", decision["advisories"])
            self.assertNotEqual(decision["reason"], "kev_unavailable")
            self.assertNotEqual(decision["reason"], "lookup_failed")

            # Tamper with the lockfile without updating metadata: must fail closed (exit 2).
            (tree / "package-lock.json").write_bytes(lock_bytes + b"\n")
            tampered = _run_python("install_skill.py", ["mcp-audit", "--json"], env=env)
            self.assertEqual(tampered.returncode, 2, tampered.stdout + tampered.stderr)
            tampered_data = json.loads(tampered.stdout)
            self.assertEqual(tampered_data["code"], 2)
            self.assertEqual(tampered_data["trees"][0]["status"], "no_verdict")
            self.assertIn("SHA-256 does not match", tampered_data["trees"][0]["error"])

    def test_npm_audit_signatures_live_refuses_unattested_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "unattested"
            tree.mkdir()
            (tree / "package.json").write_text(
                json.dumps({"name": "mcp-sig-check", "private": True,
                            "dependencies": {"is-number": "7.0.0"}}),
                encoding="utf-8",
            )
            npm = shutil.which("npm")
            lock_proc = _run_cmd(
                [npm, "install", "--package-lock-only", "--ignore-scripts",
                 "--registry=https://registry.npmjs.org/", "--no-audit", "--no-fund"],
                cwd=tree, timeout=120,
            )
            self.assertEqual(lock_proc.returncode, 0, lock_proc.stdout + lock_proc.stderr)
            ci_proc = _run_cmd(
                [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                 "--registry=https://registry.npmjs.org/"],
                cwd=tree, timeout=120,
            )
            self.assertEqual(ci_proc.returncode, 0, ci_proc.stdout + ci_proc.stderr)
            with self.assertRaises(_mcp_locked.Refused) as ctx:
                _mcp_npm._audit_signatures(_mcp_locked.run_tool, npm, tree, [("is-number", "7.0.0")])
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("verified no provenance attestation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
