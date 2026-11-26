"""The wrappers' helper probes never load code from the working directory
(CWE-427).

Each test plants a real file in a real working directory and runs the real
wrapper function; a planted file proves it ran by writing a marker file at an
absolute path. Network stays on this machine: LLM and VirusTotal calls are
pointed at 127.0.0.1:9, where nothing listens.
"""
import ast
from contextlib import redirect_stdout
import importlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")  # never read this machine's personal config
import _exe  # noqa: E402

WINDOWS = os.name == "nt"
NOWHERE = "http://127.0.0.1:9"
# Entry points that start with a hardened environment. run_all_tests.py is a
# developer tool; the _*_boot.py files run inside scanner Pythons the wrappers
# start, so they inherit the hardened environment.
NOT_HARDENED = {"run_all_tests.py"}
# Pinned so a new entry point, or a guard the test stops recognising, shows up.
ENTRY_POINTS = sorted(["audit_installed.py", "check_image_pins.py", "check_lock.py",
                       "install_skill.py", "llm_check.py", "llm_scan.py", "scan_cli.py",
                       "scan_mcp.py", "scan_skill.py", "scan_url.py", "update_skills.py",
                       "verify_skills_cli.py"])


def plant_program(folder: Path, name: str, marker: Path) -> None:
    if WINDOWS:
        (folder / f"{name}.bat").write_text(f'@echo ran> "{marker}"\n', encoding="ascii")
    else:
        script = folder / name
        script.write_text(f"#!/bin/sh\necho ran > '{marker}'\n", encoding="ascii")
        script.chmod(0o755)


def plant_module(folder: Path, name: str, marker: Path) -> None:
    (folder / f"{name}.py").write_text(
        f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        "raise SystemExit(3)\n", encoding="utf-8")


class InWorkDir(unittest.TestCase):
    def setUp(self):
        self._old = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name).resolve()
        self.work = base / "work"
        self.work.mkdir()
        self.markers = base / "markers"
        self.markers.mkdir()
        self.empty = base / "empty"
        self.empty.mkdir()
        os.chdir(self.work)

    def tearDown(self):
        os.chdir(self._old)
        self._tmp.cleanup()

    def child(self, code: str, extra_env: dict, timeout: float = 240) -> subprocess.CompletedProcess:
        """Run `code` in a fresh isolated Python started in the planted folder."""
        env = {**os.environ, **extra_env, "AGENT_GUARD_NO_USER_CONFIG": "1"}
        return subprocess.run([sys.executable, "-I", "-c", code, str(SCRIPTS), str(self.empty)],
                              cwd=self.work, env=env, capture_output=True, text=True,
                              timeout=timeout)


class ProbeTests(InWorkDir):
    def probe_host(self, runtime: str, *extra_path: str):
        sm = importlib.import_module("scan_mcp")
        # An empty entry, as on real Windows machines, and folders without the tool.
        path = os.pathsep.join(["", str(self.empty), *extra_path])
        with patch.dict(os.environ, {"PATH": path}):
            # A user's shell usually lacks the switch (this test host may set
            # it); cmd.exe would otherwise skip a planted .bat on its own.
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            return sm.host_runtime_version(runtime)

    def test_the_host_node_probe_does_not_run_a_planted_node(self):
        marker = self.markers / "node"
        plant_program(self.work, "node", marker)
        system = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32")] if WINDOWS else []
        self.assertIsNone(self.probe_host("node", *system))   # System32: cmd.exe for the .bat
        self.assertFalse(marker.exists(), "planted node ran")

    def test_the_host_python_probe_does_not_run_a_planted_uv(self):
        if WINDOWS:
            # The probe runs uv in an empty directory, so a planted .bat is not
            # found there, but a planted .exe still starts. where.exe as uv.exe
            # answers `uv python find` with the path of a real Python, so the
            # old probe returned that Python's version.
            system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
            shutil.copyfile(system / "where.exe", self.work / "uv.exe")
            self.assertIsNone(self.probe_host("python", os.path.dirname(sys.executable)))
        else:
            marker = self.markers / "uv"
            plant_program(self.work, "uv", marker)
            self.assertIsNone(self.probe_host("python"))
            self.assertFalse(marker.exists(), "planted uv ran")

    def test_the_mcpscanner_probe_does_not_import_a_planted_module(self):
        sm = importlib.import_module("scan_mcp")
        marker = self.markers / "mcpscanner"
        plant_module(self.work, "mcpscanner", marker)
        try:
            found = sm.mcpscanner_python()
        except SystemExit:
            found = None   # no scanner environment on this machine
        self.assertFalse(marker.exists(), "planted mcpscanner.py was imported")
        if _exe.which("uv"):
            # The probe really ran and found a scanner Python, not just failed.
            self.assertTrue(found and os.path.isfile(found), found)

    @unittest.skipUnless(_exe.which("uv"), "needs the Cisco scanner's uv tool environment")
    def test_the_virustotal_helper_does_not_import_a_planted_module(self):
        marker = self.markers / "json"
        plant_module(self.work, "json", marker)
        # A relative target: the helper keeps the working directory.
        code = ("import os, sys\nsys.path.insert(0, sys.argv[1])\nfrom pathlib import Path\n"
                "import scan_mcp\n"
                "sys.exit(scan_mcp.run_virustotal(Path(os.path.relpath(sys.argv[2]))))\n")
        done = self.child(code, {"VIRUSTOTAL_API_KEY": "test-placeholder", "HTTPS_PROXY": NOWHERE,
                                 "HTTP_PROXY": NOWHERE, "ALL_PROXY": NOWHERE, "NO_PROXY": ""})
        self.assertFalse(marker.exists(), "planted json.py was imported:\n" + done.stdout + done.stderr)
        # Printed only from the helper's parsed report: the helper really ran.
        self.assertIn("VirusTotal summary:", done.stdout, done.stdout + done.stderr)
        self.assertIn("total_to_scan: 0", done.stdout)

    @unittest.skipUnless(_exe.which("uv"), "needs the Cisco scanner's uv tool environment")
    def test_the_llm_probe_does_not_import_a_planted_module(self):
        marker = self.markers / "litellm"
        plant_module(self.work, "litellm", marker)
        code = ("import sys\nsys.path.insert(0, sys.argv[1])\n"
                "import llm_check\nsys.exit(llm_check.probe('mcp'))\n")
        done = self.child(code, {"MCP_SCANNER_LLM_API_KEY": "test-placeholder",
                                 "MCP_SCANNER_LLM_MODEL": "openai/test-model",
                                 "MCP_SCANNER_LLM_BASE_URL": NOWHERE,
                                 "MCP_SCANNER_LLM_TIMEOUT": "5"})
        self.assertFalse(marker.exists(), "planted litellm.py was imported:\n" + done.stdout + done.stderr)
        self.assertIn("mcp probe", done.stdout)   # the probe really ran and failed on the network


class AuditTests(InWorkDir):
    def test_execute_runs_the_wrappers_own_script_not_one_in_the_working_directory(self):
        audit = importlib.import_module("audit_installed")
        marker = self.markers / "scan_skill"
        (self.work / "scripts").mkdir()
        plant_module(self.work / "scripts", "scan_skill", marker)
        rc = audit.run(["python", "scripts/scan_skill.py", "--help"], True)
        self.assertFalse(marker.exists(), "planted scripts/scan_skill.py ran")
        self.assertEqual(rc, 0)

    def test_execute_refuses_a_command_that_is_not_one_of_its_scripts(self):
        audit = importlib.import_module("audit_installed")
        marker = self.markers / "other"
        plant_module(self.work, "other", marker)
        for cmd in (["python", "other.py"], [sys.executable, "other.py"], ["python"],
                    ["python", "scripts/"], ["python", "scripts/../README.md"],
                    ["python", "elsewhere/scan_skill.py", "--help"],
                    ["python", "scripts/not-there.py"],
                    ["node", "scripts/scan_skill.py", "--help"]):
            with self.subTest(cmd=cmd):
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = audit.run(cmd, True)
                self.assertEqual(rc, 2)
                self.assertIn("NOT EXECUTED", out.getvalue())
                self.assertFalse(marker.exists())


class SourceRules(unittest.TestCase):
    def test_no_wrapper_looks_programs_up_with_shutil_which(self):
        offenders = [f"{path.name}:{n}" for path in sorted(SCRIPTS.glob("*.py"))
                     if path.name != "_exe.py"
                     for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                     if "shutil.which" in line]
        self.assertEqual(offenders, [])

    def test_every_entry_point_hardens_the_environment_before_its_own_imports(self):
        """The first __main__ guard hardens, and only the standard library and
        _exe are imported above it, so no wrapper import runs unhardened."""
        missing = []
        for path in sorted(SCRIPTS.glob("*.py")):
            if path.name in NOT_HARDENED or path.name.endswith("_boot.py"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if not any(isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"
                       for node in tree.body):
                continue   # a library module, not an entry point
            for node in tree.body:
                if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'":
                    if ast.unparse(node.body[0]) != "_exe.harden_environ()":
                        missing.append(f"{path.name}: first guard starts with "
                                       f"{ast.unparse(node.body[0])}")
                    break
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = ([node.module] if isinstance(node, ast.ImportFrom)
                             else [alias.name for alias in node.names])
                    roots = {(name or "").split(".")[0] for name in names}
                    foreign = roots - set(sys.stdlib_module_names) - {"__future__", "_exe"}
                    if foreign:
                        missing.append(f"{path.name}: imports {sorted(foreign)} before hardening")
                        break
        self.assertEqual(missing, [])
        self.assertGreaterEqual(len(ENTRY_POINTS), 12)

    def test_the_entry_point_list_matches_the_scripts_folder(self):
        found = sorted(path.name for path in SCRIPTS.glob("*.py")
                       if path.name not in NOT_HARDENED and not path.name.endswith("_boot.py")
                       and any(isinstance(node, ast.If)
                               and ast.unparse(node.test) == "__name__ == '__main__'"
                               for node in ast.parse(path.read_text(encoding="utf-8")).body))
        self.assertEqual(found, ENTRY_POINTS)


if __name__ == "__main__":
    unittest.main()
