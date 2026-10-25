"""Stage 3: dynamic install analysis with OpenSSF package-analysis.

Static scanners read an install script; they cannot see what it does. This
stage installs and imports the package inside OpenSSF's analysis sandbox
(gVisor inside a privileged Docker container) and judges the recorded
behaviour: files read and written, DNS lookups, connections and processes.

package-analysis records, it does not judge. The rules below are ours and
were calibrated against clean packages on the pinned image:

  * reading credential stores (~/.ssh, ~/.aws, .npmrc, .netrc, wallets, ...)
    is a finding. The package manager itself reads a few of them during
    install (npm: .npmrc; pip: /etc/shadow, /etc/sudoers, .netrc); the records carry no
    process, so exactly those are excused in the install phase only,
  * writing outside the package areas (/app, package caches, /tmp) is a
    finding -- shell profiles, /etc, ~/.ssh, system binaries,
  * DNS lookups and connections outside the ecosystem's registry (plus
    --allow-host) are findings; the sandbox resolver on port 53 is not,
  * network tools (curl, wget, nc, ...) started by the package are findings,
  * the sandbox plants fake credentials in the environment; seeing one in a
    DNS name or a command line is exfiltration.

A failed phase, a missing phase or a result for another package gives no
verdict. The analysed package really reaches the network (the sandbox has
nothing worth stealing); what it contacts is what this stage reports.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import _egress
from _skillspector import run_bounded

# OpenSSF package-analysis, analysis image of 2026-05-20, pinned by digest.
IMAGE = ("gcr.io/ossf-malware-analysis/analysis@sha256:"
         "1f3104f3f0cfddeaf62f0952d663e129cb5efe38486766e676fb926fa84c4c27")
# The analysis image pulls its per-ecosystem sandbox images into this volume;
# keeping it makes every run after the first take seconds instead of minutes.
CACHE_VOLUME = "agent-guard-dynamic-cache"
TIMEOUT = int(os.environ.get("AGENT_GUARD_DYNAMIC_TIMEOUT", "1200"))

ECOSYSTEMS = ("npm", "pypi")
REGISTRY_HOSTS = {
    "npm": ("registry.npmjs.org",),
    "pypi": ("pypi.org", "files.pythonhosted.org"),
}
# Read by the package manager itself during install (calibrated).
MANAGER_READS = {
    "npm": {"/app/.npmrc", "/root/.npmrc"},
    "pypi": {"/etc/shadow", "/etc/shadow-", "/etc/sudoers", "/etc/sudoers.d", "/root/.netrc"},
}
REQUIRED_PHASES = ("install", "import")
PHASE_ORDER = ("install", "import", "execute")
PHASE_KEYS = ("Files", "DNS", "Sockets", "Commands")  # lists every completed phase carries

SENSITIVE_READ = re.compile(
    r"/\.ssh/|id_rsa|id_ed25519|/\.aws/|/\.azure/|/\.config/gcloud/|/\.gnupg/"
    r"|/\.docker/config\.json$|/\.kube/|/\.config/gh/|/\.git-credentials$"
    r"|/\.netrc$|/\.npmrc$|/\.pypirc$|/\.env$|/\.env\.|_history$"
    r"|^/etc/shadow|^/etc/sudoers|/\.mozilla/|/\.config/(google-chrome|chromium)/"
    r"|/\.bitcoin/|/\.ethereum/|/\.config/solana/|/\.electrum/")
WRITE_OK = ("/app/", "/root/.npm/", "/root/.cache/", "/tmp/", "/dev/", "/proc/",
            "/execution.log", "pipe:", "socket:", "anon_inode:", "host:")
NET_TOOLS = ("curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp",
             "ssh", "scp", "sftp", "rsync", "dig", "nslookup", "host", "drill")
# \x60 is the backtick. Written as an escape because SkillSpector's shell parser
# reads a literal one as an unclosed command substitution and then inspects
# this file only partially.
_NET_TOOL_WORD = re.compile(r"(?:^|[\s;&|\x60(/])(" + "|".join(NET_TOOLS) + r")(?=\s|$)")
_SHELLS = ("sh", "bash", "dash", "zsh", "ash")
_PLANTED_KEY = re.compile(r"(KEY|SECRET|TOKEN|PASS)", re.IGNORECASE)


@dataclass
class Report:
    findings: list = field(default_factory=list)
    complete: bool = True
    problem: str = ""
    name: str = ""
    version: str = ""
    phases: list = field(default_factory=list)
    limits: list = field(default_factory=list)


def split_spec(ecosystem: str, spec: str) -> tuple:
    """`name@version` (npm, scoped names included) or `name==version` (PyPI)."""
    spec = spec.strip()
    if ecosystem == "pypi" and "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip() or None
    at = spec.find("@", 1 if spec.startswith("@") else 0)
    if at > 0:
        return spec[:at], spec[at + 1:] or None
    return spec, None


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _planted_values(phase: dict) -> set:
    values = set()
    for command in phase.get("Commands") or []:
        for entry in command.get("Environment") or []:
            key, sep, value = entry.partition("=")
            if sep and _PLANTED_KEY.search(key) and len(value) >= 8:
                values.add(value)
    return values


def analyse(result: dict, ecosystem: str, allow_hosts=(), expect_name: str | None = None) -> Report:
    """Judge an OpenSSF result. A shape this code did not expect (an entry that is
    no object, a changed schema) is an incomplete analysis, never a crash with a
    BLOCK-looking exit code."""
    try:
        return _analyse(result, ecosystem, allow_hosts, expect_name)
    except Exception as exc:
        report = Report()
        report.complete = False
        report.problem = f"the result could not be evaluated ({type(exc).__name__}: {exc})"
        return report


def _analyse(result: dict, ecosystem: str, allow_hosts, expect_name: str | None) -> Report:
    package = result.get("Package") or {}
    report = Report(name=package.get("Name", ""), version=package.get("Version", ""))
    analysis = result.get("Analysis") or {}
    if expect_name and _normal(report.name) != _normal(expect_name):
        report.complete = False
        report.problem = f"result is for package {report.name!r}, not {expect_name!r}"
        return report
    missing = [p for p in REQUIRED_PHASES if p not in analysis]
    # An MCP stdio server takes over stdout and closes it; OpenSSF's own execute
    # script then crashes on its next print. That phase is optional (see
    # REQUIRED_PHASES) and everything up to the crash is recorded and judged
    # below, so it is a stated limit, not a gap. install and import stay strict.
    if (analysis.get("execute") or {}).get("Status") == "error_analysis":
        report.limits.append("execute phase ended early (the analysis script failed, "
                             "for example because the package closed stdout); behaviour "
                             "recorded until then is judged")
    failed = [p for p, r in analysis.items() if (r or {}).get("Status") != "completed"
              and not (p == "execute" and (r or {}).get("Status") == "error_analysis")]
    if missing or failed:
        report.complete = False
        report.problem = "; ".join(filter(None, [
            f"phase(s) missing: {', '.join(missing)}" if missing else "",
            f"phase(s) did not complete: {', '.join(failed)}" if failed else ""]))

    # A completed phase must carry every record list (null is how the recorded output
    # spells "none"). A renamed or mistyped key would otherwise read as a clean phase.
    unreadable = [f"{name}: {key}" for name, result_phase in analysis.items()
                  if (result_phase or {}).get("Status") == "completed"
                  for key in PHASE_KEYS
                  if key not in result_phase
                  or not (result_phase[key] is None or isinstance(result_phase[key], list))]
    # The execute phase may end in error_analysis (see above). Whatever record lists it
    # still carries are read as "nothing found" below, so their types are checked too.
    crashed = analysis.get("execute") or {}
    if crashed.get("Status") == "error_analysis":
        unreadable += [f"execute: {key}" for key in PHASE_KEYS
                       if key in crashed
                       and not (crashed[key] is None or isinstance(crashed[key], list))]
    if unreadable:
        report.complete = False
        report.problem = "; ".join(filter(None, [
            report.problem,
            f"result keys missing or of the wrong type: {', '.join(unreadable)}"]))
        return report

    allow = _egress.parse_allow([*REGISTRY_HOSTS[ecosystem], *allow_hosts])
    allowed_names = {host for host, _port in allow}

    def finding(text):
        if text not in report.findings:
            report.findings.append(text)

    order = [p for p in PHASE_ORDER if p in analysis] + \
            [p for p in analysis if p not in PHASE_ORDER]
    report.phases = order
    for name in order:
        phase = analysis[name] or {}
        excused = MANAGER_READS[ecosystem] if name == "install" else set()
        for entry in phase.get("Files") or []:
            path = entry.get("Path") or ""
            if entry.get("Read") and SENSITIVE_READ.search(path) and path not in excused:
                finding(f"{name}: reads sensitive file {path}")
            if (entry.get("Write") or entry.get("Delete")) and not path.startswith(WRITE_OK):
                finding(f"{name}: writes {path}")

        lookups = [q.get("Hostname", "").rstrip(".").lower()
                   for block in phase.get("DNS") or [] for q in block.get("Queries") or []]
        for host in lookups:
            if host and host not in allowed_names:
                finding(f"{name}: DNS lookup of {host}")
        for sock in phase.get("Sockets") or []:
            port, address = sock.get("Port") or 0, sock.get("Address", "")
            # 0: resolved only, never connected; 53 on a private address: the resolver.
            # A configured public resolver is not exempt here: OpenSSF sockets carry
            # no protocol, so DNS over TCP cannot be told from UDP (UDP lookups are
            # judged from the DNS block above).
            if port == 0 or (port == 53 and _egress.private_address(address)):
                continue
            names = [h.rstrip(".").lower() for h in sock.get("Hostnames") or []]
            if (address, port) in allow or any((h, port) in allow for h in names):
                continue
            finding(f"{name}: connection to {address}:{port} "
                    f"({', '.join(names) if names else 'no DNS name'})")

        planted = _planted_values(phase)
        for command in phase.get("Commands") or []:
            argv = [str(a) for a in command.get("Command") or []]
            if not argv:
                continue
            line = " ".join(argv)
            tool = os.path.basename(argv[0])
            shell_body = " ".join(argv[2:]) if tool in _SHELLS and argv[1:2] == ["-c"] else ""
            if tool in NET_TOOLS or (shell_body and _NET_TOOL_WORD.search(shell_body)):
                finding(f"{name}: runs {line[:200]}")
            if any(value in line for value in planted):
                finding(f"{name}: planted credential passed to a command ({tool})")
        lowered = {value.lower() for value in planted}
        if any(value in host for host in lookups for value in lowered):
            finding(f"{name}: planted credential leaves in a DNS lookup")
    return report


def verdict(report: Report) -> int:
    print("\n" + "=" * 60)
    label = f"{report.name} {report.version}".strip() or "package"
    print(f"Dynamic install analysis (OpenSSF package-analysis): {label}")
    if report.phases:
        print(f"  phases: {', '.join(report.phases)}")
    for limit in report.limits:
        print(f"  LIMIT: {limit}")
    if report.findings:
        for item in report.findings:
            print(f"  - {item}")
    if not report.complete:
        print(f"[BLOCK] NO VERDICT -- dynamic analysis incomplete: {report.problem}. "
              "Do NOT install. Re-run the scan.")
        return 2
    if report.findings:
        print(f"[BLOCK] {len(report.findings)} suspicious action(s) while installing or "
              "importing the package. Do not install. If a destination is the package's "
              "own, documented service, review it and re-run with --allow-host HOST[:PORT].")
        return 1
    print("[OK] dynamic analysis: no suspicious file, network or process activity.")
    return 0


# -- running the analysis ---------------------------------------------------------

def docker_argv(ecosystem: str, name: str, version: str | None, out: Path,
                container: str = "agent-guard-dynamic") -> list:
    argv = ["docker", "run", "--cgroupns=host", "--privileged", "--rm", "--name", container,
            "-v", f"{CACHE_VOLUME}:/var/lib/containers", "-v", "/tmp",
            "-v", f"{out / 'results'}:/results",
            "-v", f"{out / 'static'}:/staticResults",
            "-v", f"{out / 'writes'}:/writeResults",
            "-v", f"{out / 'analyzed'}:/analyzedPackages",
            "-v", f"{out / 'strace'}:/straceLogs",
            IMAGE, "analyze", "-ecosystem", ecosystem, "-package", name]
    if version:
        argv += ["-version", version]
    argv += ["-dynamic-bucket", "file:///results/", "-file-writes-bucket", "file:///writeResults/",
             "-static-bucket", "file:///staticResults/",
             "-analyzed-pkg-bucket", "file:///analyzedPackages/",
             "-execution-log-bucket", "file:///results"]
    return argv


def _remove(container: str):
    try:
        subprocess.run(["docker", "rm", "--force", container], capture_output=True,
                       text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _no_verdict(reason: str) -> int:
    print("\n" + "=" * 60)
    print(f"[BLOCK] NO VERDICT -- dynamic install analysis: {reason}. Do NOT install.")
    return 2


def run(ecosystem: str, spec: str, allow_hosts=()) -> int:
    if shutil.which("docker") is None:
        return _no_verdict("Docker was not found on PATH. Install/start Docker, or re-run "
                           "with --no-dynamic to skip this stage knowingly")
    try:
        _egress.parse_allow(allow_hosts)
    except ValueError as exc:
        return _no_verdict(str(exc))
    name, version = split_spec(ecosystem, spec)
    container = "agent-guard-dynamic-" + uuid.uuid4().hex
    print(f"  dynamic install analysis in OpenSSF sandbox ({ecosystem} {name}"
          f"{' ' + version if version else ''}; first run pulls ~1-4 GB)")
    with tempfile.TemporaryDirectory(prefix="agent-guard-dynamic-") as tmp:
        out = Path(tmp)
        for sub in ("results", "static", "writes", "analyzed", "strace"):
            (out / sub).mkdir()
        try:
            proc = run_bounded(docker_argv(ecosystem, name, version, out, container),
                               timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            _remove(container)
            return _no_verdict(f"timed out after {TIMEOUT}s (AGENT_GUARD_DYNAMIC_TIMEOUT)")
        if proc.returncode != 0:
            tail = ((proc.stderr or "") + (proc.stdout or "")).strip()[-1500:]
            print(tail)
            return _no_verdict(f"analysis container failed (exit {proc.returncode})")
        files = sorted((out / "results").glob("*.json"))
        if not files:
            return _no_verdict("the analysis wrote no result")
        try:
            result = json.loads(files[0].read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _no_verdict(f"unreadable result ({exc})")
    report = analyse(result, ecosystem, allow_hosts, expect_name=name)
    if version and report.complete and report.version != version:
        report.complete = False
        report.problem = f"analysed version {report.version!r}, requested {version!r}"
    return verdict(report)
