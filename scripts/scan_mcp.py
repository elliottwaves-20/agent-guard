#!/usr/bin/env python3
"""
MCP server security scanner -- scan first, install after (for MCP servers).

Unlike skills (plain Markdown + scripts that are only *read*), an MCP server is
code that must *run* to expose its tools. That makes naive "scan by starting it"
unsafe: a malicious server can act during startup, before anything is analysed.
This wrapper enforces the safe order:

  Stage 1 (default, NO execution): fetch the package source straight from the
    registry (PyPI sdist / npm tarball) with urllib -- never pip/uvx/npm install --
    and run SkillSpector's static scanner on the source. Nothing from the
    package runs. SkillSpector's pattern set covers the MCP-specific risks
    (Tool Poisoning, Tool Misuse, Least Privilege) on top of taint tracking,
    credential-access and exfiltration checks.

  Stage 1b (default, needs Docker; --no-dynamic skips it and gives exit 2
    unless AGENT_GUARD_STATIC_ONLY=1): the package is
    installed and imported inside OpenSSF's package-analysis sandbox (gVisor)
    and its file, network and process activity is judged -- install scripts
    run here, never on your machine (see _dynamic.py).

  Stage 2 (optional, --sandbox): the host scanner inspects the target inside a
    throwaway Docker container with no host filesystem access, so the server can
    be started for runtime tool/prompt analysis without touching your machine.
    This is the one thing a static scan cannot do: see MCP tools that are only
    registered at runtime. Powered by cisco-ai-mcp-scanner. The target's
    network traffic is captured: besides the PyPI/npm registries (and hosts
    named with --allow-host) every DNS lookup or connection blocks the
    verdict. --no-network runs the target with no network at all.

LLM analysis is optional. Stage 1 uses SkillSpector's provider config
(SKILLSPECTOR_*; by default a coding-agent CLI such as claude_cli, no API key),
while Stage 2 / remote uses Cisco mcp-scanner's LiteLLM config
(MCP_SCANNER_LLM_*, API key required -- Cisco has no CLI-subscription path).
Without any usable SkillSpector provider, Stage 1 runs static-only (--no-llm)
and ends with exit 2 (no verdict) unless AGENT_GUARD_STATIC_ONLY=1 is set.

Usage:
  python scan_mcp.py pypi  <package>[==version]      # fetch sdist, scan source
  python scan_mcp.py npm   <package>[@version]       # fetch tarball, scan source
  python scan_mcp.py local <path>                    # scan local source dir
  python scan_mcp.py remote <url>                     # scan a running remote MCP
  python scan_mcp.py virustotal <path>                # hash reputation check
  python scan_mcp.py pypi <pkg> --sandbox -- uvx <pkg>   # Stage 2: stdio in Docker
  python scan_mcp.py pypi <pkg> --sandbox --allow-host api.example.com -- uvx <pkg>

After a SAFE verdict, install with:
  python install_skill.py mcp --name <n> --command uvx --arg <pkg> [...]
"""

import argparse
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
import uuid
from pathlib import Path

import _dynamic
import _egress
import _llm_profile
from _skillspector import (
    SCAN_TIMEOUT,
    USER_CONFIG,
    combine_verdicts,
    die,
    run_bounded,
    run_skillspector as shared_run_skillspector,
    skipped_dynamic_verdict,
)

MCP_SCANNER = shutil.which("mcp-scanner")      # Stage 2 / remote: runtime (Cisco)

# (name, profile) for the Cisco runtime check, or None for MCP_SCANNER_LLM_*.
try:
    CISCO_PROFILE = _llm_profile.select_profile(USER_CONFIG, "mcp", os.environ)
except _llm_profile.ProfileError as exc:
    die(f"agent-guard config: {exc}")

CISCO_LLM_KEY = os.environ.get("MCP_SCANNER_LLM_API_KEY", "").strip()
CISCO_LLM_MODEL = os.environ.get("MCP_SCANNER_LLM_MODEL", "").strip()
CISCO_LLM_BASE_URL = os.environ.get("MCP_SCANNER_LLM_BASE_URL", "").strip()
CISCO_LLM_API_VERSION = os.environ.get("MCP_SCANNER_LLM_API_VERSION", "").strip()
# Named explicitly: Cisco's default adds "api" (the hosted Cisco AI Defense
# analyzer), which fails the whole scan unless MCP_SCANNER_API_KEY is set.
CISCO_ANALYZERS = "yara,llm"


def _llm_key_kind(key: str) -> str:
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("sk-proj-") or key.startswith("sk-"):
        return "openai"
    if key.startswith("nvapi-"):
        return "nvidia"
    return "unknown"


def _llm_model_kind(model: str) -> str:
    low = model.lower()
    if low.startswith(("anthropic/", "claude-")):
        return "anthropic"
    if low.startswith(("openai/", "gpt-", "o1", "o3", "o4")):
        return "openai"
    if low.startswith(("gemini/", "vertex_ai/", "bedrock/", "ollama/")):
        return "provider-prefixed"
    return "unknown"


def validate_cisco_llm_config() -> None:
    if not CISCO_LLM_KEY or not CISCO_LLM_MODEL:
        return
    key_kind = _llm_key_kind(CISCO_LLM_KEY)
    model_kind = _llm_model_kind(CISCO_LLM_MODEL)
    if key_kind in ("anthropic", "openai") and model_kind in ("anthropic", "openai"):
        if key_kind != model_kind:
            die(
                "MCP_SCANNER_LLM_API_KEY does not match MCP_SCANNER_LLM_MODEL. "
                f"Detected a {key_kind} key with a {model_kind} model. "
                "Use an Anthropic/Claude model with an Anthropic key, or an "
                "OpenAI/GPT model with an OpenAI key."
            )


CISCO_BOOT = Path(__file__).with_name("_cisco_boot.py")


def cisco_command(env: dict) -> list:
    """argv prefix for a Cisco scan. A reasoning profile needs the boot shim,
    which applies Cisco's reasoning request rule to the profile's model;
    otherwise the installed `mcp-scanner` entry point is used unchanged."""
    if env.get("AGENT_GUARD_CISCO_REASONING") == "1":
        return [mcpscanner_python(), str(CISCO_BOOT)]
    return [MCP_SCANNER]


def cisco_llm_problem() -> str | None:
    """Why the Cisco runtime LLM cannot run, or None when it can."""
    if CISCO_PROFILE:
        return _llm_profile.cisco_env(*CISCO_PROFILE, os.environ)[1]
    if not CISCO_LLM_KEY:
        return ("no Cisco runtime LLM key -- configure an [llm.use] mcp profile or "
                "MCP_SCANNER_LLM_API_KEY + MCP_SCANNER_LLM_MODEL")
    return None


def cisco_env() -> dict:
    """Environment for the Cisco MCP scanner: hand it the LiteLLM model + base
    URL so its LiteLLM uses the configured runtime provider instead of its
    default. The key is passed via environment, not CLI args, so it does not
    show up in process listings and avoids mcp-scanner CLI flag regressions."""
    if CISCO_PROFILE:
        name, profile = CISCO_PROFILE
        e, problem = _llm_profile.cisco_env(name, profile, os.environ)
        if problem:
            die(f"Cisco runtime LLM: {problem}")
        if (profile.get("limits") or {}).get("rpm"):
            # Cisco analyses all tools of a server concurrently and has no
            # concurrency switch, so a per-minute quota can only be absorbed
            # by its retries (profile: retries / retry_delay), not enforced.
            print(f"  NOTE: profile {name} sets limits.rpm; the Cisco scanner cannot "
                  "honour it (it analyses all tools in parallel). Raise retries / "
                  "retry_delay or use a provider with a larger per-minute quota.")
        return e
    validate_cisco_llm_config()
    e = dict(os.environ)
    if CISCO_LLM_KEY:
        e["MCP_SCANNER_LLM_API_KEY"] = CISCO_LLM_KEY
        key_kind = _llm_key_kind(CISCO_LLM_KEY)
        if key_kind == "anthropic":
            e["ANTHROPIC_API_KEY"] = CISCO_LLM_KEY
        elif key_kind == "openai":
            e["OPENAI_API_KEY"] = CISCO_LLM_KEY
    if CISCO_LLM_MODEL:
        e["MCP_SCANNER_LLM_MODEL"] = CISCO_LLM_MODEL
    if CISCO_LLM_BASE_URL:
        e["MCP_SCANNER_LLM_BASE_URL"] = CISCO_LLM_BASE_URL
    if CISCO_LLM_API_VERSION:
        e["MCP_SCANNER_LLM_API_VERSION"] = CISCO_LLM_API_VERSION
    return e


DOCKER_IMAGE = "agent-guard-mcp-sandbox"
# The target container only needs launchers (uv/uvx, node/npx, git). The Cisco
# analyzer runs on the host, so it is not installed here. The image is tagged
# by the hash of this text, so an edit here always builds a fresh image.
SANDBOX_DOCKERFILE = (
    "FROM python:3.12-slim\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends "
    "git nodejs npm curl ca-certificates && rm -rf /var/lib/apt/lists/*\n"
    "RUN pip install --no-cache-dir uv\n"
    "RUN useradd -m -u 1000 scanner\n"
    "USER scanner\n"
)

# How long the scanner waits for a stdio MCP to start. The default (60s) is too
# short for servers whose first `uvx`/`npx` launch must download heavy deps
# (pandas, numpy, ...) inside a fresh container.
STDIO_TIMEOUT = int(os.environ.get("SCAN_MCP_STDIO_TIMEOUT", "240"))
VT_MAX_FILES = int(os.environ.get("MCP_SCANNER_VT_MAX_FILES", "10"))
# A VirusTotal report older than this was made with outdated engine signatures.
VT_STALE_DAYS = 30

VT_HELPER = r"""
import json
import os
import sys
from pathlib import Path

from mcpscanner.config.constants import MCPScannerConstants as CONSTANTS
from mcpscanner.core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

target = Path(sys.argv[1])
max_files = int(sys.argv[2])
api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
if not api_key:
    print(json.dumps({"error": "missing_key"}))
    sys.exit(2)

analyzer = VirusTotalAnalyzer(
    api_key=api_key,
    enabled=True,
    upload_files=os.environ.get("MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES", "").lower() == "true",
    max_files=max_files,
    inclusion_extensions=getattr(CONSTANTS, "VIRUSTOTAL_INCLUSION_EXTENSIONS", set()),
    exclusion_extensions=getattr(CONSTANTS, "VIRUSTOTAL_EXCLUSION_EXTENSIONS", set()),
)

# VirusTotal answers 200 with empty engine stats for a hash it knows but has not
# analysed yet; the analyzer then reports 0 engines and the file looks clean.
# Treat such a result as "not found" (unknown is not clean) in both branches below.
# A positive verdict is never downgraded.
_query_original = analyzer._query_virustotal_cached


def _query_with_engines(file_hash):
    result = _query_original(file_hash)
    vt_result, hash_found, error_reason = result
    if hash_found and not error_reason and isinstance(vt_result, dict):
        engines = vt_result.get("total_engines")
        positive = vt_result.get("malicious", 0) or vt_result.get("suspicious", 0)
        if not positive and (type(engines) is not int or engines <= 0):
            return None, False, None
    return result


analyzer._query_virustotal_cached = _query_with_engines

if target.is_file():
    # analyze_file() returns None for a clean file, an unknown hash and a failed
    # lookup alike. Query the hash directly so those outcomes stay apart --
    # "VirusTotal could not tell" must never read as "clean".
    import hashlib
    h = hashlib.sha256()
    with target.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    file_hash = h.hexdigest()
    summary = {
        "total_found": 1,
        "total_to_scan": 1,
        "scanned": 0,
        "clean": 0,
        "malicious": 0,
        "suspicious": 0,
        "not_found": 0,
        "throttled": 0,
        "failed": 0,
        "skipped_by_limit": 0,
    }
    findings = []
    try:
        vt_result, hash_found, error_reason = analyzer._query_virustotal_cached(file_hash)
        if not error_reason and not hash_found and analyzer.upload_files:
            vt_result = analyzer._upload_and_scan(target, file_hash)
            hash_found = vt_result is not None
            error_reason = None if hash_found else "upload_failed"
    except Exception as exc:  # fail closed, including a changed private API
        vt_result, hash_found, error_reason = None, False, f"exception: {exc}"
    if error_reason in ("rate_limit", "quota_exceeded", "daily_cap_reached", "auth_error"):
        summary["throttled"] = 1
    elif error_reason:
        summary["failed"] = 1
    elif not hash_found:
        summary["not_found"] = 1
    else:
        summary["scanned"] = 1
        summary["scan_date"] = vt_result.get("scan_date")
        if vt_result.get("malicious", 0) > 0:
            summary["malicious"] = 1
            findings = [analyzer._create_finding(
                file_path=str(target), file_hash=file_hash, vt_result=vt_result)]
        elif vt_result.get("suspicious", 0) > 0:
            summary["suspicious"] = 1
        else:
            summary["clean"] = 1
elif target.is_dir():
    findings = analyzer.analyze_directory(str(target))
    # An empty summary only says Cisco found nothing to scan (Cisco leaves it
    # empty only when no file is eligible; Cisco is not pinned, so this is an assumption). Cisco drops files under
    # dot directories and __pycache__, symlinks that leave the root, and cannot tell
    # text from a binary without puremagic. Count what it would check without those
    # exclusions so that the verdict can tell "nothing there" from "nothing looked at".
    summary = dict(analyzer.last_scan_summary or {"total_to_scan": 0})
    from mcpscanner.utils import file_magic
    magic_ok = bool(getattr(file_magic, "_PUREMAGIC_AVAILABLE", False))
    eligible = 0
    for entry in target.rglob("*"):
        try:
            if entry.is_symlink():
                eligible += 1  # never followed, so never checked
            elif entry.is_file():
                if not magic_ok or analyzer._should_scan_file(str(entry)):
                    eligible += 1
                else:
                    with entry.open("rb") as handle:
                        handle.read(1)  # an unreadable file cannot be judged
        except Exception:
            eligible += 1
    summary["agent_guard_eligible"] = eligible
else:
    print(json.dumps({"error": "missing_path"}))
    sys.exit(2)

print(json.dumps({
    "summary": summary,
    "findings": [
        {
            "severity": finding.severity,
            "summary": finding.summary,
            "details": finding.details or {},
        }
        for finding in findings
    ],
}))
"""


def need_mcp_scanner():
    if MCP_SCANNER is None:
        die("cisco-ai-mcp-scanner (mcp-scanner) not found on PATH -- needed for "
            "--sandbox / remote runtime scans. Run setup.sh / setup.ps1 first.")


def mcpscanner_python() -> str:
    """Return a Python executable that can import Cisco's mcpscanner package.

    `uv tool install cisco-ai-mcp-scanner` exposes `mcp-scanner` on PATH, but
    not necessarily the package in the Python running this wrapper. Prefer the
    current interpreter when it works, otherwise ask uv for the tool venv.
    """
    probe = subprocess.run(
        [sys.executable, "-c", "import mcpscanner"],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        return sys.executable

    uv = shutil.which("uv")
    if uv is None:
        die("uv not found on PATH and current Python cannot import mcpscanner.")
    tool_dir = subprocess.run([uv, "tool", "dir"], capture_output=True, text=True)
    if tool_dir.returncode != 0:
        die("Could not locate uv tool directory for cisco-ai-mcp-scanner.")
    root = Path(tool_dir.stdout.strip()) / "cisco-ai-mcp-scanner"
    candidates = [
        root / "Scripts" / "python.exe",
        root / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    die("Could not find the cisco-ai-mcp-scanner Python environment. Re-run setup.")


def http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def http_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


# -- safe extraction (no path traversal -- CVE-2007-4559) ----------------------

def safe_extract_tar(data: bytes, dest: Path):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        # Python 3.12+: data filter rejects traversal/absolute paths/special files
        try:
            tf.extractall(dest, filter="data")
            return
        except TypeError:
            pass  # older Python: manual guard below
        for m in tf.getmembers():
            p = (dest / m.name).resolve()
            if not p.is_relative_to(dest.resolve()):
                die(f"unsafe path in archive: {m.name}")
            if not (m.isfile() or m.isdir()):
                die(f"archive contains a link ({m.name}); refusing to extract")
        tf.extractall(dest)


def safe_extract_zip(data: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            p = (dest / name).resolve()
            if not p.is_relative_to(dest.resolve()):
                die(f"unsafe path in archive: {name}")
        zf.extractall(dest)


# -- source acquisition (NO package code executed) ----------------------------

def fetch_pypi(spec: str, dest: Path) -> str:
    name, _, version = spec.partition("==")
    meta = http_json(f"https://pypi.org/pypi/{name}/json")
    version = version or meta["info"]["version"]
    files = meta.get("releases", {}).get(version)
    if not files:
        die(f"{name}=={version} has no release files on PyPI; refusing a different version.")
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    if not sdists:
        die(f"{name}=={version} has no source distribution (sdist) on PyPI -- "
            "cannot scan source without executing a wheel. Try --sandbox instead.")
    url = sdists[0]["url"]
    print(f"  fetching sdist: {url}")
    safe_extract_tar(http_bytes(url), dest)
    return f"{name}=={version}"


def fetch_npm(spec: str, dest: Path) -> str:
    if spec.startswith("@"):
        scope_name, _, version = spec[1:].partition("@")
        name, version = "@" + scope_name, version
    else:
        name, _, version = spec.partition("@")
    meta = http_json(f"https://registry.npmjs.org/{name}")
    version = version or meta.get("dist-tags", {}).get("latest")
    version = meta.get("dist-tags", {}).get(version, version)
    ver = meta.get("versions", {}).get(version)
    if not ver:
        die(f"{name}@{version} does not exist on npm; refusing a different version.")
    url = ver["dist"]["tarball"]
    print(f"  fetching npm tarball: {url}")
    safe_extract_tar(http_bytes(url), dest)
    return f"{name}@{version}"


# -- Stage 1: SkillSpector static source scan ---------------------------------

def run_skillspector(src: Path) -> int:
    """Static scan of MCP source with SkillSpector. Nothing from the package
    runs. Writes a JSON report to a temp file (robust across platforms; the
    terminal renderer is unreliable on legacy Windows consoles) and judges it."""
    return shared_run_skillspector(src, runtime_hint=True)


# -- Cisco runtime paths (remote + Stage 2 sandbox) ---------------------------

def run_cisco(cmd: list, label: str, env: dict = None) -> int:
    """Run an mcp-scanner command with a hard timeout, then judge its output."""
    print(f"  {label}")
    try:
        r = run_bounded(cmd, timeout=SCAN_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
              "install. The server may hang on start, or its dependencies are too "
              "slow to fetch. Raise SCAN_MCP_TIMEOUT or review manually.")
        return 2
    out = r.stdout or ""
    # stderr is shown for the user but never parsed: it could carry a forged summary.
    print(out + (r.stderr or ""))
    return verdict(out, r.returncode)


def run_remote(url: str) -> int:
    need_mcp_scanner()
    env = cisco_env()
    cmd = [*cisco_command(env), "--format", "summary", "--analyzers", CISCO_ANALYZERS,
           "remote", "--server-url", url]
    return run_cisco(cmd, f"scanning remote MCP (no local code runs): {url}", env=env)


def run_virustotal(path: Path, max_files: int = VT_MAX_FILES) -> int:
    """Run Cisco's VirusTotal analyzer directly.

    The upstream `mcp-scanner virustotal` CLI path in cisco-ai-mcp-scanner 4.7.3
    currently trips a Python `os` scoping bug. Calling the analyzer directly
    keeps agent-guard's documented VT check usable without patching site-packages.
    """
    if not os.environ.get("VIRUSTOTAL_API_KEY", "").strip():
        die("VIRUSTOTAL_API_KEY is not set. Add it to .env or the process environment.")
    if not path.exists():
        die(f"VirusTotal scan path does not exist: {path}")

    print(f"  VirusTotal hash reputation scan: {path}")
    print("  uploads: disabled unless MCP_SCANNER_VIRUSTOTAL_UPLOAD_FILES=true")
    python = mcpscanner_python()
    r = run_bounded([python, "-c", VT_HELPER, str(path), str(max_files)],
                    timeout=SCAN_TIMEOUT, env=dict(os.environ))
    if r.stderr:
        print(r.stderr)
    try:
        report = json.loads((r.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        print(r.stdout or "")
        print("\n" + "=" * 60)
        print("[BLOCK] NO VERDICT -- VirusTotal analyzer returned unparsable output.")
        return 2
    if r.returncode != 0 or report.get("error"):
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- VirusTotal analyzer failed: {report.get('error', 'error')}")
        return 2
    return virustotal_verdict(report)


def sandbox_allow_list(allow_hosts=()) -> set:
    """Registries + AGENT_GUARD_SANDBOX_ALLOW (comma list) + --allow-host."""
    extra = [h for h in os.environ.get("AGENT_GUARD_SANDBOX_ALLOW", "").split(",") if h.strip()]
    try:
        return _egress.parse_allow([*_egress.DEFAULT_ALLOW, *extra, *allow_hosts])
    except ValueError as exc:
        die(str(exc))


def run_sandbox(command: list, *, allow_hosts=(), network: bool = True) -> int:
    """Keep the trusted Cisco analyzer on the host; only the target runs in Docker.

    Scanner API credentials never enter the target container or Docker argv.
    The target has no host bind mounts. By default it shares the network
    namespace of a capture container: it can reach the package registries it
    needs to start, and every other DNS lookup or connection is reported and
    blocks the verdict (see _egress). network=False runs it with no network.
    """
    need_mcp_scanner()
    if not command:
        die("sandbox scan needs a launch command")
    if shutil.which("docker") is None:
        die("--sandbox needs Docker, which was not found on PATH.")
    problem = cisco_llm_problem()
    if problem:
        die(f"sandbox scan needs a Cisco runtime LLM: {problem}")
    allow = sandbox_allow_list(allow_hosts) if network else set()
    image = build_sandbox_image()

    capture = None
    if network:
        try:
            capture = _egress.Capture.start()
        except (_egress.CaptureError, OSError, subprocess.TimeoutExpired) as exc:
            print("\n" + "=" * 60)
            print(f"[BLOCK] NO VERDICT -- network capture could not start ({exc}). "
                  "Do NOT install. Fix Docker or re-run with --no-network for a "
                  "command that needs no downloads.")
            return 2
        net = f"container:{capture.name}"
        print(f"  network: capture on, allowed: {', '.join(sorted(f'{h}:{p}' for h, p in allow))}")
    else:
        net = "none"
        print("  network: none (--no-network)")

    container = "agent-guard-scan-" + uuid.uuid4().hex
    docker = [
        "run", "--rm", "-i", "--name", container,
        "--network", net, "--read-only", "--tmpfs", "/tmp:exec",
        "--user", "1000:1000", "--security-opt", "no-new-privileges",
        _egress.NO_CAPABILITIES, "--pids-limit", "256",
        "-e", "HOME=/tmp", "-e", "UV_CACHE_DIR=/tmp/uvcache",
        # Launchers must not reach for hosts outside the allow list on their
        # own: uv would fetch a Python build from GitHub, npm checks for updates.
        "-e", "UV_PYTHON_DOWNLOADS=never",
        "-e", "NPM_CONFIG_UPDATE_NOTIFIER=false", "-e", "NO_UPDATE_NOTIFIER=1",
        image, *command,
    ]
    env = cisco_env()
    env["MCP_SCANNER_STDIO_TIMEOUT"] = str(STDIO_TIMEOUT)
    scan = [*cisco_command(env), "--format", "summary", "--analyzers", CISCO_ANALYZERS,
            "stdio", "--stdio-command", "docker"]
    scan.extend(f"--stdio-arg={arg}" for arg in docker)
    finished = False
    try:
        rc = run_cisco(scan,
            "Stage 2: host analyzer with isolated Docker target (no scanner credentials in target)",
            env=env)
        finished = True
    finally:
        # A timed-out analyzer may leave its child alive. Remove only this
        # invocation's uniquely named container, including on failed handshakes.
        # A failed cleanup must not replace the scan result or leave the capture
        # container behind; say so instead.
        try:
            subprocess.run(["docker", "rm", "--force", container],
                           capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"[WARN] could not remove sandbox container {container}: {exc}. "
                  "Remove it manually (docker rm --force).", file=sys.stderr)
        if capture is not None and not finished:
            capture.remove()
    if capture is not None:
        rc = combine_verdicts(rc, _egress.verdict(capture.finish(allow)))
    return rc


def sandbox_image() -> str:
    digest = hashlib.sha256(SANDBOX_DOCKERFILE.encode("utf-8")).hexdigest()[:12]
    return f"{DOCKER_IMAGE}:{digest}"


def build_sandbox_image() -> str:
    tag = sandbox_image()
    have = subprocess.run(["docker", "image", "inspect", tag],
                          capture_output=True, text=True)
    if have.returncode == 0:
        return tag
    print("  building Docker sandbox image (one-time)...")
    # uv/uvx and node/npx launch the target MCP. HOME is moved to the tmpfs at
    # runtime because the container root is read-only.
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "Dockerfile").write_text(SANDBOX_DOCKERFILE, encoding="utf-8")
        r = subprocess.run(["docker", "build", "-t", tag, d])
        if r.returncode != 0:
            die("Docker sandbox image build failed.")
    return tag


def _shquote(s: str) -> str:
    return s if s and all(c.isalnum() or c in "-_./@" for c in s) else repr(s)


def _summary_int(output: str, key: str):
    """Pull an integer that follows `key:` in the scanner summary, or None."""
    found = []
    for line in output.splitlines():
        low = line.lower().strip()
        if low.startswith(key):
            try:
                found.append(int(line.split(":", 1)[1]))
            except (ValueError, IndexError):
                return None
    # A repeated line is ambiguous: no value rather than the first one.
    return found[0] if len(found) == 1 else None


def _summary_line_count(output: str, key: str) -> int:
    return sum(1 for line in output.splitlines() if line.lower().strip().startswith(key))


def verdict(output: str, code: int) -> int:
    """Turn an mcp-scanner (Cisco) summary into a clear verdict. Fail closed.

    Used by the runtime paths (remote + Stage 2 sandbox stdio)."""
    print("\n" + "=" * 60)
    lowered = output.lower()
    unsafe = _summary_int(output, "unsafe items:")
    tools = _summary_int(output, "total tools scanned:")

    llm_failure_markers = (
        "llm analysis failed",
        "llm api error",
        "litellm.authenticationerror",
        "authenticationerror:",
        "rate_limit_exceeded",
        "invalid_api_key",
    )
    if any(marker in lowered for marker in llm_failure_markers):
        print("[BLOCK] NO VERDICT -- Cisco LLM analysis failed. Do NOT install. "
              "Fix MCP_SCANNER_LLM_* and re-run the scan.")
        return 2

    # Scanner crashed and produced no parsable counts -> no verdict.
    if code != 0 and not (unsafe is not None and unsafe > 0):
        print("[BLOCK] NO VERDICT -- scanner errored. Do NOT install. Re-run the scan.")
        return 2

    # Source scan found nothing to analyse (tools defined dynamically, or the
    # analyzer can't see them statically). NOT a clean bill of health.
    if (tools is None or tools <= 0) and not unsafe:
        print("[WARN] INCONCLUSIVE -- the live scan found no analyzable tools. "
              "That is not a safety guarantee; the server may register tools "
              "differently or fail to start. Review manually before installing.")
        return 2

    if unsafe is None:
        print("[WARN] NO VERDICT -- could not parse scanner output. Review manually "
              "before installing.")
        return 2
    # Since 4.8.5 an analyzer that crashed leaves its item at is_safe=None,
    # listed as "Incomplete items: N". Unchecked is not clean.
    incomplete = _summary_int(output, "incomplete items:")
    if unsafe == 0 and incomplete is None and _summary_line_count(output, "incomplete items:"):
        print("[BLOCK] NO VERDICT -- the 'Incomplete items' line is unreadable or "
              "repeated. Do NOT install. Re-run the scan.")
        return 2
    if unsafe == 0 and incomplete:
        print(f"[BLOCK] NO VERDICT -- {incomplete} item(s) not fully analyzed (an "
              "analyzer failed, see above). Do NOT install. Re-run the scan.")
        return 2
    if unsafe == 0:
        extra = f" ({tools} tool(s) checked)" if tools else ""
        print(f"[SAFE] -- no unsafe items{extra}. Installation reasonable.")
        return 0
    print(f"[BLOCK] {unsafe} UNSAFE item(s) found -- review the findings above before "
          "installing. Do not install on a whim.")
    return 1


def virustotal_verdict(report: dict) -> int:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    findings = report.get("findings") or []
    print("\n" + "=" * 60)
    print("VirusTotal summary:")
    for key in ("total_found", "total_to_scan", "scanned", "clean", "malicious",
                "suspicious", "not_found", "throttled", "failed", "skipped_by_limit"):
        if key in summary:
            print(f"  {key}: {summary[key]}")
    scan_date = summary.get("scan_date")
    if isinstance(scan_date, (int, float)):
        import time
        age_days = (time.time() - scan_date) / 86400
        print(f"  last VirusTotal analysis: {time.strftime('%Y-%m-%d', time.gmtime(scan_date))} "
              f"({age_days:.0f} days ago)")
        if age_days > VT_STALE_DAYS:
            print(f"  NOTE: that report is older than {VT_STALE_DAYS} days -- engines "
                  "updated since then were not applied. Re-analyse on virustotal.com "
                  "if in doubt.")

    if findings:
        for finding in findings:
            print(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('summary', '')}")
            permalink = (finding.get("details") or {}).get("permalink")
            if permalink:
                print(f"  {permalink}")
        print("\n[BLOCK] VirusTotal flagged one or more files. Do not install.")
        return 1

    # An absent or malformed summary is not a clean report (bool is not an int here).
    total = summary.get("total_to_scan")
    if not summary or type(total) is not int or total < 0:
        print("\n[WARN] NO VERDICT -- the VirusTotal summary is missing or malformed. "
              "Re-run the scan.")
        return 2
    if total > 0:
        # Absent "malicious" has always meant none; the other counts must be present.
        counts = [summary.get("scanned"), summary.get("clean"), summary.get("malicious", 0)]
        scanned, clean, malicious = counts
        if any(type(c) is not int or c < 0 for c in counts):
            print("\n[WARN] NO VERDICT -- the VirusTotal summary is incomplete or has "
                  "invalid counts. Re-run the scan.")
            return 2
        if malicious:
            print("\n[BLOCK] VirusTotal counts malicious file(s). Do not install.")
            return 1

    # agent-guard counts the checkable files itself (the helper adds the count to
    # every directory summary). Cisco must have counted at least as many.
    eligible = summary.get("agent_guard_eligible")
    if eligible is not None or total == 0:
        found = summary.get("total_found", total)
        if type(eligible) is not int or eligible < 0:
            print("\n[WARN] NO VERDICT -- the VirusTotal summary has no valid count of "
                  "checkable files. Re-run the scan.")
            return 2
        if type(found) is not int or eligible > found:
            print(f"\n[WARN] NO VERDICT -- {eligible} file(s) could be checked, but "
                  f"VirusTotal looked at {found if type(found) is int else 0}. Cisco "
                  "skips files under dot directories and __pycache__, symlinks and "
                  "files whose type it cannot tell; those files were not checked. "
                  "Review them manually.")
            return 2

    if total == 0:
        print("\nNOTE: no file was eligible for a VirusTotal check, so there is "
              "nothing to report.")

    if summary.get("failed", 0) or summary.get("throttled", 0):
        print("\n[WARN] INCONCLUSIVE -- some VirusTotal lookups failed or were throttled.")
        return 2
    if summary.get("not_found", 0):
        print(f"\n[WARN] NO VERDICT -- VirusTotal has never seen {summary['not_found']} "
              "file(s). Unknown is not clean: a new or targeted payload looks exactly "
              "like this. Review manually.")
        return 2
    if summary.get("suspicious", 0):
        print("\n[WARN] NO VERDICT -- VirusTotal engines rate a file suspicious. "
              "Review the report manually.")
        return 2
    # Cisco's directory scan counts a suspicious-only file as scanned but neither
    # clean nor malicious; any such gap is an unexplained result.
    if total > 0 and (summary["scanned"] < 1
                      or summary["clean"] + summary.get("malicious", 0) != summary["scanned"]
                      or summary["clean"] != total):
        print("\n[WARN] NO VERDICT -- the VirusTotal counts do not add up (not every "
              "checked file came back clean). Review manually.")
        return 2
    if summary.get("skipped_by_limit", 0):
        print(f"\n[WARN] NO VERDICT -- {summary['skipped_by_limit']} file(s) were not "
              "checked (file limit). Raise MCP_SCANNER_VT_MAX_FILES or review manually.")
        return 2

    print("\n[SAFE] VirusTotal found no known-malicious files in the checked set.")
    return 0


# -- CLI -----------------------------------------------------------------------

def _split_launch_command(argv: list) -> tuple:
    """Split the sandbox launch command off at the first `--`.

    argparse (with subparsers) mishandles `--` before a trailing positional
    list: it either rejects the tokens or misassigns them. Splitting before
    parse_args keeps `pypi <pkg> --sandbox -- uvx <pkg>` working as
    documented."""
    if "--" in argv:
        split = argv.index("--")
        return argv[:split], argv[split + 1:]
    return argv, []


def _add_network_options(sp):
    sp.add_argument("--allow-host", action="append", default=[], metavar="HOST[:PORT]",
                    help="sandbox and (pypi/npm) dynamic analysis: also allow this "
                         "destination (default port 443; the package registries are "
                         "always allowed). Repeatable; AGENT_GUARD_SANDBOX_ALLOW=h1,h2 "
                         "adds more for the sandbox")
    sp.add_argument("--no-network", action="store_true",
                    help="sandbox: run the target without any network "
                         "(only for commands that need no downloads)")


def main():
    p = argparse.ArgumentParser(
        description="Scan an MCP server for malicious code before installing it.")
    sub = p.add_subparsers(dest="mode", required=True)

    for m, helptext in [("pypi", "PyPI package (fetch sdist, scan source)"),
                        ("npm", "npm package (fetch tarball, scan source)")]:
        sp = sub.add_parser(m, help=helptext)
        sp.add_argument("package", help="package name, optionally with version")
        sp.add_argument("--sandbox", action="store_true",
                        help="Stage 2: also run a live stdio scan in Docker")
        sp.add_argument("command", nargs="*",
                        help="after `--`: the launch command for the sandbox "
                             "scan, e.g. -- uvx package-name")
        _add_network_options(sp)
        sp.add_argument("--no-dynamic", action="store_true",
                        help="skip the dynamic install analysis (Stage 1b, needs Docker); "
                             "the result is NO VERDICT unless AGENT_GUARD_STATIC_ONLY=1")

    sp = sub.add_parser("local", help="scan a local MCP source directory")
    sp.add_argument("path")

    sp = sub.add_parser("remote", help="scan a running remote MCP by URL")
    sp.add_argument("url")

    sp = sub.add_parser("virustotal", help="VirusTotal hash reputation scan")
    sp.add_argument("path")
    sp.add_argument("--max-files", type=int, default=VT_MAX_FILES,
                    help="max scannable files to query (default: MCP_SCANNER_VT_MAX_FILES or 10)")

    sp = sub.add_parser("sandbox", help="Stage 2 only: live stdio scan in Docker")
    sp.add_argument("command", nargs="*",
                    help="launch command, e.g. uvx package (optionally after `--`)")
    _add_network_options(sp)

    argv, launch_command = _split_launch_command(sys.argv[1:])
    args = p.parse_args(argv)

    if args.mode in ("pypi", "npm"):
        command = launch_command or args.command
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)
            print(f"-- Stage 1: source scan of {args.package} (no execution) --")
            (fetch_pypi if args.mode == "pypi" else fetch_npm)(args.package, dest)
            rc = run_skillspector(dest)
        if args.no_dynamic:
            rc = combine_verdicts(rc, skipped_dynamic_verdict())
        else:
            print("\n-- Stage 1b: dynamic install analysis (OpenSSF sandbox) --")
            rc = combine_verdicts(rc, _dynamic.run(args.mode, args.package, allow_hosts=args.allow_host))
        if args.sandbox:
            if not command:
                die("--sandbox needs a launch command after `--`, "
                    "e.g. -- uvx package-name")
            print("\n-- Stage 2: live runtime scan in Docker sandbox --")
            rc = combine_verdicts(rc, run_sandbox(command, allow_hosts=args.allow_host,
                                                 network=not args.no_network))
        sys.exit(rc)

    if args.mode == "local":
        sys.exit(run_skillspector(Path(args.path)))
    if args.mode == "remote":
        sys.exit(run_remote(args.url))
    if args.mode == "virustotal":
        sys.exit(run_virustotal(Path(args.path), args.max_files))
    if args.mode == "sandbox":
        command = launch_command or args.command
        if not command:
            die("sandbox scan needs a launch command, e.g. sandbox uvx package-name")
        sys.exit(run_sandbox(command, allow_hosts=args.allow_host,
                             network=not args.no_network))


if __name__ == "__main__":
    import _console

    _console.utf8_stdio()
    main()
