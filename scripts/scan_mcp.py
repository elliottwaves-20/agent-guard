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

  Stage 2 (optional, --sandbox): run the live `mcp-scanner stdio` scan inside a
    throwaway Docker container with no host filesystem access, so the server can
    be started for runtime tool/prompt analysis without touching your machine.
    This is the one thing a static scan cannot do: see MCP tools that are only
    registered at runtime. Powered by cisco-ai-mcp-scanner.

LLM analysis is optional. Stage 1 uses SkillSpector's provider config
(SKILLSPECTOR_*; by default a coding-agent CLI such as claude_cli, no API key),
while Stage 2 / remote uses Cisco mcp-scanner's LiteLLM config
(MCP_SCANNER_LLM_*, API key required -- Cisco has no CLI-subscription path).
Without any usable SkillSpector provider, Stage 1 runs static-only (--no-llm).

Usage:
  python scan_mcp.py pypi  <package>[==version]      # fetch sdist, scan source
  python scan_mcp.py npm   <package>[@version]       # fetch tarball, scan source
  python scan_mcp.py local <path>                    # scan local source dir
  python scan_mcp.py remote <url>                     # scan a running remote MCP
  python scan_mcp.py virustotal <path>                # hash reputation check
  python scan_mcp.py pypi <pkg> --sandbox -- uvx <pkg>   # Stage 2: stdio in Docker

After a SAFE verdict, install with:
  python install_skill.py mcp --name <n> --command uvx --arg <pkg> [...]
"""

import argparse
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
from pathlib import Path

from _skillspector import (
    SCAN_TIMEOUT,
    die,
    run_skillspector as shared_run_skillspector,
)

MCP_SCANNER = shutil.which("mcp-scanner")      # Stage 2 / remote: runtime (Cisco)


CISCO_LLM_KEY = os.environ.get("MCP_SCANNER_LLM_API_KEY", "").strip()
CISCO_LLM_MODEL = os.environ.get("MCP_SCANNER_LLM_MODEL", "").strip()
CISCO_LLM_BASE_URL = os.environ.get("MCP_SCANNER_LLM_BASE_URL", "").strip()
CISCO_LLM_API_VERSION = os.environ.get("MCP_SCANNER_LLM_API_VERSION", "").strip()


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


def cisco_env() -> dict:
    """Environment for the Cisco MCP scanner: hand it the LiteLLM model + base
    URL so its LiteLLM uses the configured runtime provider instead of its
    default. The key is passed via environment, not CLI args, so it does not
    show up in process listings and avoids mcp-scanner CLI flag regressions."""
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
# Persistent Docker volume for the in-container uv cache, so a server's heavy
# deps (pandas/numpy/...) are downloaded once, not on every sandbox run. Holds
# only downloaded packages -- no host filesystem is exposed.
CACHE_VOLUME = "agent-guard-mcp-uvcache"

# How long the scanner waits for a stdio MCP to start. The default (60s) is too
# short for servers whose first `uvx`/`npx` launch must download heavy deps
# (pandas, numpy, ...) inside a fresh container.
STDIO_TIMEOUT = int(os.environ.get("SCAN_MCP_STDIO_TIMEOUT", "240"))
VT_MAX_FILES = int(os.environ.get("MCP_SCANNER_VT_MAX_FILES", "10"))

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

if target.is_file():
    finding = analyzer.analyze_file(str(target))
    findings = [finding] if finding else []
    summary = {
        "total_found": 1,
        "total_to_scan": 1,
        "scanned": 1,
        "clean": 0 if finding else 1,
        "malicious": 1 if finding else 0,
        "not_found": 0,
        "throttled": 0,
        "failed": 0,
        "skipped_by_limit": 0,
    }
elif target.is_dir():
    findings = analyzer.analyze_directory(str(target))
    summary = analyzer.last_scan_summary
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
            if not str(p).startswith(str(dest.resolve())):
                die(f"unsafe path in archive: {m.name}")
            if m.issym() or m.islnk():
                die(f"archive contains a link ({m.name}); refusing to extract")
        tf.extractall(dest)


def safe_extract_zip(data: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            p = (dest / name).resolve()
            if not str(p).startswith(str(dest.resolve())):
                die(f"unsafe path in archive: {name}")
        zf.extractall(dest)


# -- source acquisition (NO package code executed) ----------------------------

def fetch_pypi(spec: str, dest: Path) -> Path:
    name, _, version = spec.partition("==")
    meta = http_json(f"https://pypi.org/pypi/{name}/json")
    version = version or meta["info"]["version"]
    files = meta.get("releases", {}).get(version) or meta["urls"]
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    if not sdists:
        die(f"{name}=={version} has no source distribution (sdist) on PyPI -- "
            "cannot scan source without executing a wheel. Try --sandbox instead.")
    url = sdists[0]["url"]
    print(f"  fetching sdist: {url}")
    safe_extract_tar(http_bytes(url), dest)
    return dest


def fetch_npm(spec: str, dest: Path) -> Path:
    if spec.startswith("@"):
        scope_name, _, version = spec[1:].partition("@")
        name, version = "@" + scope_name, version
    else:
        name, _, version = spec.partition("@")
    meta = http_json(f"https://registry.npmjs.org/{name}")
    version = version or meta.get("dist-tags", {}).get("latest")
    ver = meta["versions"][version]
    url = ver["dist"]["tarball"]
    print(f"  fetching npm tarball: {url}")
    safe_extract_tar(http_bytes(url), dest)
    return dest


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
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=SCAN_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
              "install. The server may hang on start, or its dependencies are too "
              "slow to fetch. Raise SCAN_MCP_TIMEOUT or review manually.")
        return 2
    out = (r.stdout or "") + (r.stderr or "")
    print(out)
    return verdict(out, r.returncode)


def run_remote(url: str) -> int:
    need_mcp_scanner()
    cmd = [MCP_SCANNER, "--format", "summary", "remote", "--server-url", url]
    return run_cisco(cmd, f"scanning remote MCP (no local code runs): {url}",
                     env=cisco_env())


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
    r = subprocess.run(
        [python, "-c", VT_HELPER, str(path), str(max_files)],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT,
        env=dict(os.environ),
    )
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


def run_sandbox(command: list) -> int:
    """Stage 2: run the live stdio scan inside a throwaway Docker container.

    The container gets NO host filesystem mount, a non-root user, and a
    read-only root with tmpfs. Network stays ON because the behavioral
    analyser needs the LLM API -- so the threat we contain is host-filesystem
    access (SSH keys, .env, documents), not all egress.
    """
    need_mcp_scanner()
    if shutil.which("docker") is None:
        die("--sandbox needs Docker, which was not found on PATH.")
    if not CISCO_LLM_KEY:
        die("sandbox scan needs a Cisco runtime LLM key. Configure "
            "MCP_SCANNER_LLM_API_KEY + MCP_SCANNER_LLM_MODEL in .env.")
    validate_cisco_llm_config()
    build_sandbox_image()
    ensure_cache_volume()
    inner = " ".join(_shquote(c) for c in command)
    # `mcp-scanner` here is the binary *inside* the container (on its PATH).
    # --format is a GLOBAL flag and must precede the `stdio` subcommand.
    # Live (stdio) analysis uses yara (local signatures) + llm (semantic
    # analysis of the running server's tools/prompts). The behavioral analyzer
    # is source-only and rejects stdio; api needs Cisco AI Defense access, while
    # VirusTotal is handled by this wrapper's separate `virustotal` mode.
    # Both the LLM key and the stdio timeout are passed as ENV VARS, never as
    # CLI flags: every flag the scanner copies into os.environ inside main()
    # (--llm-api-key, --stdio-timeout) hits an UnboundLocalError there. The env
    # vars are read cleanly. STDIO_TIMEOUT raises the 60s default so a fresh
    # container has time to download a server's deps (pandas/numpy/...) first.
    scan = ["mcp-scanner", "--format", "summary",
            "--analyzers", "yara,llm",
            "stdio", "--stdio-command", command[0]]
    for a in command[1:]:
        scan.append(f"--stdio-arg={a}")

    # Pre-fetch the server and its deps BEFORE the scan, in the same container.
    # A heavy server (pandas/numpy/...) can take minutes to download on its first
    # `uvx`/`npx` launch -- longer than the scanner's stdio handshake timeout.
    # Running the launch command once with stdin closed warms the uv cache and
    # Python imports (the server reads stdin, gets EOF, exits), so the real scan
    # connects fast. Combined with the persistent cache volume, later runs skip
    # the download entirely.
    launch = " ".join(shlex.quote(c) for c in command)
    scan_str = " ".join(shlex.quote(c) for c in scan)
    script = (
        f'echo "[sandbox] pre-fetching server + deps (first run can be slow)..." >&2; '
        f'timeout {STDIO_TIMEOUT} {launch} </dev/null >/dev/null 2>&1 || true; '
        f'echo "[sandbox] running live scan..." >&2; '
        f'{scan_str}'
    )
    docker = [
        "docker", "run", "--rm",
        "--network", "bridge",            # needed for the LLM API call
        "--read-only", "--tmpfs", "/tmp:exec",
        "--user", "1000:1000",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        # container root is read-only; give uv/uvx and the MCP a writable HOME
        # on the tmpfs, and a PERSISTENT volume for the uv cache so heavy deps
        # download once across runs (the volume holds only packages, not host fs)
        "-v", f"{CACHE_VOLUME}:/uvcache",
        "-e", "HOME=/tmp",
        "-e", "UV_CACHE_DIR=/uvcache",
        "-e", f"MCP_SCANNER_LLM_API_KEY={CISCO_LLM_KEY}",
        "-e", f"MCP_SCANNER_LLM_MODEL={CISCO_LLM_MODEL}",
        "-e", f"MCP_SCANNER_STDIO_TIMEOUT={STDIO_TIMEOUT}",
    ]
    cisco_key_kind = _llm_key_kind(CISCO_LLM_KEY)
    if cisco_key_kind == "anthropic":
        docker += ["-e", f"ANTHROPIC_API_KEY={CISCO_LLM_KEY}"]
    elif cisco_key_kind == "openai":
        docker += ["-e", f"OPENAI_API_KEY={CISCO_LLM_KEY}"]
    if CISCO_LLM_BASE_URL:
        docker += ["-e", f"MCP_SCANNER_LLM_BASE_URL={CISCO_LLM_BASE_URL}"]
    if CISCO_LLM_API_VERSION:
        docker += ["-e", f"MCP_SCANNER_LLM_API_VERSION={CISCO_LLM_API_VERSION}"]
    docker += [
        DOCKER_IMAGE,
        "sh", "-c", script,
    ]
    return run_cisco(
        docker,
        f"Stage 2: live stdio scan of `{inner}` inside Docker sandbox "
        "(no host filesystem access)")


def ensure_cache_volume():
    """Create the uv cache volume and hand it to the non-root scanner user.

    Docker volumes are created root-owned, but the container runs as uid 1000,
    so without this chown uv cannot write the cache (Permission denied)."""
    subprocess.run(["docker", "volume", "create", CACHE_VOLUME],
                   capture_output=True, text=True)
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{CACHE_VOLUME}:/uvcache",
         "--user", "root", "--entrypoint", "chown", DOCKER_IMAGE,
         "-R", "1000:1000", "/uvcache"],
        capture_output=True, text=True)


def build_sandbox_image():
    have = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                          capture_output=True, text=True)
    if have.returncode == 0:
        return
    print("  building Docker sandbox image (one-time)...")
    # Install system-wide (/usr/local/bin) so the non-root scanner user can run
    # mcp-scanner; uv/uvx ship along to launch the target MCP. HOME is moved to
    # the tmpfs at runtime because the container root is read-only.
    dockerfile = (
        "FROM python:3.12-slim\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        "git nodejs npm curl ca-certificates && rm -rf /var/lib/apt/lists/*\n"
        "RUN pip install --no-cache-dir uv cisco-ai-mcp-scanner\n"
        "RUN useradd -m -u 1000 scanner\n"
        "USER scanner\n"
    )
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        r = subprocess.run(["docker", "build", "-t", DOCKER_IMAGE, d])
        if r.returncode != 0:
            die("Docker sandbox image build failed.")


def _shquote(s: str) -> str:
    return s if s and all(c.isalnum() or c in "-_./@" for c in s) else repr(s)


def _summary_int(output: str, key: str):
    """Pull an integer that follows `key:` in the scanner summary, or None."""
    for line in output.splitlines():
        low = line.lower().strip()
        if low.startswith(key):
            try:
                return int(line.split(":", 1)[1])
            except (ValueError, IndexError):
                return None
    return None


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
    if code != 0 and unsafe is None:
        print("[BLOCK] NO VERDICT -- scanner errored. Do NOT install. Re-run the scan.")
        return 2

    # Source scan found nothing to analyse (tools defined dynamically, or the
    # analyzer can't see them statically). NOT a clean bill of health.
    if tools == 0 and not unsafe:
        print("[WARN] INCONCLUSIVE -- the live scan found no analyzable tools. "
              "That is not a safety guarantee; the server may register tools "
              "differently or fail to start. Review manually before installing.")
        return 2

    if unsafe is None:
        print("[WARN] NO VERDICT -- could not parse scanner output. Review manually "
              "before installing.")
        return 2
    if unsafe == 0:
        extra = f" ({tools} tool(s) checked)" if tools else ""
        print(f"[SAFE] -- no unsafe items{extra}. Installation reasonable.")
        return 0
    print(f"[BLOCK] {unsafe} UNSAFE item(s) found -- review the findings above before "
          "installing. Do not install on a whim.")
    return 1


def virustotal_verdict(report: dict) -> int:
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    print("\n" + "=" * 60)
    print("VirusTotal summary:")
    for key in ("total_found", "total_to_scan", "scanned", "clean", "malicious",
                "not_found", "throttled", "failed", "skipped_by_limit"):
        if key in summary:
            print(f"  {key}: {summary[key]}")

    if findings:
        for finding in findings:
            print(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('summary', '')}")
            permalink = (finding.get("details") or {}).get("permalink")
            if permalink:
                print(f"  {permalink}")
        print("\n[BLOCK] VirusTotal flagged one or more files. Do not install.")
        return 1

    if summary.get("failed", 0) or summary.get("throttled", 0):
        print("\n[WARN] INCONCLUSIVE -- some VirusTotal lookups failed or were throttled.")
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

    argv, launch_command = _split_launch_command(sys.argv[1:])
    args = p.parse_args(argv)

    if args.mode in ("pypi", "npm"):
        command = launch_command or args.command
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)
            print(f"-- Stage 1: source scan of {args.package} (no execution) --")
            (fetch_pypi if args.mode == "pypi" else fetch_npm)(args.package, dest)
            rc = run_skillspector(dest)
        if args.sandbox:
            if not command:
                die("--sandbox needs a launch command after `--`, "
                    "e.g. -- uvx package-name")
            print("\n-- Stage 2: live runtime scan in Docker sandbox --")
            rc = max(rc, run_sandbox(command))
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
        sys.exit(run_sandbox(command))


if __name__ == "__main__":
    main()
