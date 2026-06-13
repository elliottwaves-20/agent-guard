#!/usr/bin/env python3
"""
MCP server security scanner -- scan first, install after (for MCP servers).

Unlike skills (plain Markdown + scripts that are only *read*), an MCP server is
code that must *run* to expose its tools. That makes naive "scan by starting it"
unsafe: a malicious server can act during startup, before anything is analysed.
This wrapper enforces the safe order:

  Stage 1 (default, NO execution): fetch the package source straight from the
    registry (PyPI sdist / npm tarball) with urllib -- never pip/uvx/npm install --
    and run `mcp-scanner behavioral` on the source. Nothing from the package runs.

  Stage 2 (optional, --sandbox): run the live `mcp-scanner stdio` scan inside a
    throwaway Docker container with no host filesystem access, so the server can
    be started for runtime tool/prompt analysis without touching your machine.

Powered by cisco-ai-mcp-scanner. Stage 1 needs an LLM key (behavioral alignment
is LLM-based); it reads SKILL_SCANNER_LLM_API_KEY (same .env as the skill flow).

Usage:
  python scan_mcp.py pypi  <package>[==version]      # fetch sdist, scan source
  python scan_mcp.py npm   <package>[@version]       # fetch tarball, scan source
  python scan_mcp.py local <path>                    # scan local source dir
  python scan_mcp.py remote <url>                     # scan a running remote MCP
  python scan_mcp.py pypi <pkg> --sandbox -- uvx <pkg>   # Stage 2: stdio in Docker

After a SAFE verdict, install with:
  python install_skill.py mcp --name <n> --command uvx --args <pkg> [...]
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

MCP_SCANNER = shutil.which("mcp-scanner")
LLM_KEY = os.environ.get("SKILL_SCANNER_LLM_API_KEY", "")

# The MCP scanner's LiteLLM model. It defaults to gpt-4o, so an Anthropic key
# without this set fails with an OpenAI auth error. Honor an explicit
# MCP_SCANNER_LLM_MODEL, else derive a sensible model from the key prefix.
LLM_MODEL = os.environ.get("MCP_SCANNER_LLM_MODEL", "")
if not LLM_MODEL and LLM_KEY.startswith("sk-ant-"):
    LLM_MODEL = "anthropic/claude-haiku-4-5-20251001"

DOCKER_IMAGE = "skill-scanner-mcp-sandbox"
# Persistent Docker volume for the in-container uv cache, so a server's heavy
# deps (pandas/numpy/...) are downloaded once, not on every sandbox run. Holds
# only downloaded packages -- no host filesystem is exposed.
CACHE_VOLUME = "skill-scanner-mcp-uvcache"

# Hard cap on a single scanner invocation, so a hanging scan never blocks forever.
# Generous, because the FIRST sandbox run of a heavy server downloads its deps.
SCAN_TIMEOUT = int(os.environ.get("SCAN_MCP_TIMEOUT", "600"))
# How long the scanner waits for a stdio MCP to start. The default (60s) is too
# short for servers whose first `uvx`/`npx` launch must download heavy deps
# (pandas, numpy, ...) inside a fresh container.
STDIO_TIMEOUT = int(os.environ.get("SCAN_MCP_STDIO_TIMEOUT", "240"))


def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def need_scanner():
    if MCP_SCANNER is None:
        die("cisco-ai-mcp-scanner not found on PATH. Run setup.sh / setup.ps1 first.")


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


# -- scanning -----------------------------------------------------------------

def scanner_env() -> dict:
    """os.environ plus the resolved LLM model, so the scanner's LiteLLM picks
    the right provider instead of its gpt-4o default."""
    e = dict(os.environ)
    if LLM_MODEL:
        e["MCP_SCANNER_LLM_MODEL"] = LLM_MODEL
    return e


def run_scanner(cmd: list, label: str, env: dict = None) -> int:
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


def run_behavioral(src: Path) -> int:
    need_scanner()
    if not LLM_KEY:
        die("behavioral source scan needs an LLM key. Set SKILL_SCANNER_LLM_API_KEY "
            "in .env and `source` it before scanning.")
    cmd = [MCP_SCANNER, "--llm-api-key", LLM_KEY, "behavioral", str(src),
           "--format", "summary"]
    return run_scanner(cmd, f"scanning source (no execution): {src}",
                       env=scanner_env())


def run_remote(url: str) -> int:
    need_scanner()
    cmd = [MCP_SCANNER, "remote", "--server-url", url, "--format", "summary"]
    if LLM_KEY:
        cmd[1:1] = ["--llm-api-key", LLM_KEY]
    return run_scanner(cmd, f"scanning remote MCP (no local code runs): {url}",
                       env=scanner_env())


def run_sandbox(command: list) -> int:
    """Stage 2: run the live stdio scan inside a throwaway Docker container.

    The container gets NO host filesystem mount, a non-root user, and a
    read-only root with tmpfs. Network stays ON because the behavioral
    analyser needs the LLM API -- so the threat we contain is host-filesystem
    access (SSH keys, .env, documents), not all egress.
    """
    if shutil.which("docker") is None:
        die("--sandbox needs Docker, which was not found on PATH.")
    if not LLM_KEY:
        die("sandbox scan needs SKILL_SCANNER_LLM_API_KEY in the environment.")
    build_sandbox_image()
    ensure_cache_volume()
    inner = " ".join(_shquote(c) for c in command)
    # `mcp-scanner` here is the binary *inside* the container (on its PATH).
    # --format is a GLOBAL flag and must precede the `stdio` subcommand.
    # The key is passed via MCP_SCANNER_LLM_API_KEY (env) rather than the
    # --llm-api-key flag: the latter hits an UnboundLocalError in the scanner's
    # stdio path (cli.py), while the env var is read cleanly.
    # Live (stdio) analysis uses yara (local signatures) + llm (semantic
    # analysis of the running server's tools/prompts). The behavioral analyzer
    # is source-only (Stage 1) and rejects stdio; api/virustotal need paid keys.
    # Both the LLM key and the stdio timeout are passed as ENV VARS, never as
    # CLI flags: every flag the scanner copies into os.environ inside main()
    # (--llm-api-key, --stdio-timeout) hits an UnboundLocalError there. The env
    # vars are read cleanly. STDIO_TIMEOUT raises the 60s default so a fresh
    # container has time to download a server's deps (pandas/numpy/...) first.
    scan = ["mcp-scanner", "--format", "summary",
            "--analyzers", "yara,llm",
            "stdio", "--stdio-command", command[0]]
    for a in command[1:]:
        scan += ["--stdio-arg", a]

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
        "-e", f"MCP_SCANNER_LLM_API_KEY={LLM_KEY}",
        "-e", f"MCP_SCANNER_LLM_MODEL={LLM_MODEL}",
        "-e", f"MCP_SCANNER_STDIO_TIMEOUT={STDIO_TIMEOUT}",
        DOCKER_IMAGE,
        "sh", "-c", script,
    ]
    return run_scanner(
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
        "nodejs npm curl ca-certificates && rm -rf /var/lib/apt/lists/*\n"
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
    """Turn mcp-scanner summary into a clear verdict. Fail closed."""
    print("\n" + "=" * 60)
    unsafe = _summary_int(output, "unsafe items:")
    tools = _summary_int(output, "total tools scanned:")

    # Scanner crashed and produced no parsable counts -> no verdict.
    if code != 0 and unsafe is None:
        print("[BLOCK] NO VERDICT -- scanner errored. Do NOT install. Re-run the scan.")
        return 2

    # Source scan found nothing to analyse (tools defined dynamically, or the
    # analyzer can't see them statically). NOT a clean bill of health.
    if tools == 0 and not unsafe:
        print("[WARN] INCONCLUSIVE -- the source scan found no analyzable tools in "
              "this package. That is not a safety guarantee; the tools may be "
              "registered dynamically. Run a live check with --sandbox before "
              "installing.")
        return 2

    if unsafe is None:
        print("[WARN] NO VERDICT -- could not parse scanner output. Review manually "
              "before installing.")
        return 2
    if unsafe == 0:
        extra = f" ({tools} tool(s) checked)" if tools else ""
        print(f"[SAFE] -- no unsafe items{extra}. Installation reasonable.\n"
              "   Reminder: a clean source scan does not prove runtime safety. "
              "Use --sandbox for a live check if in doubt.")
        return 0
    print(f"[BLOCK] {unsafe} UNSAFE item(s) found -- review the findings above before "
          "installing. Do not install on a whim.")
    return 1


# -- CLI -----------------------------------------------------------------------

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

    sp = sub.add_parser("sandbox", help="Stage 2 only: live stdio scan in Docker")
    sp.add_argument("command", nargs="+", help="launch command, e.g. uvx package")

    args = p.parse_args()

    if args.mode in ("pypi", "npm"):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)
            print(f"-- Stage 1: source scan of {args.package} (no execution) --")
            (fetch_pypi if args.mode == "pypi" else fetch_npm)(args.package, dest)
            rc = run_behavioral(dest)
        if args.sandbox:
            if not args.command:
                die("--sandbox needs a launch command after `--`, "
                    "e.g. -- uvx package-name")
            print("\n-- Stage 2: live runtime scan in Docker sandbox --")
            rc = max(rc, run_sandbox(args.command))
        sys.exit(rc)

    if args.mode == "local":
        sys.exit(run_behavioral(Path(args.path)))
    if args.mode == "remote":
        sys.exit(run_remote(args.url))
    if args.mode == "sandbox":
        sys.exit(run_sandbox(args.command))


if __name__ == "__main__":
    main()
