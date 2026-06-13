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
DOCKER_IMAGE = "skill-scanner-mcp-sandbox"


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

def run_behavioral(src: Path) -> int:
    need_scanner()
    if not LLM_KEY:
        die("behavioral source scan needs an LLM key. Set SKILL_SCANNER_LLM_API_KEY "
            "in .env and `source` it before scanning.")
    cmd = [MCP_SCANNER, "--llm-api-key", LLM_KEY, "behavioral", str(src),
           "--format", "summary"]
    print(f"  scanning source (no execution): {src}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    print(out)
    return verdict(out, r.returncode)


def run_remote(url: str) -> int:
    need_scanner()
    cmd = [MCP_SCANNER, "remote", "--server-url", url, "--format", "summary"]
    if LLM_KEY:
        cmd[1:1] = ["--llm-api-key", LLM_KEY]
    print(f"  scanning remote MCP (no local code runs): {url}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    print((r.stdout or "") + (r.stderr or ""))
    return verdict((r.stdout or "") + (r.stderr or ""), r.returncode)


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
    inner = " ".join(_shquote(c) for c in command)
    # `mcp-scanner` here is the binary *inside* the container (on its PATH).
    # --format is a GLOBAL flag and must precede the `stdio` subcommand.
    # The key is passed via MCP_SCANNER_LLM_API_KEY (env) rather than the
    # --llm-api-key flag: the latter hits an UnboundLocalError in the scanner's
    # stdio path (cli.py), while the env var is read cleanly.
    # Live (stdio) analysis uses yara (local signatures) + llm (semantic
    # analysis of the running server's tools/prompts). The behavioral analyzer
    # is source-only (Stage 1) and rejects stdio; api/virustotal need paid keys.
    scan = ["mcp-scanner", "--format", "summary",
            "--analyzers", "yara,llm",
            "stdio", "--stdio-command", command[0]]
    for a in command[1:]:
        scan += ["--stdio-arg", a]
    docker = [
        "docker", "run", "--rm",
        "--network", "bridge",            # needed for the LLM API call
        "--read-only", "--tmpfs", "/tmp:exec",
        "--user", "1000:1000",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        # container root is read-only; give uv/uvx and the MCP a writable HOME
        # on the tmpfs so they can cache and spawn
        "-e", "HOME=/tmp",
        "-e", "UV_CACHE_DIR=/tmp/uv",
        "-e", f"MCP_SCANNER_LLM_API_KEY={LLM_KEY}",
        DOCKER_IMAGE,
    ] + scan
    print(f"  Stage 2: live stdio scan of `{inner}` inside Docker sandbox "
          "(no host filesystem access)")
    r = subprocess.run(docker, capture_output=True, text=True)
    print((r.stdout or "") + (r.stderr or ""))
    return verdict((r.stdout or "") + (r.stderr or ""), r.returncode)


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


def verdict(output: str, code: int) -> int:
    """Parse mcp-scanner summary into a clear verdict. Fail closed."""
    print("\n" + "=" * 60)
    unsafe = None
    for line in output.splitlines():
        low = line.lower().strip()
        if low.startswith("unsafe items:"):
            try:
                unsafe = int(line.split(":")[1])
            except ValueError:
                pass
    if code != 0 and unsafe is None:
        print("[BLOCK] NO VERDICT -- scanner errored. Do NOT install. Re-run the scan.")
        return 2
    if unsafe is None:
        print("[WARN] NO VERDICT -- could not parse scanner output. Review manually "
              "before installing.")
        return 2
    if unsafe == 0:
        print("[SAFE] -- no unsafe items. Installation reasonable.\n"
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
