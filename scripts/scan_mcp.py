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

LLM analysis is optional. Configure one provider in .env (SKILLSPECTOR_PROVIDER
+ its key); scan_mcp.py reuses that choice for the Cisco runtime scanner too.
Without a provider, Stage 1 runs static-only (--no-llm).

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

SKILLSPECTOR = shutil.which("skillspector")   # Stage 1: static source scan
MCP_SCANNER = shutil.which("mcp-scanner")      # Stage 2 / remote: runtime (Cisco)


# -- LLM resolution -----------------------------------------------------------
# One provider config drives both scanners. SkillSpector reads its own native
# env (SKILLSPECTOR_PROVIDER + the provider's key var); the Cisco runtime
# scanner wants a LiteLLM `provider/model` id + key. resolve_llm() reads the
# SkillSpector-native variables (with a legacy SKILL_SCANNER_* fallback so an
# older .env keeps working) and the *_env() helpers feed each scanner the shape
# it expects.

def resolve_llm():
    """Return (provider, key, model, base_url) from the configured env.

    Precedence: SkillSpector-native vars, then legacy Cisco SKILL_SCANNER_*.
    If no provider is named, infer it from whichever credential is present.
    """
    provider = (os.environ.get("SKILLSPECTOR_PROVIDER", "")
                or os.environ.get("SKILL_SCANNER_LLM_PROVIDER", "")).strip().lower()
    model = (os.environ.get("SKILLSPECTOR_MODEL", "")
             or os.environ.get("SKILL_SCANNER_LLM_MODEL", "")).strip()
    base = (os.environ.get("OPENAI_BASE_URL", "")
            or os.environ.get("MCP_SCANNER_LLM_BASE_URL", "")
            or os.environ.get("SKILL_SCANNER_LLM_BASE_URL", "")).strip()
    legacy_key = os.environ.get("SKILL_SCANNER_LLM_API_KEY", "").strip()

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or legacy_key
    elif provider in ("openai", "openai-compatible", "custom-openai"):
        provider = "openai"
        key = os.environ.get("OPENAI_API_KEY", "").strip() or legacy_key
    elif provider in ("nv_build", "nv_inference"):
        key = os.environ.get("NVIDIA_INFERENCE_KEY", "").strip() or legacy_key
    else:
        # No provider named -- infer from whichever credential exists.
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider, key = "anthropic", os.environ["ANTHROPIC_API_KEY"].strip()
        elif os.environ.get("OPENAI_API_KEY"):
            provider, key = "openai", os.environ["OPENAI_API_KEY"].strip()
        elif os.environ.get("NVIDIA_INFERENCE_KEY"):
            provider, key = "nv_inference", os.environ["NVIDIA_INFERENCE_KEY"].strip()
        elif legacy_key:
            key = legacy_key
            provider = "anthropic" if legacy_key.startswith("sk-ant-") else "openai"
        else:
            key = ""
    return provider, key, model, base


PROVIDER, LLM_KEY, LLM_MODEL_RAW, LLM_BASE_URL = resolve_llm()


def _to_litellm_model(provider: str, model: str) -> str:
    """Map the resolved provider/model to the LiteLLM `provider/model` id the
    Cisco MCP scanner expects (it defaults to gpt-4o otherwise)."""
    if not model:
        return "anthropic/claude-haiku-4-5-20251001" if provider == "anthropic" else ""
    if "/" in model:
        return model  # already prefixed (ollama/..., anthropic/..., openrouter/...)
    if provider == "openai":
        # gpt-* is native to LiteLLM; a custom OpenAI-compatible model still
        # routes through the openai adapter + base URL.
        return model if model.startswith("gpt-") else f"openai/{model}"
    if provider == "anthropic" or model.startswith("claude"):
        return f"anthropic/{model}"
    return model


# Explicit MCP_SCANNER_LLM_MODEL wins; otherwise derive from the resolved
# provider so Anthropic/OpenAI/Ollama/etc. all work without extra config.
CISCO_LLM_MODEL = (os.environ.get("MCP_SCANNER_LLM_MODEL", "").strip()
                   or _to_litellm_model(PROVIDER, LLM_MODEL_RAW))


def skillspector_llm_usable() -> bool:
    """Whether SkillSpector's LLM layer can actually run with the configured
    provider. Its semantic analyzers request structured outputs whose JSON
    schema (integer/number `minimum`/`maximum`) only SkillSpector's OpenAI and
    NVIDIA providers accept. Anthropic's OpenAI-compatible endpoint rejects that
    schema (HTTP 400), so with Anthropic SkillSpector is run static-only --
    Anthropic still drives the Cisco runtime scan, which uses LiteLLM."""
    return bool(LLM_KEY and PROVIDER in ("openai", "nv_build", "nv_inference"))


def skillspector_env() -> dict:
    """Environment for SkillSpector: force UTF-8 (its rich terminal renderer
    crashes on a legacy Windows cp1252 console) and, when the provider's LLM
    path is usable, expose the provider + key under SkillSpector's native
    variable names."""
    e = dict(os.environ)
    e["PYTHONUTF8"] = "1"
    e["PYTHONIOENCODING"] = "utf-8"
    if skillspector_llm_usable():
        e["SKILLSPECTOR_PROVIDER"] = PROVIDER
        if PROVIDER == "openai":
            e["OPENAI_API_KEY"] = LLM_KEY
            if LLM_BASE_URL:
                e["OPENAI_BASE_URL"] = LLM_BASE_URL
        elif PROVIDER in ("nv_build", "nv_inference"):
            e["NVIDIA_INFERENCE_KEY"] = LLM_KEY
        if LLM_MODEL_RAW:
            e["SKILLSPECTOR_MODEL"] = LLM_MODEL_RAW
    return e


def cisco_env() -> dict:
    """Environment for the Cisco MCP scanner: hand it the LiteLLM model + base
    URL so its LiteLLM uses the configured provider instead of its gpt-4o
    default. (The key itself is passed per-invocation, see below.)"""
    e = dict(os.environ)
    if CISCO_LLM_MODEL:
        e["MCP_SCANNER_LLM_MODEL"] = CISCO_LLM_MODEL
    if LLM_BASE_URL:
        e["MCP_SCANNER_LLM_BASE_URL"] = LLM_BASE_URL
    return e


DOCKER_IMAGE = "agent-guard-mcp-sandbox"
# Persistent Docker volume for the in-container uv cache, so a server's heavy
# deps (pandas/numpy/...) are downloaded once, not on every sandbox run. Holds
# only downloaded packages -- no host filesystem is exposed.
CACHE_VOLUME = "agent-guard-mcp-uvcache"

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


def need_skillspector():
    if SKILLSPECTOR is None:
        die("skillspector not found on PATH. Run setup.sh / setup.ps1 first.")


def need_mcp_scanner():
    if MCP_SCANNER is None:
        die("cisco-ai-mcp-scanner (mcp-scanner) not found on PATH -- needed for "
            "--sandbox / remote runtime scans. Run setup.sh / setup.ps1 first.")


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
    need_skillspector()
    env = skillspector_env()
    use_llm = skillspector_llm_usable()
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "report.json"
        cmd = [SKILLSPECTOR, "scan", str(src),
               "--format", "json", "--output", str(report)]
        if not use_llm:
            cmd.append("--no-llm")
        if not use_llm and PROVIDER == "anthropic" and LLM_KEY:
            suffix = ("  [static only -- SkillSpector's LLM path is incompatible "
                      "with Anthropic; Anthropic still drives --sandbox]")
        elif not use_llm:
            suffix = "  [static only -- no LLM provider configured]"
        else:
            suffix = ""
        print(f"  SkillSpector static scan (no execution): {src}{suffix}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=SCAN_TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            print("\n" + "=" * 60)
            print(f"[BLOCK] NO VERDICT -- scan timed out after {SCAN_TIMEOUT}s. Do NOT "
                  "install. Raise SCAN_MCP_TIMEOUT or review manually.")
            return 2
        # Never hide scanner errors (fail closed): surface stderr if present.
        if r.stderr.strip():
            print(r.stderr, file=sys.stderr)
        return verdict_skillspector(report, r.returncode)


def verdict_skillspector(report_path: Path, code: int) -> int:
    """Turn a SkillSpector JSON report into a clear verdict. Fail closed."""
    print("\n" + "=" * 60)
    data = None
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = None
    if data is None:
        print("[BLOCK] NO VERDICT -- SkillSpector produced no parsable report "
              f"(exit {code}). Do NOT install. Re-run the scan.")
        return 2

    ra = data.get("risk_assessment") or {}
    score = ra.get("score")
    severity = str(ra.get("severity") or "").upper()
    rec = str(ra.get("recommendation") or "").upper()
    issues = data.get("issues") or []
    meta = data.get("metadata") or {}

    if issues:
        print(f"Findings ({len(issues)}):")
        for it in issues:
            loc = it.get("location") or {}
            where = f"{loc.get('file')}:{loc.get('start_line')}" if loc.get("file") else "?"
            print(f"  {str(it.get('severity') or '?').upper()}: "
                  f"{it.get('id') or ''} {it.get('category') or ''} @ {where}")
            if it.get("explanation"):
                print(f"      {it['explanation']}")

    if score is None:
        print("[BLOCK] NO VERDICT -- report has no risk score. Review manually "
              "before installing.")
        return 2

    sev_set = {str(it.get("severity") or "").upper() for it in issues}
    runtime_note = ("\n   Note: a static source scan cannot see MCP tools that are "
                    "registered only at runtime. Use --sandbox for a live check of "
                    "an unfamiliar server.")
    llm_note = ("" if meta.get("llm_available")
                else "  (static only -- configure a provider for semantic analysis)")

    if (rec == "DO_NOT_INSTALL"
            or (isinstance(score, (int, float)) and score > 50)
            or (sev_set & {"HIGH", "CRITICAL"})):
        print(f"[BLOCK] risk {score}/100 ({severity}) -- {len(issues)} finding(s). "
              "Review the findings above before installing. Do not install on a whim.")
        return 1

    extra = f" with {len(issues)} low/medium note(s)" if issues else ""
    print(f"[SAFE] risk {score}/100 ({severity}){extra}. Installation reasonable."
          f"{llm_note}{runtime_note}")
    return 0


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
    cmd = [MCP_SCANNER, "remote", "--server-url", url, "--format", "summary"]
    if LLM_KEY:
        cmd[1:1] = ["--llm-api-key", LLM_KEY]
    return run_cisco(cmd, f"scanning remote MCP (no local code runs): {url}",
                     env=cisco_env())


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
    if not LLM_KEY:
        die("sandbox scan needs an LLM key. Configure a provider in .env "
            "(e.g. SKILLSPECTOR_PROVIDER=anthropic + ANTHROPIC_API_KEY).")
    build_sandbox_image()
    ensure_cache_volume()
    inner = " ".join(_shquote(c) for c in command)
    # `mcp-scanner` here is the binary *inside* the container (on its PATH).
    # --format is a GLOBAL flag and must precede the `stdio` subcommand.
    # Live (stdio) analysis uses yara (local signatures) + llm (semantic
    # analysis of the running server's tools/prompts). The behavioral analyzer
    # is source-only and rejects stdio; api/virustotal need paid keys.
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
        "-e", f"MCP_SCANNER_LLM_MODEL={CISCO_LLM_MODEL}",
        "-e", f"MCP_SCANNER_STDIO_TIMEOUT={STDIO_TIMEOUT}",
    ]
    if LLM_BASE_URL:
        docker += ["-e", f"MCP_SCANNER_LLM_BASE_URL={LLM_BASE_URL}"]
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
    """Turn an mcp-scanner (Cisco) summary into a clear verdict. Fail closed.

    Used by the runtime paths (remote + Stage 2 sandbox stdio)."""
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
            rc = run_skillspector(dest)
        if args.sandbox:
            if not args.command:
                die("--sandbox needs a launch command after `--`, "
                    "e.g. -- uvx package-name")
            print("\n-- Stage 2: live runtime scan in Docker sandbox --")
            rc = max(rc, run_sandbox(args.command))
        sys.exit(rc)

    if args.mode == "local":
        sys.exit(run_skillspector(Path(args.path)))
    if args.mode == "remote":
        sys.exit(run_remote(args.url))
    if args.mode == "sandbox":
        sys.exit(run_sandbox(args.command))


if __name__ == "__main__":
    main()
