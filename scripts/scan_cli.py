#!/usr/bin/env python3
"""
CLI tool security scanner -- scan first, install after (for CLI tools).

Agents increasingly install command-line tools (npm/PyPI packages, cargo
crates, GitHub release binaries, `curl | bash` installers) instead of MCP
servers. This router gives those installs the same scan-first workflow that
agent-guard already enforces for skills and MCPs, by routing each source to
the professional scanner best suited for it -- never writing our own
detection:

  npm / pypi / go   -> Datadog GuardDog (heuristics + YARA on package source
                       and registry metadata). Runs natively if `guarddog` is
                       on PATH, otherwise via the official Docker image
                       (the only supported install on Windows).
                       npm / pypi add a dynamic stage by default: the package is
                       installed and imported in OpenSSF's package-analysis
                       sandbox and its file, network and process activity is
                       judged (_dynamic.py). --no-dynamic skips it knowingly.
  binary <url>      -> download (never executed), SHA256, VirusTotal hash
                       reputation check (reuses the scan_mcp.py stage).
                       --deep adds a malcontent capability scan via Docker.
  script <url>      -> download (never executed), SkillSpector static scan.
                       Made for `curl | bash` installers: read it, never run it.
  cargo <crate>     -> Datadog GuardDog `crates` scan (GuardDog >= 3.2.0:
                       heuristics + YARA + registry metadata) PLUS a
                       SkillSpector static scan of the crate source fetched
                       from crates.io (taint tracking, YARA, OSV.dev). The
                       worse verdict wins; Socket Firewall (sfw) is still
                       recommended as an install-time net.

Exit codes (same contract as scan_skill.py / scan_mcp.py):
  0 = SAFE verdict       (nothing known-bad found -- NOT a guarantee)
  1 = BLOCK verdict      (findings -- this is a verdict, not an error)
  2 = no verdict         (scanner failed/unparsable -- fail closed)

Detection limits (documented, not hidden):
  - VirusTotal only knows files it has seen: an unseen hash gives NO VERDICT
    (exit 2), never SAFE. A known-and-clean hash can still be a targeted
    payload that no engine detects yet; prefer signed releases.
  - malcontent's Windows PE analysis is weaker than its ELF analysis.
  - GuardDog is heuristic; a clean result is not proof of harmlessness.
  - A static script scan cannot see second-stage payloads fetched at runtime.

Usage:
  python scan_cli.py npm  <package>[@version]
  python scan_cli.py pypi <package>[==version|@version]
  python scan_cli.py go   <module>[@version]
  python scan_cli.py binary <url> [--deep]
  python scan_cli.py script <url>
  python scan_cli.py cargo <crate>[@version]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import _dynamic
from _skillspector import (
    SCAN_TIMEOUT,
    combine_verdicts,
    die,
    run_bounded,
    run_skillspector,
    skipped_dynamic_verdict,
)
from _url_resolver import safe_basename
from scan_mcp import http_bytes, http_json, run_virustotal, safe_extract_tar

GUARDDOG_IMAGE = os.environ.get(
    "AGENT_GUARD_GUARDDOG_IMAGE", "ghcr.io/datadog/guarddog:latest")
MALCONTENT_IMAGE = os.environ.get(
    "AGENT_GUARD_MALCONTENT_IMAGE", "cgr.dev/chainguard/malcontent:latest")

# Cap a single downloaded artifact; a "release binary" larger than this is
# almost never a CLI tool and would blow past VirusTotal's usefulness anyway.
MAX_DOWNLOAD_BYTES = int(os.environ.get(
    "AGENT_GUARD_MAX_DOWNLOAD_BYTES", str(512 * 1024 * 1024)))


def _split_version(spec: str, seps: tuple = ("@", "==")) -> tuple:
    """Split `pkg@1.2.3` / `pkg==1.2.3` into (name, version-or-None).

    npm scoped packages (`@scope/name@1.2.3`) keep their leading `@`."""
    body = spec
    prefix = ""
    if spec.startswith("@"):        # npm scope -- the leading @ is not a separator
        prefix, body = "@", spec[1:]
    for sep in seps:
        if sep in body:
            name, _, version = body.partition(sep)
            return prefix + name, (version or None)
    return spec, None


def _download(url: str, dest: Path) -> Path:
    """Download `url` to `dest` (never executed). Refuses oversized files."""
    if not url.lower().startswith(("https://", "http://")):
        die(f"unsupported URL scheme: {url}")
    if url.lower().startswith("http://"):
        print("  WARNING: plain-HTTP download -- no transport integrity. "
              "Prefer an https:// URL.")
    req = urllib.request.Request(url, headers={"User-Agent": "agent-guard"})
    with urllib.request.urlopen(req, timeout=120) as r:
        length = r.headers.get("Content-Length")
        if length and int(length) > MAX_DOWNLOAD_BYTES:
            die(f"download exceeds AGENT_GUARD_MAX_DOWNLOAD_BYTES: {length} bytes")
        data = r.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        die("download exceeds AGENT_GUARD_MAX_DOWNLOAD_BYTES")
    dest.write_bytes(data)
    return dest


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_json(text: str):
    """Parse the JSON object out of scanner stdout. Tolerates progress noise
    before/after the report (whole-output parse first, then the outermost
    brace span). Returns None if nothing parses -- caller fails closed."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


# -- GuardDog (npm / pypi / go) ------------------------------------------------

def guarddog_command(ecosystem: str, package: str, version: str = None) -> list:
    """Build the GuardDog invocation: native binary if on PATH, else the
    official Docker image (the only supported install on Windows)."""
    args = [ecosystem, "scan", package, "--output-format", "json"]
    if version:
        args += ["--version", version]
    native = shutil.which("guarddog")
    if native:
        return [native] + args
    if shutil.which("docker") is None:
        die("GuardDog is not on PATH and Docker was not found. On Windows, "
            "GuardDog only runs via Docker -- start Docker Desktop, or install "
            "GuardDog natively (Linux/macOS: pipx install guarddog).")
    # --pull=always: `docker run` reuses a cached :latest image forever, so the
    # heuristics would freeze at the first pull. Offline, the pull fails and the
    # run produces no report -> NO VERDICT.
    return ["docker", "run", "--rm", "--pull=always", GUARDDOG_IMAGE] + args


# GuardDog 3.0 ships two kinds of rules. `capability-*` rules are transparency
# notes ("this package can read files / spawn processes") that fire on nearly
# every real-world library; the remaining rules are malware heuristics. Only
# the latter drive the BLOCK verdict -- capabilities are always printed so the
# reviewer sees them, but a file-reading HTTP library is not malware.
CAPABILITY_RULE_PREFIX = "capability-"

# Exception: some capabilities ARE the attack vector. An install-time hook
# (setup.py cmdclass install/develop override) executes code the moment the
# user runs `pip install` -- exactly the step this scanner gates. GuardDog 2.x
# classified this as the `cmd-overwrite` malware heuristic; 3.0 files it under
# capabilities, where a pure prefix split would wave real malware through
# (verified against DataDog's own malicious-software-packages-dataset: sample
# 0wneg fires ONLY capability-process-hooks). These rules block like malware
# heuristics.
BLOCKING_CAPABILITY_RULES = {
    "capability-process-hooks",
}


def guarddog_verdict(report: dict) -> int:
    """Map a GuardDog JSON report onto the agent-guard exit-code contract.
    Fail closed: no parsable finding count means no verdict."""
    print("\n" + "=" * 60)
    if "issues" not in report and "results" not in report:
        print("[BLOCK] NO VERDICT -- the GuardDog report has neither an issue "
              "count nor rule results. Do NOT install. Re-run the scan.")
        return 2
    errors = report.get("errors") or {}
    results = report.get("results") or {}
    flagged = {k: v for k, v in results.items() if v}
    malicious = {k: v for k, v in flagged.items()
                 if not k.startswith(CAPABILITY_RULE_PREFIX)
                 or k in BLOCKING_CAPABILITY_RULES}
    capabilities = {k: v for k, v in flagged.items() if k not in malicious}

    if errors:
        print(f"GuardDog rule errors ({len(errors)}):")
        for rule, err in errors.items():
            print(f"  {rule}: {err}")

    if malicious:
        print(f"Blocking findings ({len(malicious)} rule(s)):")
        for rule, finding in malicious.items():
            print(f"  {rule}: {finding}")
        if any(r in BLOCKING_CAPABILITY_RULES for r in malicious):
            print("  NOTE: capability-process-hooks means code runs AT INSTALL "
                  "TIME (setup.py install/develop hook) -- the classic PyPI "
                  "malware vector. Legitimate build tooling uses it too; read "
                  "the hook before deciding.")
    if capabilities:
        print(f"Capabilities (informational, {len(capabilities)} rule(s)):")
        for rule, finding in capabilities.items():
            print(f"  {rule}: {finding}")

    if not results:
        # No per-rule results to classify -- fall back to the raw issue count
        # and treat any finding as blocking (conservative).
        issues = report.get("issues")
        if not isinstance(issues, int):
            print("[BLOCK] NO VERDICT -- could not read a finding count from "
                  "the GuardDog report. Do NOT install. Re-run the scan.")
            return 2
        if errors and not issues:
            print("[WARN] INCONCLUSIVE -- GuardDog rules errored and no "
                  "findings were produced. Review manually.")
            return 2
        if issues > 0:
            print(f"[BLOCK] GuardDog flagged {issues} issue(s) -- review before "
                  "installing. Do not install on a whim.")
            return 1
        print("[SAFE] GuardDog found no known-malicious indicators. NOT a "
              "proof of harmlessness -- heuristics only cover known patterns.")
        return 0

    if errors and not malicious:
        print("[WARN] INCONCLUSIVE -- GuardDog rules errored and no findings "
              "were produced. That is not a clean result. Review manually.")
        return 2
    if malicious:
        print(f"[BLOCK] GuardDog flagged {len(malicious)} blocking issue(s) -- "
              "review the findings above before installing. Do not install on "
              "a whim.")
        return 1
    if capabilities:
        print("[SAFE] no malware heuristics fired. The capability notes above "
              "are informational -- verify they are plausible for this kind of "
              "package (a linter that opens network sockets is suspicious; an "
              "HTTP client that reads files is not).")
        return 0
    print("[SAFE] GuardDog found no known-malicious indicators. NOT a proof of "
          "harmlessness -- heuristics only cover known attack patterns.")
    return 0


def run_guarddog(ecosystem: str, spec: str) -> int:
    seps = ("==", "@") if ecosystem == "pypi" else ("@",)
    package, version = _split_version(spec, seps)
    cmd = guarddog_command(ecosystem, package, version)
    shown = version or "latest"
    print(f"  GuardDog scan ({ecosystem}): {package} {shown}")
    if cmd[0] == "docker":
        print(f"  via Docker image {GUARDDOG_IMAGE} (pulled fresh on every run)")
    try:
        r = run_bounded(cmd, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- GuardDog timed out after {SCAN_TIMEOUT}s. "
              "Do NOT install. Raise AGENT_GUARD_SCAN_TIMEOUT or review manually.")
        return 2
    if r.stderr.strip():
        print(r.stderr, file=sys.stderr)
    report = _extract_json(r.stdout or "")
    if report is None:
        print(r.stdout or "")
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- GuardDog produced no parsable JSON report "
              f"(exit {r.returncode}). Do NOT install. Re-run the scan.")
        return 2
    verdict = guarddog_verdict(report)
    if r.returncode != 0 and verdict == 0:
        print("[BLOCK] NO VERDICT -- GuardDog exited with an error despite a low-risk report.")
        return 2
    return verdict


# -- binary (GitHub release / arbitrary download) ------------------------------

def malcontent_verdict(report: dict) -> int:
    """Judge a malcontent JSON report: CRITICAL/HIGH risk -> BLOCK."""
    print("\n" + "=" * 60)
    files = report.get("Files") or {}
    if not isinstance(files, dict):
        print("[BLOCK] NO VERDICT -- malcontent report has an unexpected format "
              "(Files is not an object). Review manually before installing.")
        return 2
    worst = ""
    unknown = False
    order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for name, info in files.items():
        raw = info.get("RiskLevel") if isinstance(info, dict) else None
        level = str(raw).upper() if raw else ""
        print(f"  {name}: risk {level or 'MISSING'}")
        if level not in order:
            unknown = True
        elif order.index(level) > order.index(worst or "NONE"):
            worst = level
    if not files:
        print("[WARN] NO VERDICT -- malcontent reported no analyzed files. "
              "Review manually before installing.")
        return 2
    if worst in ("HIGH", "CRITICAL"):
        print(f"[BLOCK] malcontent rates the binary {worst} risk -- review its "
              "behavior report before installing.")
        return 1
    if unknown:
        print("[BLOCK] NO VERDICT -- malcontent gave a missing or unknown risk "
              "level for at least one file. Review manually before installing.")
        return 2
    print(f"[SAFE] malcontent risk level {worst or 'NONE'}. Capability analysis "
          "only -- Windows PE coverage is weaker than ELF; not a guarantee.")
    return 0


def run_malcontent(path: Path) -> int:
    """--deep stage: malcontent capability analysis via Docker (never executes
    the binary; malcontent reads it statically)."""
    if shutil.which("docker") is None:
        print("\n" + "=" * 60)
        print("[BLOCK] NO VERDICT -- --deep needs Docker for malcontent, and "
              "Docker was not found on PATH.")
        return 2
    print(f"  malcontent capability scan via {MALCONTENT_IMAGE}")
    print("  NOTE: malcontent's Windows PE analysis is weaker than ELF -- "
          "treat a clean result on .exe files with extra care.")
    cmd = ["docker", "run", "--rm", "--pull=always",
           "-v", f"{path.parent}:/scan:ro",
           MALCONTENT_IMAGE,
           "--format=json", "analyze", f"/scan/{path.name}"]
    try:
        r = run_bounded(cmd, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- malcontent timed out after {SCAN_TIMEOUT}s.")
        return 2
    if r.stderr.strip():
        print(r.stderr, file=sys.stderr)
    report = _extract_json(r.stdout or "")
    if report is None:
        print(r.stdout or "")
        print("\n" + "=" * 60)
        print(f"[BLOCK] NO VERDICT -- malcontent produced no parsable JSON "
              f"(exit {r.returncode}).")
        return 2
    result = malcontent_verdict(report)
    if r.returncode != 0 and result == 0:
        print("[BLOCK] NO VERDICT -- malcontent exited with an error despite a low-risk report.")
        return 2
    return result


def run_binary(url: str, deep: bool) -> int:
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / safe_basename(url, "download.bin")
        if dest.resolve().parent != Path(d).resolve():
            print("[BLOCK] NO VERDICT -- the download name would leave the "
                  "temp directory. Do NOT install.")
            return 2
        print(f"  downloading (never executed): {url}")
        _download(url, dest)
        digest = _sha256(dest)
        print(f"  SHA256: {digest}")
        print(f"  size:   {dest.stat().st_size} bytes")
        print("  LIMIT: VirusTotal only knows files it has seen. An unseen hash "
              "gives NO VERDICT (exit 2), never SAFE. A known-and-clean hash "
              "can still be a targeted payload that no engine detects yet. "
              "Prefer signed releases of well-known projects.")
        rc = run_virustotal(dest, max_files=1)
        if deep:
            print("\n-- deep: malcontent capability analysis --")
            rc = combine_verdicts(rc, run_malcontent(dest))
        return rc


# -- script (curl | bash installers) -------------------------------------------

def run_script(url: str) -> int:
    with tempfile.TemporaryDirectory() as d:
        name = safe_basename(url, "installer")
        if "." not in name:
            name += ".sh"
        dest = Path(d) / name
        if dest.resolve().parent != Path(d).resolve():
            print("[BLOCK] NO VERDICT -- the download name would leave the "
                  "temp directory. Do NOT install.")
            return 2
        print(f"  downloading installer (never executed): {url}")
        _download(url, dest)
        print(f"  SHA256: {_sha256(dest)}")
        print("  LIMIT: this is a STATIC scan. A second-stage payload the "
              "script downloads at runtime is not covered. If the script "
              "fetches and pipes further scripts, scan those URLs too.")
        return run_skillspector(dest)


# -- cargo (crates.io) -----------------------------------------------------------

def fetch_crate(spec: str, dest: Path) -> tuple:
    name, version = _split_version(spec, ("@",))
    if not version:
        meta = http_json(f"https://crates.io/api/v1/crates/{name}")
        crate = meta.get("crate") or {}
        version = crate.get("max_stable_version") or crate.get("max_version")
        if not version:
            die(f"could not resolve a version for crate {name}")
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    print(f"  fetching crate source: {url}")
    safe_extract_tar(http_bytes(url), dest)
    return name, version


def run_cargo(spec: str) -> int:
    """cargo crate: GuardDog `crates` scan + SkillSpector static source scan."""
    print("  cargo crate: GuardDog crates scan (heuristics + registry metadata) "
          "followed by a SkillSpector static scan of the crate source.")
    print("  NOTE: GuardDog's crates rules are newer and thinner than its "
          "npm/PyPI rules. Consider Socket Firewall as an install-time net: "
          "`sfw cargo install <crate>`.")
    print("\n-- stage 1: GuardDog --")
    gd = run_guarddog("crates", spec)
    print("\n-- stage 2: SkillSpector static source scan --")
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d)
        name, version = fetch_crate(spec, dest)
        print(f"  static scan of {name} {version} (no execution)")
        ss = run_skillspector(dest)
    rc = combine_verdicts(gd, ss)
    print("\n" + "=" * 60)
    label = {0: "SAFE", 1: "BLOCK", 2: "NO VERDICT"}[rc]
    print(f"[{label}] cargo combined verdict -> exit {rc} "
          f"(GuardDog exit {gd}, SkillSpector exit {ss}).")
    return rc


# -- CLI -------------------------------------------------------------------------

def _add_dynamic_options(sp):
    sp.add_argument("--no-dynamic", action="store_true",
                    help="skip the dynamic install analysis (it needs Docker); the result is "
                         "NO VERDICT unless AGENT_GUARD_STATIC_ONLY=1")
    sp.add_argument("--allow-host", action="append", default=[], metavar="HOST[:PORT]",
                    help="dynamic analysis: also allow this destination (default port 443; the "
                         "package registry is always allowed). Repeatable")


def main():
    p = argparse.ArgumentParser(
        description="Scan a CLI tool for malicious code before installing it.")
    sub = p.add_subparsers(dest="mode", required=True)

    for eco, helptext in [("npm", "npm package -> GuardDog"),
                          ("pypi", "PyPI package -> GuardDog"),
                          ("go", "Go module -> GuardDog")]:
        sp = sub.add_parser(eco, help=helptext)
        sp.add_argument("package", help="package name, optionally with version")
        if eco in _dynamic.ECOSYSTEMS:
            _add_dynamic_options(sp)

    sp = sub.add_parser("binary",
                        help="release binary URL -> SHA256 + VirusTotal")
    sp.add_argument("url")
    sp.add_argument("--deep", action="store_true",
                    help="also run a malcontent capability scan (Docker)")

    sp = sub.add_parser("script",
                        help="curl|bash installer URL -> static scan, never run")
    sp.add_argument("url")

    sp = sub.add_parser("cargo",
                        help="crates.io crate -> GuardDog crates scan + static source scan")
    sp.add_argument("crate", help="crate name, optionally with @version")

    args = p.parse_args()

    if args.mode in _dynamic.ECOSYSTEMS:
        rc = run_guarddog(args.mode, args.package)
        if args.no_dynamic:
            sys.exit(combine_verdicts(rc, skipped_dynamic_verdict()))
        print("\n-- Dynamic install analysis (OpenSSF sandbox) --")
        sys.exit(combine_verdicts(rc, _dynamic.run(args.mode, args.package,
                                                   allow_hosts=args.allow_host)))
    if args.mode == "go":
        sys.exit(run_guarddog(args.mode, args.package))
    if args.mode == "binary":
        sys.exit(run_binary(args.url, args.deep))
    if args.mode == "script":
        sys.exit(run_script(args.url))
    if args.mode == "cargo":
        sys.exit(run_cargo(args.crate))


if __name__ == "__main__":
    import _console

    _console.utf8_stdio()
    main()
