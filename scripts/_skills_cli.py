#!/usr/bin/env python3
"""Delegate skill distribution to the `skills` CLI (vercel-labs/skills).

Why delegate instead of linking ourselves: the ecosystem already has one
established tool for the "install this skill into every agent on this machine"
problem. It writes a single canonical copy to `~/.agents/skills/<name>` and
links every agent directory to it -- an NTFS junction on Windows with an
automatic copy fallback -- and it carries the skills directory of 80+ agents.
Our own table only ever covered the handful of agents we could inspect, and a
wrong path there fails silently: the user gets an installation that is never
loaded. Delegating removes that whole class of failure.

Trust model. The pinned version below is the only one this wrapper runs:

  1. npm registry metadata must match the pinned sha1/sha512.
  2. GuardDog -- our own CLI-scanning pipeline -- scans that exact version.
     A SAFE verdict passes. A BLOCK passes only when its blocking findings are
     exactly the ones recorded in scripts/reviewed/skills-cli-<version>.json,
     which states for each one why it was accepted. Any new, missing or
     changed finding stops delegation.
  3. The result is cached per version, so this runs once per pin.

The recorded findings are neutralised rather than merely argued away: the CLI
runs with `npm_config_ignore_scripts=true` (no lifecycle script can execute)
and with a reduced environment that carries no credentials.

Anything unexpected -- registry mismatch, unknown finding, missing npx,
timeout, non-zero exit -- disables delegation and the caller falls back to its
own installer. An installation never fails because of this module; only the
distribution method changes, and the output says so.

Opt out entirely with AGENT_GUARD_SKILLS_CLI=0.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from _skillspector import run_bounded

# -- pinned release -----------------------------------------------------------

SKILLS_PACKAGE = "skills"
SKILLS_VERSION = "1.7.0"
SKILLS_SHASUM = "28a0d4f65a261d38cbd1737fb10f1b7f99926ac5"
SKILLS_INTEGRITY = (
    "sha512-OfePnDft+Xt9/tCoHdCUe5fkM8i+Q3QOSQO53hm7mKtsXyvc+CKOAAliVWZ484HS3cWx+6r+ob0AArixs3jYXw=="
)
REGISTRY_BASE = "https://registry.npmjs.org"

REVIEW_DIR = Path(__file__).resolve().parent / "reviewed"

# The canonical store the CLI writes; every agent directory links to it.
CANONICAL_SKILLS_DIR = Path.home() / ".agents" / "skills"

DELEGATION_TIMEOUT = float(os.environ.get("AGENT_GUARD_SKILLS_CLI_TIMEOUT", "300"))

# Our tool ids -> the CLI's agent names, used only when the caller restricts
# the targets with --tools. Claude Desktop maps to nothing on purpose: it reads
# the same ~/.claude/skills as Claude Code, so the CLI has no separate agent for
# it. Antigravity maps to two agents (the App and the `agy` CLI). Any name we
# do not know is passed through unchanged, so every one of the CLI's agents can
# be selected by its own name.
AGENT_NAMES = {
    "claude-code": ("claude-code",),
    "claude-desktop": (),
    "codex": ("codex",),
    "antigravity": ("antigravity", "antigravity-cli"),
    "gemini-cli": ("gemini-cli",),
    "hermes": ("hermes-agent",),
    "openclaw": ("openclaw",),
}

# Environment variables the delegated process may see. Everything else -- above
# all API keys and GITHUB_TOKEN / GH_TOKEN / COPILOT_GITHUB_TOKEN, which the
# CLI reads for private repositories -- is withheld.
ENV_ALLOWLIST = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE",
    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROGRAMDATA", "LANG", "LC_ALL", "NODE_PATH", "NPM_CONFIG_CACHE",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME",
}


# -- configuration ------------------------------------------------------------

def enabled() -> bool:
    return os.environ.get("AGENT_GUARD_SKILLS_CLI", "1").strip().lower() not in {"0", "false", "no"}


def copy_mode() -> bool:
    """Force independent copies instead of links (agents behind mounts)."""
    return os.environ.get("AGENT_GUARD_SKILLS_CLI_COPY", "").strip().lower() in {"1", "true", "yes"}


def agent_names(selected=None, present: dict | None = None) -> list:
    """Agent arguments for the CLI.

    Without an explicit selection this returns ['*']: the CLI then installs
    into every agent it detects itself, which is the point of delegating -- its
    table is maintained upstream and covers 80+ agents, ours never will."""
    if selected is None:
        return ["*"]
    names = []
    for tid in selected:
        if present is not None and not present.get(tid, True):
            continue
        for name in AGENT_NAMES.get(tid, (tid,)):
            if name not in names:
                names.append(name)
    return names


def hardened_env() -> dict:
    """Reduced environment for the delegated process.

    `npm_config_ignore_scripts` stops npm from running any lifecycle script
    (the pinned package declares `"prepare": "husky"`, which npm would not run
    for a registry tarball anyway -- this makes that structural instead of
    circumstantial)."""
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_ALLOWLIST}
    env["npm_config_ignore_scripts"] = "true"
    env["NO_COLOR"] = "1"
    return env


# -- pinned-release verification ---------------------------------------------

def review_path(version: str = SKILLS_VERSION) -> Path:
    return REVIEW_DIR / f"skills-cli-{version}.json"


def load_review(path: Path) -> dict:
    """Read and validate the reviewed-findings file for a pinned version.

    Mirrors the strictness of the SkillSpector reviewed baseline: no wildcards,
    every accepted finding names its rule, file, matched text and a reason."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError("reviewed findings file must use version 1")
    if data.get("package") != SKILLS_PACKAGE:
        raise ValueError("reviewed findings file names a different package")
    for key in ("package_version", "shasum", "integrity", "reviewed_on"):
        if not str(data.get(key, "")).strip():
            raise ValueError(f"reviewed findings file requires a non-empty {key}")
    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        raise ValueError("reviewed findings file must list the accepted findings")
    for entry in findings:
        if not isinstance(entry, dict):
            raise ValueError("invalid reviewed finding entry")
        for key in ("rule", "file", "match", "reason"):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"reviewed finding requires a non-empty {key}")
            if value.strip() == "*":
                raise ValueError("reviewed findings must not use wildcards")
    return data


def finding_key(rule: str, entry) -> tuple:
    """Identity of a GuardDog finding, deliberately without the line number.

    A rebuild moves `dist/cli.mjs:3721` to a different line without changing
    anything of substance, so the file and the matched text carry the identity;
    the line would turn every release into a false alarm."""
    if isinstance(entry, dict):
        location = str(entry.get("location", ""))
        match = str(entry.get("match", ""))
    else:
        location = str(entry)
        match = ""
    path = location.rsplit(":", 1)[0] if ":" in location else location
    return (rule, path.replace("\\", "/"), match)


def blocking_findings(report: dict) -> set:
    """Fingerprints of the findings that drive a BLOCK verdict."""
    import scan_cli
    results = (report or {}).get("results") or {}
    keys = set()
    for rule, entries in results.items():
        if not entries:
            continue
        if (rule.startswith(scan_cli.CAPABILITY_RULE_PREFIX)
                and rule not in scan_cli.BLOCKING_CAPABILITY_RULES):
            continue
        for entry in (entries if isinstance(entries, list) else [entries]):
            keys.add(finding_key(rule, entry))
    return keys


def review_findings(review: dict) -> set:
    return {(f["rule"], f["file"].replace("\\", "/"), f["match"])
            for f in review["findings"]}


def registry_metadata(version: str = SKILLS_VERSION) -> dict:
    url = f"{REGISTRY_BASE}/{SKILLS_PACKAGE}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": "agent-guard"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def latest_version():
    """`latest` dist-tag, for a note when the pin has fallen behind."""
    try:
        req = urllib.request.Request(f"{REGISTRY_BASE}/{SKILLS_PACKAGE}",
                                     headers={"User-Agent": "agent-guard",
                                              "Accept": "application/vnd.npm.install-v1+json"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        return (data.get("dist-tags") or {}).get("latest")
    except Exception:
        return None


def integrity_matches(meta: dict, shasum: str = SKILLS_SHASUM,
                      integrity: str = SKILLS_INTEGRITY) -> bool:
    dist = (meta or {}).get("dist") or {}
    return dist.get("shasum") == shasum and dist.get("integrity") == integrity


def guarddog_report(version: str = SKILLS_VERSION, timeout: float = 900.0):
    """Run our own GuardDog pipeline and return the parsed JSON report."""
    import scan_cli
    cmd = scan_cli.guarddog_command("npm", SKILLS_PACKAGE, version)
    print(f"  skills CLI: scanning {SKILLS_PACKAGE}@{version} with GuardDog")
    try:
        result = run_bounded(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  skills CLI: GuardDog timed out after {timeout:.0f}s")
        return None
    if result.stderr and result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return scan_cli._extract_json(result.stdout or "")


def verification_marker(version: str = SKILLS_VERSION) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "state"))
    return base / "agent-guard" / "skills-cli" / f"{version}.json"


def review_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pinned_package(force: bool = False) -> bool:
    """Pin check plus GuardDog scan against the reviewed findings, cached."""
    import scan_cli

    review_file = review_path()
    try:
        review = load_review(review_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"  skills CLI: reviewed findings file unusable ({exc})")
        return False
    digest = review_digest(review_file)

    marker = verification_marker()
    if not force and marker.is_file():
        try:
            cached = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cached = {}
        if (cached.get("version") == SKILLS_VERSION
                and cached.get("shasum") == SKILLS_SHASUM
                and cached.get("integrity") == SKILLS_INTEGRITY
                and cached.get("review_digest") == digest
                and cached.get("accepted") is True):
            return True

    if review.get("package_version") != SKILLS_VERSION:
        print("  skills CLI: reviewed findings file is for "
              f"{review.get('package_version')}, pin is {SKILLS_VERSION}")
        return False
    if review.get("shasum") != SKILLS_SHASUM or review.get("integrity") != SKILLS_INTEGRITY:
        print("  skills CLI: reviewed findings file does not match the pinned digests")
        return False

    try:
        meta = registry_metadata()
    except Exception as exc:                      # offline, proxy, registry down
        print(f"  skills CLI: registry metadata unavailable ({exc})")
        return False
    if not integrity_matches(meta):
        print("  skills CLI: registry digests do not match the pin for "
              f"{SKILLS_PACKAGE}@{SKILLS_VERSION} -- not running it.")
        return False

    newest = latest_version()
    if newest and newest != SKILLS_VERSION:
        print(f"  skills CLI: pin is {SKILLS_VERSION}, registry latest is {newest} "
              "-- review and raise the pin (scripts/verify_skills_cli.py --update)")

    report = guarddog_report()
    if report is None:
        print("  skills CLI: GuardDog produced no parsable report -- not running it.")
        return False
    verdict = scan_cli.guarddog_verdict(report)

    accepted = False
    if verdict == 0:
        accepted = True
    elif verdict == 1:
        found = blocking_findings(report)
        expected = review_findings(review)
        if found == expected:
            print(f"REVIEW: {len(found)} blocking finding(s) accepted by "
                  f"{review_file.name}:")
            for entry in review["findings"]:
                print(f"  {entry['rule']} ({entry['file']}): {entry['reason']}")
            accepted = True
        else:
            for key in sorted(found - expected):
                print(f"  skills CLI: UNREVIEWED finding {key[0]} in {key[1]} ({key[2]})")
            for key in sorted(expected - found):
                print(f"  skills CLI: reviewed finding no longer present: {key[0]} in {key[1]}")
            print("  skills CLI: findings differ from the reviewed set -- not running it.")
    else:
        print("  skills CLI: GuardDog gave no verdict -- not running it.")

    if not accepted:
        return False

    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({
        "package": SKILLS_PACKAGE,
        "version": SKILLS_VERSION,
        "shasum": SKILLS_SHASUM,
        "integrity": SKILLS_INTEGRITY,
        "review_digest": digest,
        "accepted": True,
    }, indent=2) + "\n", encoding="utf-8")
    return True


# -- delegation ---------------------------------------------------------------

def echo(text: str, stream=None):
    """Print output from the delegated process without dying on its glyphs.

    The CLI prints check marks and box drawing; a Windows console in cp1252
    raises UnicodeEncodeError on those, which would turn a successful
    distribution into a traceback."""
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    stream.write(text.encode(encoding, "replace").decode(encoding, "replace") + "\n")


def npx_path():
    return shutil.which("npx")


def skills_argv(source: Path, names: list, copy: bool = False) -> list:
    """`npx` always runs the pinned version, so the artifact that was scanned
    is the one that executes. A `skills` binary already on PATH is deliberately
    ignored: its version is whatever the user installed, which no pin covers."""
    argv = [npx_path() or "npx", "-y", f"{SKILLS_PACKAGE}@{SKILLS_VERSION}",
            "add", str(source), "-g"]
    for name in names:
        argv += ["-a", name]
    if copy:
        argv.append("--copy")
    argv.append("-y")
    return argv


def distribute(source: Path, dry: bool, selected=None, present: dict | None = None) -> tuple:
    """Install `source` into the agents through the skills CLI.

    Returns (handled, names). `handled` is False whenever the caller must fall
    back to its own installer."""
    if not enabled():
        return False, []
    names = agent_names(selected, present)
    if not names:
        return False, []
    if npx_path() is None:
        print("  skills CLI: npx not found on PATH -- using the built-in installer")
        return False, []

    argv = skills_argv(source, names, copy=copy_mode())
    printable = " ".join(["npx"] + argv[1:])
    if dry:
        print(f"[DRY]   delegate to skills CLI: {printable}")
        return True, names

    if not verify_pinned_package():
        return False, []

    print(f"  delegate to skills CLI: {printable}")
    try:
        result = run_bounded(argv, timeout=DELEGATION_TIMEOUT, env=hardened_env())
    except subprocess.TimeoutExpired:
        print(f"  skills CLI: timed out after {DELEGATION_TIMEOUT:.0f}s "
              "-- using the built-in installer")
        return False, []
    if result.stdout:
        echo(result.stdout.rstrip())
    if result.returncode != 0:
        if result.stderr:
            echo(result.stderr.rstrip(), sys.stderr)
        print("  skills CLI: exited with an error -- using the built-in installer")
        return False, []
    return True, names
