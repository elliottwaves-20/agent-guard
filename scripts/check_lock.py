"""Judge a candidate lockfile or query advisories for one exact package version."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections import defaultdict
from contextlib import nullcontext, redirect_stdout
from dataclasses import replace
from pathlib import Path

import _fastlane
import _lockcheck
import _mcp_locked
import _mcp_npm
import _mcp_uv
import _user_config
import _versions
from _lockcheck import Entry, NoVerdict, entry_key
from _mcp_locked import Refused, age_arg, normalize_pypi, parse_overrides


class _HelpRequested(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise NoVerdict(message)

    def exit(self, status=0, message=None):
        if status == 0:
            raise _HelpRequested
        raise NoVerdict(message or "argument parsing failed")


def _parser():
    parser = _Parser(description=__doc__, allow_abbrev=False, add_help=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("file", nargs="?", type=Path, metavar="FILE")
    mode.add_argument("--package", metavar="ECOSYSTEM:NAME@VERSION")
    parser.add_argument("--previous", type=Path, metavar="FILE")
    parser.add_argument("--top", metavar="NAME")
    parser.add_argument("--root-name", metavar="NAME", help="virtual root name in uv.lock")
    parser.add_argument("--override", action="append", metavar="NAME=VERSION")
    parser.add_argument("--override-reason", metavar="TEXT")
    parser.add_argument("--min-age-days", type=age_arg, metavar="N")
    parser.add_argument("--trusted-days", type=age_arg, metavar="N")
    parser.add_argument("--no-fast-lane", action="store_true")
    parser.add_argument("--receipts", type=Path, metavar="DIR")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-h", "--help", action="help")
    return parser


def _finding(advisory):
    return {"id": advisory.id, "kind": "malware" if advisory.source.endswith("-malware")
            else "security", "severity": advisory.severity, "source": advisory.source}


def _no_verdict(exc):
    message = str(exc) or type(exc).__name__
    return message if message.startswith("NO VERDICT --") else f"NO VERDICT -- {message}"


def _package(args, fetch):
    if any(value is not None for value in (
        args.previous, args.top, args.root_name, args.override, args.override_reason,
        args.min_age_days, args.trusted_days, args.receipts,
    )) or args.no_fast_lane:
        raise NoVerdict("--package takes only a package spec and optional --json")

    kind, _, spec = args.package.partition(":")
    name, _, version = spec.rpartition("@")
    if kind == "npm":
        ecosystem, validator = "npm", _mcp_npm
    elif kind == "pypi":
        ecosystem, validator = "PyPI", _mcp_uv
    else:
        raise NoVerdict("--package expects npm:NAME@VERSION or pypi:NAME@VERSION")
    validator.check_package(name)
    validator.check_version(version)
    _versions.key(ecosystem, version)

    entry = Entry(ecosystem, normalize_pypi(name) if kind == "pypi" else name, version)
    advisories, failures = _lockcheck.advisories_for([entry], fetch)
    lines = [f"[BLOCK] {entry.label}: {a.source} {a.id}" for a in advisories]
    lines.extend(f"NO VERDICT -- {failure}" for failure in failures)
    if not lines:
        lines.append(f"No advisory for {entry.label}.")
    return {"code": 2 if failures else int(bool(advisories)), "lines": lines,
            "findings": [_finding(a) for a in advisories]}


def _read(path, format_name, root_name, *, previous=False):
    text = path.read_text(encoding="utf-8")
    if format_name == "npm":
        return _lockcheck.npm_lock_entries(json.loads(text))
    if format_name == "uv":
        entries = _lockcheck.uv_lock_entries(text, root_name)
    else:
        entries = _lockcheck.hashed_requirements(text, require_hashes=not previous)
    return [replace(entry, name=normalize_pypi(entry.name)) for entry in entries]


def _group(entries, *, by_version=False):
    groups = defaultdict(list)
    for entry in entries:
        key = entry_key(entry)
        groups[key if by_version else key[:2]].append(entry)
    return groups


def _trusted_limit(young, candidates, previous, top, policy, fetch, now):
    """Return the eligible S1 key, and whether it still needs a fast-lane fix."""
    if top is None:
        return None, False
    name = ("npm", top)
    old, new = previous.get(name, ()), candidates.get(name, ())
    if len(old) != 1 or len(new) != 1 or old[0].version == new[0].version:
        return None, False
    key = entry_key(new[0])
    if key not in young:
        return None, False
    continuity = _fastlane.continuity("npm", top, old[0].version, new[0].version, fetch)
    if continuity == "failed":
        raise NoVerdict(f"{new[0].label}: could not establish npm provenance continuity")
    decision = _fastlane.decide({"kind": "age", "input": {
        "ecosystem": "npm", "continuity": continuity,
        "published": _lockcheck._parse_time(young[key].published).isoformat(),
        "now": now.isoformat(), "settings": {
            "min_age_days": policy.min_age_days, "trusted_days": policy.trusted_days,
        },
    }})
    if decision["action"] not in {"install", "wait"}:
        raise NoVerdict(f"{new[0].label}: could not determine the npm waiting period")
    if decision["tier"] != "s1":
        return None, False
    return key, decision["action"] == "wait"


def _bind_fix(entry, receipt, format_name):
    if format_name == "uv":
        _mcp_uv.single_pure_wheel(entry, receipt.archive_sha256, "fast lane fix")
    elif format_name == "npm":
        if entry.integrity != receipt.integrity:
            raise NoVerdict(f"{entry.label}: locked integrity differs from the SAFE receipt")
    elif entry.hashes != (receipt.archive_sha256,):
        raise NoVerdict(f"{entry.label}: fast lane fix needs exactly the hash in the SAFE receipt")


def _approve_fixes(young, previous, candidates, *, format_name, receipts_root,
                   overrides, policy, fetch):
    approval = _fastlane.TreeVerdict(0)
    old_versions = {}
    for ecosystem, name, version in young:
        old = previous.get((ecosystem, name), ())
        if len(old) == 1 and old[0].version != version:
            old_versions[entry_key(old[0])] = old[0]
    if not policy.fast_lane or not old_versions:
        return approval, {}

    advisories, failures = _lockcheck.advisories_for(list(old_versions.values()), fetch)
    if failures:
        raise NoVerdict("previous advisory lookup failed: " + "; ".join(failures))
    by_entry = defaultdict(list)
    for advisory in advisories:
        if advisory.entry is None or entry_key(advisory.entry) not in old_versions:
            raise NoVerdict(f"advisory {advisory.id} cannot be matched to an installed version")
        by_entry[entry_key(advisory.entry)].append(advisory)
    if not by_entry:
        return approval, {}

    kev = _fastlane.kev_cves(fetch)
    if kev is None:
        raise NoVerdict("KEV feed unavailable while checking installed versions")
    decisions, fixes = [], {}
    for key, advisories in by_entry.items():
        old = old_versions[key]
        override = _fastlane.user_override(old, overrides)
        record = _fastlane._decide_entry(old, advisories, kev, policy, override, fetch)
        decisions.append(record)
        candidate_key = key[:2] + (record["version"],)
        if record["action"] == "install" and candidate_key in young:
            approval.decisions.append(record)
            fixes[old.name] = candidate_key
    if any(record["action"] == "no_verdict" for record in decisions):
        approval.code = 2
        approval.lines.extend(_fastlane._decision_line(record) for record in decisions
                              if record["action"] == "no_verdict")
    else:
        kind = "npm" if format_name == "npm" else "pypi"
        _fastlane._collect_fixes(approval, receipts_root, kind)

    age_limits = {}
    if approval.code == 0:
        try:
            for name, (_, receipt, _) in approval.fixes.items():
                key = fixes[name]
                for entry in candidates[key]:
                    _bind_fix(entry, receipt, format_name)
                age_limits[key] = 0
        except (NoVerdict, Refused) as exc:
            approval.code = 2
            approval.lines.append(_no_verdict(exc))
            age_limits.clear()
    approval.decisions = decisions
    if approval.needs_scan:
        approval.lines.append(f"NO VERDICT -- {_mcp_locked.NeedsScan(approval.needs_scan)}")
    return approval, age_limits


def _file(args, fetch, now):
    format_name = {"package-lock.json": "npm", "uv.lock": "uv"}.get(
        args.file.name, "requirements")
    validator = _mcp_npm if format_name == "npm" else _mcp_uv
    if format_name == "uv" and not args.root_name:
        raise NoVerdict("--root-name is required for uv.lock")
    if format_name == "npm" and args.top is not None:
        validator.check_package(args.top)
    policy = _fastlane.policy(args.min_age_days, args.trusted_days, args.no_fast_lane)
    overrides = parse_overrides(args.override)
    if format_name == "npm":
        _mcp_npm.validate_overrides(overrides, args.override_reason)
    else:
        overrides = _mcp_uv.validate_overrides(overrides, args.override_reason)
    root = args.receipts
    if root is None:
        root = _mcp_locked.settings(_user_config.load_config(), os.environ, sys.platform).install_dir
    entries = _read(args.file, format_name, args.root_name)
    installed = (_read(args.previous, format_name, args.root_name, previous=True)
                 if args.previous is not None else entries)
    previous = _group(installed)
    previous_versions = {key: group[0].version for key, group in previous.items() if len(group) == 1}
    pypi_installed = None
    if format_name != "npm" and args.previous is not None:
        pypi_installed = {key: group[0] for key, group in _group(installed, by_version=True).items()
                          if len(group) == 1}

    def run_check(limits=None):
        return _lockcheck.check(entries, now=now, fetch=fetch, min_age_days=policy.min_age_days,
                                age_limits=limits, require_wheel=format_name == "requirements")

    result = run_check()
    approval = _fastlane.TreeVerdict(0)
    if (args.previous is not None and result.young and not result.failures
            and not result.blocking):
        young = {entry_key(wait.entry): wait for wait in result.young}
        age_limits = {}
        try:
            if format_name == "npm":
                key, still_young = _trusted_limit(young, _group(entries), previous, args.top,
                                                  policy, fetch, now)
                if key is not None:
                    age_limits[key] = policy.trusted_days
                    if not still_young:
                        del young[key]
            approval, fix_limits = _approve_fixes(
                young, previous, _group(entries, by_version=True), format_name=format_name,
                receipts_root=root, overrides=overrides, policy=policy, fetch=fetch,
            )
            age_limits.update(fix_limits)
        except (NoVerdict, OSError) as exc:
            approval = _fastlane.TreeVerdict(2, [_no_verdict(exc)])
        # Keep FILE findings from the first read even if registry data later changes.
        if result.code == 2 and approval.code == 0 and age_limits:
            result = run_check(age_limits)

    verdict = _fastlane.judge_tree(
        entries, previous_versions, receipts_root=root,
        kind="npm" if format_name == "npm" else "pypi", user_overrides=overrides,
        policy=policy, fetch=fetch, now=now, check=lambda *args, **kwargs: result,
        pypi_installed=pypi_installed,
    )
    for record in verdict.decisions:
        if record["action"] == "install":
            verdict.code = 1
            verdict.lines.append(f"[BLOCK] FILE still contains {record['package']}@"
                                 f"{record['installed']}. Resolve with {record['version']}.")
    if verdict.code != 1 and approval.code != 0:
        verdict.code = approval.code
    verdict.lines.extend(approval.lines)
    verdict.decisions.extend(approval.decisions)
    verdict.needs_scan.extend(approval.needs_scan)
    return _file_result(verdict)


def _file_result(verdict):
    advisories = [dict(_finding(a), package=a.entry.name if a.entry else None,
                       version=a.entry.version if a.entry else None, aliases=list(a.aliases))
                  for a in verdict.advisories]
    decisions = [{k: v for k, v in record.items() if k != "repo"} for record in verdict.decisions]
    young = [{"package": wait.entry.name, "version": wait.entry.version,
              "wait_until": wait.wait_until} for wait in verdict.young]
    return {"code": verdict.code, "lines": verdict.lines, "advisories": advisories,
            "decisions": decisions, "needs_scan": verdict.needs_scan, "young": young}


def main(argv=None, *, fetch=_lockcheck.http_fetch, now=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    package_mode = any(arg == "--package" or arg.startswith("--package=") for arg in argv)
    try:
        with redirect_stdout(sys.stderr) if as_json else nullcontext():
            parser = _parser()
            if "-h" in argv or "--help" in argv:
                parser.print_help()
                raise _HelpRequested
            args = parser.parse_args(argv)
            if args.package is not None:
                result = _package(args, fetch)
            else:
                result = _file(args, fetch, now or dt.datetime.now(dt.timezone.utc))
            encoded = json.dumps(result) if as_json else None
    except (Exception, SystemExit, KeyboardInterrupt) as exc:
        if isinstance(exc, _HelpRequested) and argv in (["-h"], ["--help"]):
            return 0
        message = ("NO VERDICT -- no check was run" if isinstance(exc, _HelpRequested)
                   else _no_verdict(exc))
        if package_mode:
            result = {"code": 2, "lines": [message], "findings": []}
        else:
            needs_scan = exc.items if isinstance(exc, _mcp_locked.NeedsScan) else []
            result = _file_result(_fastlane.TreeVerdict(2, [message], needs_scan=needs_scan))
        encoded = json.dumps(result) if as_json else None

    if as_json:
        print(encoded)
    else:
        for line in result["lines"]:
            print(line, file=sys.stdout if result["code"] == 0 else sys.stderr)
    return result["code"]


if __name__ == "__main__":
    raise SystemExit(main())
