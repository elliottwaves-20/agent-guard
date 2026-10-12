#!/usr/bin/env python3
"""Maintenance entry point for the pinned `skills` CLI.

The installer delegates skill distribution to `skills@<pin>` and runs it only
when GuardDog's blocking findings match scripts/reviewed/skills-cli-<pin>.json
exactly. Raising that pin is a deliberate, reviewed step -- this script does
the mechanical part of it and leaves the judgement to a human.

  python scripts/verify_skills_cli.py              # re-verify the current pin
  python scripts/verify_skills_cli.py --latest     # pin vs. registry latest
  python scripts/verify_skills_cli.py --update 1.6.0
                                                   # scan a candidate version and
                                                   # print a reviewed-findings draft

--update never edits the pin and never writes into scripts/reviewed/ on its
own. It prints a draft whose `reason` fields say REVIEW ME; fill those in, save
the file as scripts/reviewed/skills-cli-<version>.json, and update the pin in
scripts/_skills_cli.py. Accepting a finding means stating why it is harmless
for the way this wrapper invokes the CLI.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _skills_cli as cli


def check() -> int:
    ok = cli.verify_pinned_package(force=True)
    print()
    if ok:
        print(f"[OK] {cli.SKILLS_PACKAGE}@{cli.SKILLS_VERSION} is verified; "
              "delegation is available.")
        return 0
    print(f"[BLOCK] {cli.SKILLS_PACKAGE}@{cli.SKILLS_VERSION} is not verified; "
          "the installer will use its built-in linker.")
    return 1


def latest() -> int:
    newest = cli.latest_version()
    print(f"pin:    {cli.SKILLS_VERSION}")
    print(f"latest: {newest or 'unknown'}")
    if newest and newest != cli.SKILLS_VERSION:
        print(f"\nThe pin is behind. Review the candidate:\n"
              f"  python scripts/verify_skills_cli.py --update {newest}")
        return 1
    return 0


def update(version: str) -> int:
    try:
        meta = cli.registry_metadata(version)
    except Exception as exc:
        print(f"[BLOCK] registry metadata for {version} unavailable ({exc})")
        return 2
    dist = meta.get("dist") or {}
    shasum, integrity = dist.get("shasum"), dist.get("integrity")
    if not shasum or not integrity:
        print(f"[BLOCK] registry metadata for {version} has no digests")
        return 2

    report = cli.guarddog_report(version)
    if report is None:
        print("[BLOCK] GuardDog produced no parsable report; nothing to review.")
        return 2

    import scan_cli
    verdict = scan_cli.guarddog_verdict(report)
    found = cli.blocking_findings(report)

    try:
        current = cli.review_findings(cli.load_review(cli.review_path()))
    except (OSError, ValueError, json.JSONDecodeError):
        current = set()

    print()
    for key in sorted(found - current):
        print(f"NEW      {key[0]} in {key[1]} ({key[2]})")
    for key in sorted(current - found):
        print(f"GONE     {key[0]} in {key[1]} ({key[2]})")
    for key in sorted(found & current):
        print(f"KNOWN    {key[0]} in {key[1]} ({key[2]})")

    draft = {
        "version": 1,
        "package": cli.SKILLS_PACKAGE,
        "package_version": version,
        "shasum": shasum,
        "integrity": integrity,
        "source": "https://github.com/vercel-labs/skills",
        "scanner": "guarddog npm scan (ghcr.io/datadog/guarddog:latest)",
        "reviewed_on": "YYYY-MM-DD",
        "note": "REVIEW ME -- describe how this wrapper's invocation neutralises the findings below.",
        "findings": [
            {"rule": rule, "file": path, "match": match,
             "reason": "REVIEW ME"}
            for rule, path, match in sorted(found)
        ],
    }
    print(f"\nGuardDog verdict for {version}: "
          f"{'SAFE' if verdict == 0 else 'BLOCK' if verdict == 1 else 'NO VERDICT'}")
    print(f"Draft for scripts/reviewed/skills-cli-{version}.json:\n")
    print(json.dumps(draft, indent=2))
    print("\nNothing was written. Fill in every REVIEW ME, save the file, then "
          "raise SKILLS_VERSION / SKILLS_SHASUM / SKILLS_INTEGRITY in "
          "scripts/_skills_cli.py.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--latest", action="store_true",
                       help="compare the pin against the registry's latest release")
    group.add_argument("--update", metavar="VERSION",
                       help="scan a candidate version and print a reviewed-findings draft")
    args = parser.parse_args()

    if args.latest:
        return latest()
    if args.update:
        return update(args.update)
    return check()


if __name__ == "__main__":
    import _console

    _console.utf8_stdio()
    sys.exit(main())
