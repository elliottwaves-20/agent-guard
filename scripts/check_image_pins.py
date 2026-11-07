#!/usr/bin/env python3
"""Report newer releases of the pinned scanner images (GuardDog, malcontent).

The images are pinned by digest in _pins.py and never follow a moving tag.
This check keeps the pins from freezing: it compares the pinned versions with
the projects' GitHub releases and says when a newer release may be pinned
(at least 7 days after publication). It changes nothing.

Usage:
  check_image_pins.py                          report; exit 0 = up to date,
                                               1 = newer release, 2 = check failed
  check_image_pins.py --malcontent-candidate V print the newest minimal build of
                                               Chainguard's malcontent image that
                                               carries version V and is at least
                                               7 days old (for the manual bump)

GuardDog bump: pin ghcr.io/datadog/guarddog:<version>@<digest of that tag>.
Chainguard rebuilds malcontent:latest daily; base-package rebuilds do not
trigger a report, only a new malcontent release does.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import io
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request

import _pins

MIN_AGE = timedelta(days=7)
USER_AGENT = "agent-guard-check-image-pins"
# GitHub repo -> (display name, pinned version)
SCANNERS = {
    "DataDog/guarddog": ("GuardDog", _pins.GUARDDOG_VERSION),
    "chainguard-dev/malcontent": ("malcontent", _pins.MALCONTENT_VERSION),
}
# Packages that only the -dev variant (with a shell) carries.
DEV_ONLY_PACKAGES = ("busybox", "apk-tools", "bash")
_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def parse_version(tag: str):
    m = _VERSION.match(tag or "")
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def _parse_time(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def newer_releases(pinned: str, releases: list, now: datetime) -> list:
    """Stable releases newer than `pinned`, newest first. A release without a
    readable publish date is reported but never eligible."""
    base = parse_version(pinned)
    if base is None:
        raise ValueError(f"pinned version {pinned!r} is not a plain version")
    found = []
    for r in releases:
        if r.get("draft") or r.get("prerelease"):
            continue
        version = parse_version(r.get("tag_name", ""))
        if version is None or version <= base:
            continue
        published = _parse_time(r.get("published_at"))
        eligible_from = published + MIN_AGE if published else None
        found.append({"version": ".".join(map(str, version)), "published": published,
                      "eligible_from": eligible_from,
                      "eligible": eligible_from is not None and eligible_from <= now})
    found.sort(key=lambda r: parse_version(r["version"]), reverse=True)
    return found


def _get_json(url: str, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def fetch_releases(repo: str) -> list:
    return _get_json(f"https://api.github.com/repos/{repo}/releases?per_page=30",
                     {"Accept": "application/vnd.github+json"})


def check(fetch=fetch_releases, now=None) -> int:
    now = now or datetime.now(timezone.utc)
    rc = 0
    for repo, (name, pinned) in SCANNERS.items():
        try:
            newer = newer_releases(pinned, fetch(repo), now)
        except Exception as e:  # noqa: BLE001 -- any failure is a failed check (exit 2)
            print(f"[ERROR] {name}: could not check releases of {repo}: {e!r}")
            rc = 2
            continue
        if not newer:
            print(f"[OK] {name} {pinned} is up to date.")
            continue
        rc = max(rc, 1)
        for r in newer:
            if r["eligible"]:
                print(f"[UPDATE] {name} {r['version']} can be pinned "
                      f"(released {r['published']:%Y-%m-%d}); pinned is {pinned}.")
            elif r["eligible_from"]:
                print(f"[WAIT] {name} {r['version']} released {r['published']:%Y-%m-%d}; "
                      f"can be pinned from {r['eligible_from']:%Y-%m-%d %H:%M} UTC.")
            else:
                print(f"[WAIT] {name} {r['version']} has no readable release date; "
                      "check it by hand.")
    return rc


def pick_malcontent_candidate(builds, version: str, now: datetime):
    """First build (newest first) that is at least MIN_AGE old, carries
    malcontent `version` and none of the -dev packages. `packages` may be a
    callable so that only the builds old enough are downloaded."""
    want = parse_version(version)
    for b in builds:
        if b["created"] > now - MIN_AGE:
            continue
        packages = b["packages"]() if callable(b["packages"]) else b["packages"]
        have = parse_version((packages.get("malcontent") or "").split("-r")[0])
        if have is None:
            continue
        if have < want:
            return None  # older builds only carry older versions
        if have == want and not any(p in packages for p in DEV_ONLY_PACKAGES):
            return b
    return None


# --- Chainguard registry (read-only; layers are read as data, never run) ---
_CGR = "https://cgr.dev/v2/chainguard/malcontent"
_INDEX = "application/vnd.oci.image.index.v1+json"
_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Above this share of unreadable builds the list is too incomplete to trust.
MAX_FAILED_SHARE = 0.1


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class _Registry:
    def __init__(self):
        self.token = _get_json("https://cgr.dev/token?scope=repository:chainguard/malcontent:pull")["token"]
        self.opener = urllib.request.build_opener(_NoRedirect)

    def manifest(self, ref: str, accept: str) -> dict:
        return _get_json(f"{_CGR}/manifests/{ref}",
                         {"Authorization": f"Bearer {self.token}", "Accept": accept})

    def blob(self, digest: str) -> bytes:
        # Blobs redirect to storage that rejects the registry token.
        req = urllib.request.Request(f"{_CGR}/blobs/{digest}", headers={
            "Authorization": f"Bearer {self.token}", "User-Agent": USER_AGENT})
        try:
            with self.opener.open(req, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            location = e.headers.get("Location") or ""
            if not location.startswith("https://"):
                raise ValueError(f"unexpected blob redirect: {location[:80]!r}")
            with urllib.request.urlopen(location, timeout=120) as r:
                return r.read()

    def digests(self) -> list:
        # Every signed build keeps a cosign tag sha256-<digest>.sig.
        tags, last = [], None
        while True:
            url = f"{_CGR}/tags/list?n=1000" + (f"&last={last}" if last else "")
            page = _get_json(url, {"Authorization": f"Bearer {self.token}"}).get("tags") or []
            page = [t for t in page if t not in tags]
            if not page:
                break
            tags += page
            last = page[-1]
        found = {"sha256:" + t[len("sha256-"):-len(".sig")]
                 for t in tags if t.startswith("sha256-") and t.endswith(".sig")}
        return sorted(d for d in found if _DIGEST.match(d))

    def amd64(self, digest: str):
        index = self.manifest(digest, _INDEX)
        if index.get("mediaType") != _INDEX:
            return None
        entry = next((m for m in index.get("manifests", [])
                      if m.get("platform", {}).get("architecture") == "amd64"), None)
        return self.manifest(entry["digest"], _MANIFEST) if entry else None

    def created(self, manifest: dict):
        config = json.loads(self.blob(manifest["config"]["digest"]))
        # "2026-10-28T15:02:56Z", possibly with fractional seconds; UTC.
        return datetime.strptime(config["created"][:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc)

    def packages(self, manifest: dict) -> dict:
        found = {}
        for layer in manifest["layers"]:
            with tarfile.open(fileobj=io.BytesIO(self.blob(layer["digest"])), mode="r:*") as t:
                for member in t.getmembers():
                    if member.isfile() and member.name.endswith("apk/db/installed"):
                        name = None
                        for line in t.extractfile(member).read().decode("utf-8", "replace").splitlines():
                            if line.startswith("P:"):
                                name = line[2:]
                            elif line.startswith("V:") and name:
                                found[name] = line[2:]
        return found


def malcontent_builds(reg):
    """All readable builds, newest first. Raises when too many builds could
    not be read: a gappy list could hide the right candidate."""
    failed = []

    def describe(digest):
        try:
            m = reg.amd64(digest)
            return (reg.created(m), digest, m) if m is not None else None
        except Exception as e:  # noqa: BLE001 -- counted below
            failed.append(e)
            return None

    digests = reg.digests()
    # ~2,000 signed builds with three small requests each: fetch in parallel.
    with ThreadPoolExecutor(max_workers=12) as pool:
        rows = [r for r in pool.map(describe, digests) if r]
    if not rows or len(failed) > MAX_FAILED_SHARE * len(digests):
        raise RuntimeError(f"{len(failed)} of {len(digests)} builds unreadable"
                           + (f", e.g. {failed[0]!r}" if failed else ""))
    rows.sort(key=lambda r: r[0], reverse=True)
    for created, digest, m in rows:
        yield {"created": created, "digest": digest,
               "packages": (lambda m=m: reg.packages(m))}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--malcontent-candidate", metavar="VERSION",
                    help="find the malcontent build to pin for VERSION")
    args = ap.parse_args(argv)
    if not args.malcontent_candidate:
        return check()
    now = datetime.now(timezone.utc)
    try:
        build = pick_malcontent_candidate(malcontent_builds(_Registry()),
                                          args.malcontent_candidate, now)
    except Exception as e:  # noqa: BLE001 -- any failure is a failed lookup (exit 2)
        print(f"[ERROR] registry lookup failed: {e!r}")
        return 2
    if build is None:
        print(f"[WAIT] no minimal build of malcontent {args.malcontent_candidate} "
              f"that is at least {MIN_AGE.days} days old was found: the version "
              "is too new, or it does not exist (check the spelling).")
        return 1
    print(f"cgr.dev/chainguard/malcontent:latest@{build['digest']}  "
          f"(built {build['created']:%Y-%m-%d %H:%M} UTC)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
