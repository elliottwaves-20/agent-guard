"""Check every entry of an MCP server lockfile before the tree is installed (#48).

A SAFE package scan covers one package. What runs is the whole dependency
tree, so the locked MCP installers check each lockfile entry here:

- it comes from the public registry (npm: registry.npmjs.org with an
  integrity hash; uv: https://pypi.org/simple with file hashes) -- git, file,
  link, bundled or other-index entries cannot be looked up and give no verdict;
- OSV knows no advisory for the exact version (this covers the OpenSSF
  malicious-packages feed and the reviewed GitHub advisories);
- GitHub's advisory API knows no reviewed or malware advisory for it (GitHub's
  malware advisories are not part of the database OSV imports);
- the version (npm) or every locked file (PyPI) was published at least
  MIN_AGE_DAYS ago (younger means wait: no verdict with the date), and the
  registry's hash matches the locked one;
- a uv.lock may hold one Git entry only when the installer names it (GitPin):
  the scanned repository at the scanned commit.

Result codes follow the wrappers: 0 clean, 1 finding, 2 no verdict. A finding
wins over a lookup failure; any lookup that fails, is rate limited or returns
something unreadable gives no verdict (fail-closed).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: a uv.lock then cannot be checked.
    tomllib = None

MIN_AGE_DAYS = 7
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
NPM_REGISTRY_URL = "https://registry.npmjs.org/"
PYPI_JSON_URL = "https://pypi.org/pypi/"
PYPI_SIMPLE = "https://pypi.org/simple"
OSV_CHUNK = 500
GITHUB_CHUNK = 40
GITHUB_ECOSYSTEM = {"npm": "npm", "PyPI": "pip"}
WORKERS = 8
_PIN_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_PIN_VERSION = re.compile(r"[0-9][0-9A-Za-z.+!-]*")


class NoVerdict(Exception):
    """The lockfile cannot be checked completely."""


class LookupFailed(Exception):
    """A registry or advisory lookup did not give a usable answer."""


@dataclass(frozen=True)
class Entry:
    ecosystem: str
    name: str
    version: str
    integrity: str = ""
    files: tuple = field(default=())  # PyPI: (filename, sha256) of every locked file
    all_files: bool = False  # PyPI build tool without locked files: judge every file of the version

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class GitPin:
    """The one Git entry a uv.lock may hold: the scanned repository at the scanned commit."""
    name: str
    url: str
    sha: str
    subdirectory: str = ""


@dataclass
class Result:
    code: int
    lines: list


# ── Lockfile parsing ─────────────────────────────────────────────────────────

def _npm_name(key: str, entry: dict) -> str:
    if entry.get("name"):
        return entry["name"]
    return key.rsplit("node_modules/", 1)[-1]


def npm_lock_entries(lock: dict) -> list[Entry]:
    """Registry entries of a package-lock.json (lockfileVersion 2 or 3)."""
    if lock.get("lockfileVersion") not in (2, 3):
        raise NoVerdict(f"unsupported lockfileVersion {lock.get('lockfileVersion')!r}")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise NoVerdict("lockfile has no packages table")
    entries = []
    for key, entry in packages.items():
        if key == "":
            continue
        if not isinstance(entry, dict) or not key.startswith("node_modules/"):
            raise NoVerdict(f"entry outside node_modules: {key!r}")
        if entry.get("link") or entry.get("inBundle"):
            raise NoVerdict(f"linked or bundled entry cannot be looked up: {key}")
        version, resolved, integrity = entry.get("version"), entry.get("resolved"), entry.get("integrity")
        if not isinstance(version, str) or not version:
            raise NoVerdict(f"entry without version: {key}")
        if not isinstance(resolved, str) or not resolved.startswith(NPM_REGISTRY_URL):
            raise NoVerdict(f"entry not from {NPM_REGISTRY_URL}: {key} ({resolved!r})")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            raise NoVerdict(f"entry without sha512 integrity: {key}")
        entries.append(Entry("npm", _npm_name(key, entry), version, integrity=integrity))
    if not entries:
        raise NoVerdict("lockfile lists no packages")
    return entries


def npm_top_level(lock: dict, package: str, version: str, overrides: dict) -> str:
    """Integrity of the requested top-level package; every override resolved exactly."""
    top = (lock.get("packages") or {}).get(f"node_modules/{package}")
    if not isinstance(top, dict) or top.get("version") != version:
        found = top.get("version") if isinstance(top, dict) else None
        raise NoVerdict(f"lockfile resolves {package} to {found!r}, not the pinned {version}")
    integrity = top.get("integrity")
    if not isinstance(integrity, str) or not integrity:
        raise NoVerdict(f"lockfile has no integrity for {package}")
    for name, wanted in overrides.items():
        found = [entry.get("version") for key, entry in lock["packages"].items()
                 if key and isinstance(entry, dict) and _npm_name(key, entry) == name]
        if not found:
            raise NoVerdict(f"override {name}={wanted} does not appear in the lockfile")
        if any(v != wanted for v in found):
            raise NoVerdict(f"override {name}={wanted} is not resolved exactly "
                            f"(lockfile has {', '.join(sorted(set(map(str, found))))})")
    return integrity


def _github_repo(url: str) -> str | None:
    """'owner/repo' (lower case) of an https://github.com URL, else None."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc.lower() != "github.com":
        return None
    path = parts.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    segments = path.split("/")
    if len(segments) != 2 or not all(segments):
        return None
    return "/".join(segments).lower()


def _check_git_source(name: str, git_url: str, pin: GitPin) -> None:
    parts = urllib.parse.urlsplit(git_url)
    query = urllib.parse.parse_qs(parts.query)
    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    if name != pin.name:
        raise NoVerdict(f"git entry {name!r} is not the scanned package {pin.name!r}")
    repo = _github_repo(base)
    if repo is None or repo != _github_repo(pin.url):
        raise NoVerdict(f"git entry {name} comes from {base}, not the scanned {pin.url}")
    if query.get("rev") != [pin.sha] or parts.fragment != pin.sha:
        raise NoVerdict(f"git entry {name} is not pinned to the scanned commit {pin.sha}")
    if query.get("subdirectory", [""]) != [pin.subdirectory]:
        raise NoVerdict(f"git entry {name} uses another subdirectory than the scanned one")
    if set(query) - {"rev", "subdirectory"}:
        raise NoVerdict(f"git entry {name} has unexpected options: {parts.query}")


def pinned_entries(text: str) -> list[Entry]:
    """Exact `name==version` lines of `uv pip compile` output (build tools)."""
    entries = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, sep, version = line.partition("==")
        if (not sep or not _PIN_NAME.fullmatch(name.strip())
                or not _PIN_VERSION.fullmatch(version.strip())):
            raise NoVerdict(f"build requirement is not an exact pin: {raw.strip()!r}")
        entries.append(Entry("PyPI", name.strip(), version.strip(), all_files=True))
    if not entries:
        raise NoVerdict("the build requirements resolved to nothing")
    return entries


def _file_name(url: str) -> str:
    return urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])


def uv_lock_entries(text: str, root_name: str, git: GitPin | None = None) -> list[Entry]:
    """Registry entries of a uv.lock; the virtual root project is skipped.

    With `git`, exactly one Git entry -- the scanned repository at the scanned
    commit -- must be present; it is checked here and not returned (OSV and
    GitHub know nothing about a commit, its age is checked by the installer)."""
    if tomllib is None:
        raise NoVerdict("reading uv.lock needs Python 3.11+ (tomllib)")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise NoVerdict(f"unreadable uv.lock: {exc}") from exc
    entries = []
    git_seen = 0
    for pkg in data.get("package", []):
        name, version, source = pkg.get("name"), pkg.get("version"), pkg.get("source") or {}
        if source.get("virtual") == "." and name == root_name:
            continue
        if git is not None and set(source) == {"git"} and isinstance(source["git"], str):
            _check_git_source(name, source["git"], git)
            git_seen += 1
            if git_seen > 1:
                raise NoVerdict("uv.lock holds more than one git entry")
            continue
        if source.get("registry") != PYPI_SIMPLE:
            raise NoVerdict(f"entry not from {PYPI_SIMPLE}: {name} ({source!r})")
        if not isinstance(name, str) or not isinstance(version, str):
            raise NoVerdict(f"entry without name or version: {pkg!r}")
        files = []
        for item in ([pkg["sdist"]] if "sdist" in pkg else []) + list(pkg.get("wheels", [])):
            url, digest = item.get("url"), item.get("hash", "")
            if not url or not digest.startswith("sha256:"):
                raise NoVerdict(f"locked file without url or sha256: {name}")
            files.append((_file_name(url), digest.split(":", 1)[1]))
        if not files:
            raise NoVerdict(f"entry without locked files: {name}")
        entries.append(Entry("PyPI", name, version, files=tuple(files)))
    if git is not None and git_seen == 0:
        raise NoVerdict(f"uv.lock has no git entry for the scanned package {git.name}")
    if not entries and git_seen == 0:
        raise NoVerdict("uv.lock lists no packages")
    return entries


# ── Network ──────────────────────────────────────────────────────────────────

def _next_link(header: str | None) -> str | None:
    for part in (header or "").split(","):
        if 'rel="next"' in part:
            return part.split(";", 1)[0].strip().strip("<>")
    return None


def http_fetch(url: str, payload: dict | None = None) -> tuple[object, str | None]:
    """GET (or POST JSON) and return (parsed body, next-page URL)."""
    headers = {"User-Agent": "agent-guard", "Accept": "application/json"}
    if url.startswith(GITHUB_ADVISORIES_URL):
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r), _next_link(r.headers.get("Link"))
    except urllib.error.HTTPError as exc:
        raise LookupFailed(f"HTTP {exc.code} from {url.split('?')[0]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise LookupFailed(f"{url.split('?')[0]}: {exc}") from exc


# ── Checks ───────────────────────────────────────────────────────────────────

def _osv(entries, fetch, findings, failures):
    for start in range(0, len(entries), OSV_CHUNK):
        chunk = entries[start:start + OSV_CHUNK]
        queries = [{"package": {"name": e.name, "ecosystem": e.ecosystem}, "version": e.version}
                   for e in chunk]
        try:
            body, _ = fetch(OSV_BATCH_URL, {"queries": queries})
            results = body["results"]
            if not isinstance(results, list) or len(results) != len(chunk):
                raise LookupFailed("OSV returned a different number of results")
        except (LookupFailed, KeyError, TypeError) as exc:
            failures.append(f"OSV: {exc}")
            continue
        for entry, res in zip(chunk, results):
            ids = [v.get("id", "?") for v in (res or {}).get("vulns", [])]
            if ids:
                findings.append(f"{entry.label}: OSV {', '.join(ids)}")


def _github(entries, fetch, findings, failures):
    for ecosystem in sorted({e.ecosystem for e in entries}):
        group = [e for e in entries if e.ecosystem == ecosystem]
        for kind in ("reviewed", "malware"):
            for start in range(0, len(group), GITHUB_CHUNK):
                chunk = group[start:start + GITHUB_CHUNK]
                query = urllib.parse.urlencode({
                    "type": kind, "ecosystem": GITHUB_ECOSYSTEM[ecosystem],
                    "affects": ",".join(e.label for e in chunk), "per_page": 100})
                url = f"{GITHUB_ADVISORIES_URL}?{query}"
                try:
                    while url:
                        body, url = fetch(url)
                        if not isinstance(body, list):
                            raise LookupFailed("GitHub returned no advisory list")
                        for adv in body:
                            names = sorted({v.get("package", {}).get("name", "?")
                                            for v in adv.get("vulnerabilities") or []})
                            findings.append(f"GitHub {kind} {adv.get('ghsa_id', '?')} "
                                            f"({', '.join(names) or 'package not named'})")
                except LookupFailed as exc:
                    failures.append(f"GitHub {kind}: {exc}")


def _parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _too_young(label: str, what: str, published: str, cutoff: dt.datetime) -> str | None:
    """A wait message when `published` is newer than the cutoff, else None."""
    stamp = _parse_time(published)
    if stamp <= cutoff:
        return None
    ready = (stamp + dt.timedelta(days=MIN_AGE_DAYS)).date().isoformat()
    return (f"{label}: {what} {published}, younger than {MIN_AGE_DAYS} days; "
            f"wait until {ready}")


def _age_npm(entry, fetch, cutoff):
    """(finding, wait) for one npm entry; a lookup problem raises."""
    body, _ = fetch(NPM_REGISTRY_URL + urllib.parse.quote(entry.name, safe="@"))
    published = (body.get("time") or {}).get(entry.version)
    integrity = ((body.get("versions") or {}).get(entry.version) or {}).get("dist", {}).get("integrity")
    if not published:
        raise LookupFailed(f"{entry.label}: registry has no publish time")
    if integrity != entry.integrity:
        return f"{entry.label}: locked integrity differs from the registry", None
    return None, _too_young(entry.label, "published", published, cutoff)


def _age_pypi(entry, fetch, cutoff):
    """(finding, wait) for one PyPI entry; a lookup problem raises."""
    name = urllib.parse.quote(entry.name)
    body, _ = fetch(f"{PYPI_JSON_URL}{name}/{urllib.parse.quote(entry.version)}/json")
    listed = body.get("urls") or []
    known = {f.get("filename"): f for f in listed}
    if entry.all_files:
        if not listed:
            raise LookupFailed(f"{entry.label}: PyPI lists no files for this version")
        wanted = [(f.get("filename"), None) for f in listed]
    else:
        wanted = list(entry.files)
    wait = None
    for filename, digest in wanted:
        info = known.get(filename)
        if info is None or not info.get("upload_time_iso_8601"):
            raise LookupFailed(f"{entry.label}: PyPI does not list {filename}")
        if digest is not None and (info.get("digests") or {}).get("sha256") != digest:
            return f"{entry.label}: {filename} hash differs from PyPI", None
        wait = wait or _too_young(entry.label, f"{filename} uploaded",
                                  info["upload_time_iso_8601"], cutoff)
    return None, wait


def _ages(entries, fetch, cutoff, findings, failures):
    def one(entry):
        try:
            if entry.ecosystem == "npm":
                finding, wait = _age_npm(entry, fetch, cutoff)
            else:
                finding, wait = _age_pypi(entry, fetch, cutoff)
            return finding, wait
        except (LookupFailed, AttributeError, TypeError, ValueError) as exc:
            return None, f"age of {entry.label}: {exc}"
    unique = list(dict.fromkeys(entries))
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for finding, failure in pool.map(one, unique):
            if finding:
                findings.append(finding)
            if failure:
                failures.append(failure)


def check(entries: list[Entry], *, now: dt.datetime | None = None, fetch=http_fetch) -> Result:
    """Run every check over *entries*; 0 clean, 1 finding, 2 no verdict.

    An entry younger than MIN_AGE_DAYS is no finding but a reason to wait: it
    gives no verdict (2) with the date it becomes eligible (#48, K10)."""
    if not entries:
        return Result(2, ["NO VERDICT -- the lockfile lists no packages"])
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=MIN_AGE_DAYS)
    findings: list[str] = []
    failures: list[str] = []
    _osv(entries, fetch, findings, failures)
    _github(entries, fetch, findings, failures)
    _ages(entries, fetch, cutoff, findings, failures)
    if findings:
        return Result(1, [f"[BLOCK] lockfile finding: {f}" for f in findings]
                      + [f"(also unchecked: {f})" for f in failures])
    if failures:
        return Result(2, [f"NO VERDICT -- {f}" for f in failures])
    return Result(0, [f"Lockfile check passed: {len(entries)} entries, no advisory, "
                      f"all at least {MIN_AGE_DAYS} days old."])
