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
import http.client
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

import _versions
from _mcp_locked import normalize_pypi

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: a uv.lock then cannot be checked.
    tomllib = None

MIN_AGE_DAYS = 7
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAILS_URL = "https://api.osv.dev/v1/vulns/"
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
_GITHUB_COMPARISON = re.compile(r"(>=|<=|>|<|=)\s*(\S+)")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_SEVERITIES = {"low", "moderate", "high", "critical"}


class NoVerdict(Exception):
    """The lockfile cannot be checked completely."""


class LookupFailed(Exception):
    """A registry or advisory lookup did not give a usable answer."""

    def __init__(self, message: str, status: int | None = None, host: str = ""):
        super().__init__(message)
        self.status = status
        self.host = host


@dataclass(frozen=True)
class Entry:
    ecosystem: str
    name: str
    version: str
    integrity: str = ""
    files: tuple = field(default=())  # PyPI: (filename, sha256) of every locked file
    all_files: bool = False  # PyPI build tool without locked files: judge every file of the version
    hashes: tuple = ()  # PyPI files locked by SHA-256 without filenames

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"


def _package_name(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if ecosystem == "PyPI" else name


def entry_key(entry: Entry) -> tuple[str, str, str]:
    return entry.ecosystem, _package_name(entry.ecosystem, entry.name), entry.version


@dataclass(frozen=True)
class Advisory:
    entry: Entry | None
    id: str
    source: str
    aliases: tuple = ()
    severity: str | None = None
    withdrawn: bool = False
    affected: tuple = ()

    def as_case(self) -> dict:
        return {"id": self.id, "source": self.source, "aliases": list(self.aliases),
                "severity": self.severity, "withdrawn": self.withdrawn,
                "affected": [dict(interval) for interval in self.affected]}


@dataclass(frozen=True)
class Young:
    entry: Entry
    published: str
    limit_days: int
    wait_until: str


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
    advisories: list = field(default_factory=list)
    young: list = field(default_factory=list)
    failures: list = field(default_factory=list)
    blocking: list = field(default_factory=list)  # findings that are not advisories (hash, integrity)


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


def _origin(url: str) -> tuple:
    parts = urllib.parse.urlsplit(url)
    default_port = {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme, parts.hostname, parts.port if parts.port is not None else default_port


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        origin = _origin(req.full_url)
        if origin != _origin(newurl):
            fp.close()
            raise LookupFailed("redirect to a different origin refused", host=origin[1] or "")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
    host = ""
    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        opener = urllib.request.build_opener(_SameOriginRedirect())
        with opener.open(req, timeout=60) as response:
            host = urllib.parse.urlsplit(response.geturl()).hostname or ""
            status = response.getcode()
            if status != 200:
                raise LookupFailed(f"HTTP {status} from {url.split('?')[0]}",
                                   status=status, host=host)
            return json.load(response), _next_link(response.headers.get("Link"))
    except urllib.error.HTTPError as exc:
        try:
            host = urllib.parse.urlsplit(exc.url).hostname or ""
        except (TypeError, ValueError):
            host = ""
        finally:
            exc.close()
        raise LookupFailed(f"HTTP {exc.code} from {url.split('?')[0]}",
                           status=exc.code, host=host) from exc
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise LookupFailed(f"{url.split('?')[0]}: {exc}", host=host) from exc


# ── Checks ───────────────────────────────────────────────────────────────────

_BAD_RESPONSE = (LookupFailed, AttributeError, KeyError, TypeError, ValueError)
_BAD_AGE = (*_BAD_RESPONSE, OverflowError)


def _array(value, field_name):
    if not isinstance(value, list):
        raise LookupFailed(f"invalid {field_name} list")
    return value


def _text(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise LookupFailed(f"invalid {field_name}")
    return value


def _severity(value, *, github=False):
    if value is None:
        return None
    severity = _text(value, "severity").lower()
    if github and severity == "medium":
        return "moderate"
    if severity not in _SEVERITIES:
        raise LookupFailed(f"unknown severity: {value!r}")
    return severity


def _aliases(values):
    return tuple(dict.fromkeys(_text(value, "advisory alias") for value in values))


def _interval(lower=None, upper=None, lower_inclusive=True, upper_inclusive=False, fixed=None):
    return {"lower": lower, "upper": upper, "lower_inclusive": lower_inclusive,
            "upper_inclusive": upper_inclusive, "fixed": fixed}


def _withdrawn(value):
    if value is None:
        return False
    _text(value, "withdrawal date")
    return True


def _osv_range(entry, events):
    intervals = []
    lower = None
    opened = False
    for event in _array(events, "OSV events"):
        if not isinstance(event, dict) or len(event) != 1:
            raise LookupFailed("invalid OSV range event")
        action, version = next(iter(event.items()))
        _text(version, "OSV event version")
        if action == "introduced" and not opened:
            lower = None if version == "0" else version
            lower_key = _versions.key(entry.ecosystem, lower) if lower is not None else None
            if intervals:
                previous = intervals[-1]
                previous_end = _versions.key(entry.ecosystem, previous["upper"])
                if (lower_key is None or lower_key < previous_end
                        or (lower_key == previous_end and previous["upper_inclusive"])):
                    raise LookupFailed("OSV range events are out of order")
            opened = True
        elif action in ("fixed", "last_affected") and opened:
            upper_inclusive = action == "last_affected"
            if lower is not None and not upper_inclusive and (
                    _versions.key(entry.ecosystem, lower) == _versions.key(entry.ecosystem, version)):
                raise LookupFailed("empty OSV affected interval")
            intervals.append(_interval(lower, version, upper_inclusive=upper_inclusive,
                                       fixed=None if upper_inclusive else version))
            opened = False
        else:
            raise LookupFailed(f"unsupported or out-of-order OSV event: {action}")
    if opened:
        intervals.append(_interval(lower))
    if not intervals:
        raise LookupFailed("OSV range has no affected intervals")
    return intervals


def _osv_advisory(advisory, details):
    entry = advisory.entry
    if details["id"] != advisory.id:
        raise LookupFailed("OSV detail ID does not match the batch hit")
    intervals = []
    explicit_versions = []
    git_range = supported_range = False
    for affected in _array(details["affected"], "OSV affected packages"):
        package = affected["package"]
        ecosystem = _text(package["ecosystem"], "OSV package ecosystem")
        name = _text(package["name"], "OSV package name")
        if (ecosystem, _package_name(ecosystem, name)) != entry_key(entry)[:2]:
            continue
        ranges = _array(affected.get("ranges", []), "OSV ranges")
        versions = _array(affected.get("versions", []), "OSV versions")
        explicit_versions.extend(_text(v, "OSV explicit version") for v in versions)
        for record in ranges:
            kind = record["type"]
            if kind == "GIT":
                git_range = True
            elif kind in ("SEMVER", "ECOSYSTEM"):
                supported_range = True
                intervals.extend(_osv_range(entry, record["events"]))
            else:
                raise LookupFailed(f"unsupported OSV range type: {kind!r}")
    if git_range and not supported_range:
        raise LookupFailed("OSV gives only Git ranges for this package")
    # Interpret every interval, including a range after one that already matches.
    matches = [_versions.in_interval(entry.ecosystem, entry.version, interval)
               for interval in intervals]
    explicit = []
    for version in dict.fromkeys(explicit_versions):
        if not any(_versions.in_interval(entry.ecosystem, version, interval)
                   for interval in intervals):
            interval = _interval(version, version, upper_inclusive=True)
            explicit.append(interval)
            matches.append(_versions.in_interval(entry.ecosystem, entry.version, interval))
    if not any(matches):
        raise LookupFailed("OSV details do not cover the batch hit")
    return replace(advisory, affected=tuple(intervals + explicit),
                   aliases=_aliases(_array(details.get("aliases", []), "OSV aliases")),
                   severity=_severity(details.get("database_specific", {}).get("severity")),
                   withdrawn=_withdrawn(details.get("withdrawn")))


def _osv(entries, fetch, findings, advisories, failures):
    details_by_id = {}
    for start in range(0, len(entries), OSV_CHUNK):
        chunk = entries[start:start + OSV_CHUNK]
        queries = [{"package": {"name": e.name, "ecosystem": e.ecosystem}, "version": e.version}
                   for e in chunk]
        try:
            body, _ = fetch(OSV_BATCH_URL, {"queries": queries})
            results = body["results"]
            if not isinstance(results, list):
                raise LookupFailed("OSV returned no batch result list")
        except _BAD_RESPONSE as exc:
            failures.append(f"OSV: {exc}")
            continue
        aligned = len(results) == len(chunk)
        if not aligned:
            failures.append("OSV: OSV returned a different number of results")
        for index, res in enumerate(results):
            entry = chunk[index] if aligned else None
            label = entry.label if entry is not None else "package not identifiable"
            try:
                hits = _array(res.get("vulns", []), "OSV hits")
                if res.get("next_page_token") not in (None, ""):
                    failures.append(f"OSV {label}: more batch results are available")
            except _BAD_RESPONSE as exc:
                failures.append(f"OSV {label}: {exc}")
                continue
            if hits:
                ids = [hit.get("id") if isinstance(hit, dict) else None for hit in hits]
                labels = [i if isinstance(i, str) and i else "?" for i in ids]
                findings.append(f"{label}: OSV {', '.join(labels)}")
                for hit_id in ids:
                    try:
                        _text(hit_id, "OSV batch hit ID")
                    except LookupFailed as exc:
                        failures.append(f"OSV {label}: {exc}")
                        continue
                    source = "osv-malware" if hit_id.startswith("MAL-") else "osv"
                    advisory = Advisory(entry, hit_id, source)
                    try:
                        if entry is not None:
                            if hit_id not in details_by_id:
                                url = OSV_DETAILS_URL + urllib.parse.quote(hit_id, safe="")
                                details_by_id[hit_id], _ = fetch(url)
                            advisory = _osv_advisory(advisory, details_by_id[hit_id])
                    except _BAD_RESPONSE as exc:
                        failures.append(f"OSV {label} {hit_id}: {exc}")
                    advisories.append(advisory)


def _github_interval(ecosystem, vulnerability):
    raw = _text(vulnerability.get("vulnerable_version_range"), "vulnerable version range")
    interval = _interval()
    for comparison in raw.split(","):
        match = _GITHUB_COMPARISON.fullmatch(comparison.strip())
        if match is None:
            raise LookupFailed(f"unsupported GitHub range: {raw!r}")
        operator, version = match.groups()
        if operator == "=":
            sides = ("lower", "upper")
        else:
            sides = ("lower",) if operator.startswith(">") else ("upper",)
        for side in sides:
            if interval[side] is not None:
                raise LookupFailed(f"duplicate GitHub bound: {raw!r}")
            interval[side] = version
            interval[f"{side}_inclusive"] = "=" in operator
    fixed = vulnerability.get("first_patched_version")
    if isinstance(fixed, dict):
        fixed = _text(fixed.get("identifier"), "first patched version")
    if fixed is not None:
        _versions.key(ecosystem, fixed)
    interval["fixed"] = fixed
    return interval


def _github_advisories(item, kind, chunk, findings, advisories, failures):
    rows = item.get("vulnerabilities")
    advisory_id = item.get("ghsa_id")
    label = advisory_id if isinstance(advisory_id, str) and advisory_id else "?"
    names = set()
    if isinstance(rows, list):
        for row in rows:
            package = row.get("package") if isinstance(row, dict) else None
            name = package.get("name") if isinstance(package, dict) else None
            names.add(name if isinstance(name, str) else "?")
    findings.append(f"GitHub {kind} {label} ({', '.join(sorted(names)) or 'package not named'})")
    source_kind = "malware" if item.get("type") == "malware" else kind
    advisory = Advisory(None, label, f"github-{source_kind}")
    failure_prefix = f"GitHub {kind} {label}"
    try:
        _text(advisory_id, "GitHub advisory ID")
        if item.get("type", kind) != kind:
            raise LookupFailed("advisory type differs from the requested type")
        cve = item.get("cve_id")
        identifiers = _array(item.get("identifiers", []), "GitHub identifiers")
        aliases = ([cve] if cve is not None else []) + [i["value"] for i in identifiers]
        advisory = replace(advisory, aliases=_aliases(aliases),
                           severity=_severity(item.get("severity"), github=True),
                           withdrawn=_withdrawn(item.get("withdrawn_at")))
        rows = _array(rows, "GitHub vulnerabilities")
    except _BAD_RESPONSE as exc:
        failures.append(f"{failure_prefix}: {exc}")
        advisories.append(advisory)
        return
    before = len(advisories)
    ecosystem = chunk[0].ecosystem
    for row in rows:
        try:
            package = row["package"]
            name = _text(package["name"], "GitHub package name")
            reported_ecosystem = package.get("ecosystem", GITHUB_ECOSYSTEM[ecosystem])
            _text(reported_ecosystem, "GitHub package ecosystem")
            if reported_ecosystem != GITHUB_ECOSYSTEM[ecosystem]:
                continue
            name = _package_name(ecosystem, name)
            matching = [entry for entry in chunk if entry_key(entry)[1] == name]
            if not matching:
                continue
            interval = _github_interval(ecosystem, row)
            for entry in matching:
                if _versions.in_interval(ecosystem, entry.version, interval):
                    advisories.append(replace(advisory, entry=entry, affected=(interval,)))
        except _BAD_RESPONSE as exc:
            failures.append(f"{failure_prefix}: {exc}")
    if len(advisories) == before:
        advisories.append(advisory)


def _github(entries, fetch, findings, advisories, failures):
    for ecosystem in sorted({e.ecosystem for e in entries}):
        group = [e for e in entries if e.ecosystem == ecosystem]
        for kind in ("reviewed", "malware"):
            for start in range(0, len(group), GITHUB_CHUNK):
                chunk = group[start:start + GITHUB_CHUNK]
                query = urllib.parse.urlencode({
                    "type": kind, "ecosystem": GITHUB_ECOSYSTEM[ecosystem],
                    "affects": ",".join(e.label for e in chunk), "per_page": 100})
                url = f"{GITHUB_ADVISORIES_URL}?{query}"
                seen = set()
                try:
                    while url:
                        if _origin(url) != _origin(GITHUB_ADVISORIES_URL) or url in seen:
                            raise LookupFailed("invalid GitHub advisory pagination")
                        seen.add(url)
                        body, next_url = fetch(url)
                        if not isinstance(body, list):
                            raise LookupFailed("GitHub returned no advisory list")
                        for adv in body:
                            if isinstance(adv, dict):
                                _github_advisories(adv, kind, chunk, findings, advisories, failures)
                            else:
                                failures.append(f"GitHub {kind}: invalid advisory")
                        url = urllib.parse.urljoin(url, next_url) if next_url is not None else None
                except _BAD_RESPONSE as exc:
                    failures.append(f"GitHub {kind}: {exc}")


def _advisory_checks(entries, fetch):
    findings, advisories, failures = [], [], []
    supported = []
    for entry in entries:
        if entry.ecosystem in GITHUB_ECOSYSTEM:
            supported.append(entry)
        else:
            failures.append(f"{entry.label}: unsupported ecosystem {entry.ecosystem!r}")
    _osv(supported, fetch, findings, advisories, failures)
    _github(supported, fetch, findings, advisories, failures)
    return findings, advisories, failures


def advisories_for(entries: list[Entry], fetch=http_fetch) -> tuple[list[Advisory], list[str]]:
    _, advisories, failures = _advisory_checks(entries, fetch)
    return advisories, failures


def _parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class _AgeCheck:
    findings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    young: Young | None = None
    wait_line: str = ""


def _record_wait(result, entry, what, published, now, limit):
    stamp = _parse_time(published)
    delay = dt.timedelta(days=limit)
    if stamp <= now - delay:
        return
    ready = (stamp + delay).date().isoformat()
    # Keep the first wait message. The structured result must cover every file.
    if not result.wait_line:
        result.wait_line = (f"{entry.label}: {what} {published}, younger than {limit} days; "
                            f"wait until {ready}")
    if result.young is None or stamp > _parse_time(result.young.published):
        result.young = Young(entry, published, limit, ready)


def _age_npm(entry, fetch, now, limit, result):
    body, _ = fetch(NPM_REGISTRY_URL + urllib.parse.quote(entry.name, safe="@"))
    published = (body.get("time") or {}).get(entry.version)
    integrity = ((body.get("versions") or {}).get(entry.version) or {}).get("dist", {}).get("integrity")
    if integrity != entry.integrity and (integrity is not None or published):
        result.findings.append(f"{entry.label}: locked integrity differs from the registry")
    if not published:
        raise LookupFailed(f"{entry.label}: registry has no publish time")
    _text(integrity, "registry integrity")
    _record_wait(result, entry, "published", published, now, limit)


def _sha256(value):
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise LookupFailed("invalid SHA-256 digest")
    return value.lower()


def _age_pypi(entry, fetch, now, limit, result):
    name = urllib.parse.quote(entry.name)
    body, _ = fetch(f"{PYPI_JSON_URL}{name}/{urllib.parse.quote(entry.version)}/json")
    known = {}
    listed = body["urls"] if entry.hashes else body.get("urls", [])
    for info in _array(listed, "PyPI files"):
        try:
            filename = _text(info.get("filename"), "PyPI filename")
            if filename in known:
                raise LookupFailed(f"duplicate PyPI filename: {filename}")
            known[filename] = info
        except _BAD_RESPONSE as exc:
            result.failures.append(str(exc))

    if entry.hashes:
        locked_hashes = {_sha256(digest): digest for digest in entry.hashes}
        found_hashes = set()
        wanted = []
        for filename, info in known.items():
            try:
                digest = _sha256(info["digests"]["sha256"])
                if digest in locked_hashes:
                    found_hashes.add(digest)
                    wanted.append((filename, None))
            except _BAD_RESPONSE as exc:
                result.failures.append(f"{filename}: {exc}")
        if not result.failures:
            for digest, original in locked_hashes.items():
                if digest not in found_hashes:
                    result.findings.append(f"{entry.label}: {original} hash differs from PyPI")
    elif entry.all_files:
        if not known:
            raise LookupFailed(f"{entry.label}: PyPI lists no files for this version")
        wanted = [(filename, None) for filename in known]
    else:
        wanted = entry.files
        if not wanted:
            raise LookupFailed(f"{entry.label}: no locked PyPI files or hashes")

    for filename, digest in wanted:
        try:
            info = known.get(filename)
            if info is None:
                raise LookupFailed(f"{entry.label}: PyPI does not list {filename}")
            if digest is not None:
                actual = _text(info["digests"]["sha256"], "PyPI SHA-256")
                if actual != digest:
                    result.findings.append(f"{entry.label}: {filename} hash differs from PyPI")
            if not info.get("upload_time_iso_8601"):
                raise LookupFailed(f"{entry.label}: PyPI does not list {filename}")
            _record_wait(result, entry, f"{filename} uploaded", info["upload_time_iso_8601"],
                         now, limit)
        except _BAD_AGE as exc:
            result.failures.append(str(exc))


def _validate_age_limit(value):
    if type(value) is not int or value < 0:
        raise LookupFailed("age limit must be a nonnegative integer")


def _ages(entries, fetch, now, min_age_days, age_limits):
    def one(entry):
        result = _AgeCheck()
        try:
            limit = age_limits.get(entry_key(entry), min_age_days)
            _validate_age_limit(limit)
            if entry.ecosystem == "npm":
                _age_npm(entry, fetch, now, limit, result)
            elif entry.ecosystem == "PyPI":
                _age_pypi(entry, fetch, now, limit, result)
        except _BAD_AGE as exc:
            result.failures.append(str(exc))
        result.failures = [f"age of {entry.label}: {f}" for f in result.failures]
        return result

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(one, dict.fromkeys(entries)))


def check(entries: list[Entry], *, now: dt.datetime | None = None, fetch=http_fetch,
          min_age_days: int = MIN_AGE_DAYS, age_limits: Mapping[tuple, int] | None = None,
          ages: bool = True) -> Result:
    """Run every check over *entries*; 0 clean, 1 finding, 2 no verdict.

    Check age and registry hashes unless ages=False. A young entry gives no
    verdict and the day on which it becomes eligible (#48, K10)."""
    if not entries:
        return Result(2, ["NO VERDICT -- the lockfile lists no packages"])
    findings, advisories, failures = _advisory_checks(entries, fetch)
    notes = list(failures)
    young, blocking = [], []
    limits = age_limits if age_limits is not None else {}
    if ages:
        try:
            _validate_age_limit(min_age_days)
        except LookupFailed as exc:
            failures.append(str(exc))
            notes.append(str(exc))
        else:
            for age in _ages(entries, fetch, now or dt.datetime.now(dt.timezone.utc),
                             min_age_days, limits):
                findings.extend(age.findings)
                blocking.extend(age.findings)
                failures.extend(age.failures)
                if age.young is not None:
                    young.append(age.young)
                notes.extend(age.failures)
                if age.wait_line and not age.findings:
                    notes.append(age.wait_line)
    if findings:
        return Result(1, [f"[BLOCK] lockfile finding: {f}" for f in findings]
                      + [f"(also unchecked: {f})" for f in notes],
                      advisories, young, failures, blocking)
    if notes:
        return Result(2, [f"NO VERDICT -- {f}" for f in notes], advisories, young, failures)
    summary = f"Lockfile check passed: {len(entries)} entries, no advisory"
    if ages:
        if any(limits.get(entry_key(e), min_age_days) != min_age_days for e in entries):
            summary += ", all meet their age limits"
        else:
            summary += f", all at least {min_age_days} days old"
    return Result(0, [summary + "."])
