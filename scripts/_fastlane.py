"""Package age and security-fix decisions, with injected lookups for the contract."""
from __future__ import annotations

import base64
import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

import _lockcheck
import _versions
from _lockcheck import (NPM_REGISTRY_URL, PYPI_JSON_URL, Advisory, Entry, LookupFailed,
                        _array, _github_repo, _sha256, _text, advisories_for, entry_key)
from _mcp_locked import NeedsScan, Refused, normalize_pypi
from _mcp_receipts import require_receipt


@dataclass(frozen=True)
class Policy:
    min_age_days: int = 7
    trusted_days: int = 2
    fast_lane: bool = True


def policy(min_age_days: int | None, trusted_days: int | None, no_fast_lane: bool) -> Policy:
    defaults = Policy()
    minimum = defaults.min_age_days if min_age_days is None else min_age_days
    trusted = defaults.trusted_days if trusted_days is None else trusted_days
    if type(minimum) is not int or type(trusted) is not int or not 0 <= trusted <= minimum:
        raise Refused(2, "age settings must be integers with 0 <= trusted_days <= min_age_days")
    return Policy(minimum, trusted, not no_fast_lane)


_MALWARE = {"github-malware", "osv-malware"}
_SOURCES = {"github-reviewed", "osv"} | _MALWARE
_SEVERITY = {None: 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}
_REPO_PART = r"[a-z0-9_-][a-z0-9_.-]*"
_GITHUB_REPO = re.compile(rf"github\.com/{_REPO_PART}/{_REPO_PART}")
_PUBLISHER_REPO = re.compile(rf"[a-z0-9_-]+:{_REPO_PART}(?:/{_REPO_PART})+")


@dataclass
class _AdvisoryGroup:
    primary_ids: set[str]
    identities: set[str]
    severity: int
    withdrawn: bool
    intervals: list[dict]

    def representative(self) -> str:
        return min(self.primary_ids, key=lambda item: (not item.startswith("GHSA-"), item))


def _merge_advisories(advisories: list[dict]) -> list[_AdvisoryGroup]:
    groups = []
    for advisory in advisories:
        primary = advisory["id"]
        aliases = advisory["aliases"]
        withdrawn = advisory["withdrawn"]
        intervals = advisory["affected"]
        if (not isinstance(primary, str) or not primary or not isinstance(aliases, (list, tuple))
                or any(not isinstance(alias, str) or not alias for alias in aliases)
                or type(withdrawn) is not bool or not isinstance(intervals, (list, tuple))
                or advisory["source"] not in _SOURCES):
            raise TypeError("invalid advisory data")
        group = _AdvisoryGroup({primary}, {primary, *aliases},
                               _SEVERITY[advisory["severity"]], withdrawn, list(intervals))
        # Match every group that shares an identity, including groups joined by this row.
        related = [other for other in groups if group.identities & other.identities]
        for other in related:
            group.primary_ids.update(other.primary_ids)
            group.identities.update(other.identities)
            group.severity = max(group.severity, other.severity)
            group.withdrawn = group.withdrawn and other.withdrawn
            group.intervals.extend(other.intervals)
            groups.remove(other)
        groups.append(group)
    return groups


@dataclass(frozen=True)
class _Selection:
    reason: str
    version: str | None = None
    advisories: tuple[str, ...] = ()
    known_intervals: tuple[dict, ...] = ()


def _exact_fix(fixes: dict[str, tuple], choose) -> str | None:
    best = choose(fixes.values())
    pins = [version for version, order in fixes.items() if order == best]
    return pins[0] if len(pins) == 1 else None


def _select(data: dict) -> _Selection:
    if data.get("lookup_failed", False) is not False:
        return _Selection("lookup_failed")
    advisories = data["advisories"]
    if any(a["source"] in _MALWARE and a["withdrawn"] is False for a in advisories):
        return _Selection("malware")

    ecosystem, installed = data["ecosystem"], data["installed"]
    installed_order = _versions.key(ecosystem, installed)
    kev = data["kev"]
    if kev is None:
        return _Selection("kev_unavailable")
    if not isinstance(kev, (list, tuple, set, frozenset)):
        return _Selection("lookup_failed")
    kev = {item for item in kev if item.startswith("CVE-")}

    active_groups = [group for group in _merge_advisories(advisories) if not group.withdrawn]
    triggers = {}
    for group in active_groups:
        if group.severity < _SEVERITY["high"] and not group.identities & kev:
            continue
        applicable = [interval for interval in group.intervals
                      if _versions.in_interval(ecosystem, installed, interval)]
        if applicable:
            triggers[group.representative()] = applicable
    if not triggers:
        return _Selection("not_triggered")
    ids = tuple(sorted(triggers))
    enabled = data.get("settings", {}).get("fast_lane", Policy.fast_lane)
    if type(enabled) is not bool:
        return _Selection("lookup_failed", advisories=ids)
    if not enabled:
        return _Selection("disabled", advisories=ids)

    required_fixes = {}
    for intervals in triggers.values():
        fixes = {}
        for interval in intervals:
            version = interval["fixed"]
            if version is None:
                return _Selection("no_fix", advisories=ids)
            order = _versions.key(ecosystem, version)
            if order <= installed_order:
                return _Selection("no_fix", advisories=ids)
            fixes[version] = order
        smallest = _exact_fix(fixes, min)
        if smallest is None:
            return _Selection("no_fix", advisories=ids)
        required_fixes[smallest] = fixes[smallest]

    version = _exact_fix(required_fixes, max)
    if version is None:
        return _Selection("no_fix", advisories=ids)
    if _versions.is_prerelease(ecosystem, version):
        return _Selection("prerelease_fix", version, ids)
    if _versions.major(ecosystem, version) != _versions.major(ecosystem, installed):
        return _Selection("major", version, ids)
    known_intervals = tuple(interval for group in active_groups for interval in group.intervals)
    return _Selection("triggered", version, ids, known_intervals)


def _selection(data: dict) -> _Selection:
    try:
        return _select(data)
    except ValueError:
        return _Selection("unparsable_version")
    except (AttributeError, KeyError, TypeError):
        return _Selection("lookup_failed")


def select_fix(case: dict) -> tuple[str | None, str]:
    """Pick an eligible fix before fetching version-specific metadata."""
    selection = _selection(case.get("input"))
    version = selection.version if selection.reason == "triggered" else None
    return version, selection.reason


def _decision(action: str, *, version=None, tier=None, reason=None, wait_until=None,
              advisories=()) -> dict:
    return {"action": action, "version": version, "tier": tier, "reason": reason,
            "wait_until": wait_until, "advisories": list(advisories) if advisories else None}


def _timestamp(value: str) -> dt.datetime:
    stamp = dt.datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("release timestamps must have a timezone")
    return stamp.astimezone(dt.timezone.utc)


def _decide_age(data: dict) -> dict:
    settings = data.get("settings", {})
    limits = policy(settings.get("min_age_days"), settings.get("trusted_days"), False)
    trusted = data["ecosystem"] == "npm" and data.get("continuity") == "same"
    tier = "s1" if trusted else "s2"
    days = limits.trusted_days if trusted else limits.min_age_days
    threshold = _timestamp(data["published"]) + dt.timedelta(days=days)
    if _timestamp(data["now"]) >= threshold:
        return _decision("install", tier=tier)
    return _decision("wait", tier=tier, wait_until=threshold.date().isoformat())


def _valid_provenance(ecosystem: str, value: str) -> bool:
    return isinstance(value, str) and (
        value == "missing"
        or bool(_GITHUB_REPO.fullmatch(value))
        or (ecosystem == "PyPI" and bool(_PUBLISHER_REPO.fullmatch(value)))
    )


def _evaluate_fix(data: dict, version: str, known_intervals: tuple[dict, ...]) -> tuple[str, str, str | None]:
    unavailable = ("no_verdict", "lookup_failed", None)
    ecosystem = data["ecosystem"]
    record = data["versions"][version]
    residual = record["advisories"]
    pure_wheel = record.get("pure_wheel")
    if type(residual) is not int or residual < 0 or (
        ecosystem == "PyPI" and type(pure_wheel) is not bool
    ):
        return unavailable
    if residual > 0:
        return "report", "fix_has_advisory", None
    # A zero lookup count cannot clear known affected ranges from the input.
    known_matches = [_versions.in_interval(ecosystem, version, interval)
                     for interval in known_intervals]
    if any(known_matches):
        return "report", "fix_has_advisory", None
    if ecosystem == "PyPI" and pure_wheel is False:
        return "report", "no_pure_wheel", None

    old_repo = data["installed_provenance"]
    new_repo = record["provenance"]
    if not (_valid_provenance(ecosystem, old_repo) and _valid_provenance(ecosystem, new_repo)):
        return unavailable
    if "missing" in (old_repo, new_repo):
        if data.get("override") == version:
            return "install", "provenance_missing", "override"
        return "report", "provenance_missing", None
    if old_repo != new_repo:
        return "report", "repo_changed", None
    return "install", "triggered", "fast_lane"


def decide(case: dict) -> dict:
    """Return an age or fast-lane decision without fetching or installing anything."""
    try:
        data = case["input"]
        if data.get("lookup_failed", False) is not False:
            return _decision("no_verdict", reason="lookup_failed")
        if case["kind"] == "age":
            return _decide_age(data)
        if case["kind"] != "fast_lane":
            return _decision("no_verdict", reason="lookup_failed")
    except (AttributeError, KeyError, OverflowError, Refused, TypeError, ValueError):
        return _decision("no_verdict", reason="lookup_failed")

    selection = _selection(data)
    reason = selection.reason
    tier = None
    if reason == "triggered":
        try:
            action, reason, tier = _evaluate_fix(data, selection.version, selection.known_intervals)
        except ValueError:
            action, reason = "no_verdict", "unparsable_version"
        except (AttributeError, KeyError, TypeError):
            action, reason = "no_verdict", "lookup_failed"
    elif reason in {"lookup_failed", "unparsable_version", "kev_unavailable"}:
        action = "no_verdict"
    else:
        action = "report"
    return _decision(action, version=selection.version, tier=tier, reason=reason,
                     advisories=selection.advisories)


_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_INTOTO_STATEMENT = "https://in-toto.io/Statement/v1"
_SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
_PYPI_INTEGRITY_URL = "https://pypi.org/integrity/"


def _field(value: object, *path: str) -> object:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise LookupFailed(f"missing or invalid {'.'.join(path)}")
        value = value[key]
    return value


def _fetch_object(url: str, fetch) -> dict:
    try:
        body, next_url = fetch(url)
    except (OSError, TypeError, ValueError) as exc:
        raise LookupFailed(f"unable to read JSON from {url}") from exc
    if not isinstance(body, dict) or next_url is not None:
        raise LookupFailed(f"invalid or incomplete JSON object from {url}")
    return body


def _attestation_response(url: str, host: str, fetch) -> dict | None:
    try:
        return _fetch_object(url, fetch)
    except LookupFailed as exc:
        if exc.status == 404 and exc.host == host:
            return None
        raise


def kev_cves(fetch) -> frozenset[str] | None:
    """Return a complete KEV ID set, or None if the feed cannot be read."""
    try:
        body = _fetch_object(_KEV_URL, fetch)
        rows = _array(_field(body, "vulnerabilities"), "KEV vulnerabilities")
        count = body.get("count", len(rows))
        if type(count) is not int or count != len(rows):
            return None
        ids = frozenset(_text(_field(row, "cveID"), "KEV CVE ID") for row in rows)
        return ids if all(_CVE_ID.fullmatch(cve) for cve in ids) else None
    except LookupFailed:
        return None


def _statement(payload: object) -> dict:
    try:
        statement = json.loads(base64.b64decode(_text(payload, "attestation payload"),
                                               validate=True))
    except ValueError as exc:
        raise LookupFailed("invalid attestation statement") from exc
    if _field(statement, "_type") != _INTOTO_STATEMENT:
        raise LookupFailed("unsupported attestation statement type")
    _text(_field(statement, "predicateType"), "statement predicate type")
    return statement


def _check_subject(statement: dict, names: set[str], algorithm: str, digest: str) -> None:
    matched = False
    for subject in _array(_field(statement, "subject"), "attestation subjects"):
        name = _text(_field(subject, "name"), "attestation subject name")
        if name in names:
            actual = _text(_field(subject, "digest", algorithm), "attestation subject digest")
            if actual.lower() != digest:
                raise LookupFailed("attestation subject digest differs from registry")
            matched = True
    if not matched:
        raise LookupFailed("attestation does not identify the requested artifact")


def _common_repo(repos: set[str]) -> str:
    known = repos - {"missing"}
    if len(known) > 1:
        raise LookupFailed("attestations identify different repositories")
    if "missing" in repos or not known:
        return "missing"
    return known.pop()


def _npm_sha512(package: str, version: str, fetch) -> str:
    body = _fetch_object(f"{NPM_REGISTRY_URL}{package}/{version}", fetch)
    integrity = _text(_field(body, "dist", "integrity"), "npm registry integrity")
    algorithm, _, encoded = integrity.partition("-")
    try:
        digest = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise LookupFailed("invalid npm registry integrity") from exc
    if algorithm != "sha512" or len(digest) != 64:
        raise LookupFailed("invalid npm registry SHA-512 integrity")
    return digest.hex()


def npm_provenance(name: str, version: str, fetch) -> str:
    """Bind the SLSA subject to registry integrity and return its GitHub repo key."""
    package = quote(name, safe="").replace("%2F", "%2f")
    pin = quote(version, safe="")
    url = f"{NPM_REGISTRY_URL}-/npm/v1/attestations/{package}@{pin}"
    body = _attestation_response(url, "registry.npmjs.org", fetch)
    if body is None:
        return "missing"
    rows = _array(_field(body, "attestations"), "npm attestations")
    slsa = [row for row in rows if _text(_field(row, "predicateType"), "predicate type")
            == _SLSA_PROVENANCE]
    if not slsa:
        return "missing"

    digest = _npm_sha512(package, pin, fetch)
    names = {f"pkg:npm/{encoded}@{version}" for encoded in
             (quote(name, safe="/"), quote(name, safe=""), package)}
    repos = set()
    for row in slsa:
        statement = _statement(_field(row, "bundle", "dsseEnvelope", "payload"))
        if statement["predicateType"] != _SLSA_PROVENANCE:
            raise LookupFailed("conflicting npm attestation predicate type")
        _check_subject(statement, names, "sha512", digest)
        url = _text(_field(statement, "predicate", "buildDefinition", "externalParameters",
                           "workflow", "repository"), "npm attestation repository")
        try:
            parts = urlsplit(url)
            repo = _github_repo(url)
        except ValueError as exc:
            raise LookupFailed("invalid npm attestation GitHub repository") from exc
        key = f"github.com/{repo}"
        if (repo is None or parts.query or parts.fragment or any(c.isspace() for c in url)
                or not _GITHUB_REPO.fullmatch(key)):
            raise LookupFailed("invalid npm attestation GitHub repository")
        repos.add(key)
    return _common_repo(repos)


def _pypi_files(path: str, fetch) -> dict[str, str]:
    body = _fetch_object(f"{PYPI_JSON_URL}{path}/json", fetch)
    files = {}
    for row in _array(_field(body, "urls"), "PyPI files"):
        filename = _text(_field(row, "filename"), "PyPI filename")
        if filename in files:
            raise LookupFailed(f"duplicate PyPI filename: {filename}")
        files[filename] = _sha256(_field(row, "digests", "sha256"))
    return files


def _pypi_file_provenance(path: str, filename: str, digest: str, fetch) -> str:
    url = f"{_PYPI_INTEGRITY_URL}{path}/{quote(filename, safe='')}/provenance"
    body = _attestation_response(url, "pypi.org", fetch)
    if body is None:
        return "missing"
    version = _field(body, "version")
    if type(version) is not int or version != 1:
        raise LookupFailed("unsupported PyPI provenance version")

    repos = set()
    has_attestation = False
    for bundle in _array(_field(body, "attestation_bundles"), "PyPI attestation bundles"):
        kind = _text(_field(bundle, "publisher", "kind"), "PyPI publisher kind")
        repo = _text(_field(bundle, "publisher", "repository"), "PyPI publisher repository")
        key = f"{kind.lower()}:{repo.lower()}"
        if not _PUBLISHER_REPO.fullmatch(key):
            raise LookupFailed("invalid PyPI publisher identity")
        repos.add(key)
        for row in _array(_field(bundle, "attestations"), "PyPI attestations"):
            statement = _statement(_field(row, "envelope", "statement"))
            _check_subject(statement, {filename}, "sha256", digest)
            has_attestation = True
    repo = _common_repo(repos)
    return repo if has_attestation else "missing"


def _pypi_path(name: str, version: str) -> str:
    project = quote(normalize_pypi(name), safe="")
    return f"{project}/{quote(version, safe='')}"


def pypi_provenance(name: str, version: str, files: tuple[tuple[str, str], ...], fetch) -> str:
    """Bind every supplied file to the registry and its published provenance."""
    if not files:
        raise LookupFailed("no locked PyPI files to verify")
    path = _pypi_path(name, version)
    known = _pypi_files(path, fetch)
    locked = {}
    for filename, sha256 in files:
        digest = _sha256(sha256)
        if known.get(filename) != digest:
            raise LookupFailed(f"locked PyPI file differs from registry: {filename}")
        locked[filename] = digest
    repos = {_pypi_file_provenance(path, filename, digest, fetch)
             for filename, digest in locked.items()}
    return _common_repo(repos)


def _single_pure_wheel(files: dict[str, str]) -> tuple[str, str] | None:
    wheels = [(name, digest) for name, digest in files.items() if name.endswith("-none-any.whl")]
    return wheels[0] if len(wheels) == 1 else None


def pure_wheel(name: str, version: str, fetch) -> tuple[bool, str]:
    wheel = _single_pure_wheel(_pypi_files(_pypi_path(name, version), fetch))
    return (True, wheel[1]) if wheel is not None else (False, "")


def _provenance_or_failed(lookup, *args) -> str:
    try:
        return lookup(*args)
    except LookupFailed:
        return "failed"


def _pypi_fix(case_version: dict, name: str, fix: str, fetch) -> None:
    path = _pypi_path(name, fix)
    try:
        wheel = _single_pure_wheel(_pypi_files(path, fetch))
    except LookupFailed:
        case_version["pure_wheel"] = "failed"
        case_version["provenance"] = "failed"
        return
    case_version["pure_wheel"] = wheel is not None
    if wheel is not None:
        case_version["provenance"] = _provenance_or_failed(_pypi_file_provenance, path, *wheel,
                                                           fetch)


def gather(entry: Entry, advisories: list[Advisory], *, installed_files: tuple = (),
           kev: frozenset | None, policy: Policy, override: str | None, fetch) -> dict:
    """Collect the shared case for one entry and look up only the selected fix."""
    key = entry_key(entry)
    data = {"ecosystem": entry.ecosystem, "package": entry.name, "installed": entry.version,
            "advisories": [advisory.as_case() for advisory in advisories
                           if advisory.entry is not None and entry_key(advisory.entry) == key],
            "kev": sorted(kev) if kev is not None else None, "installed_provenance": None,
            "versions": {}, "override": override, "lookup_failed": False,
            "settings": {"fast_lane": policy.fast_lane}}
    case = {"kind": "fast_lane", "input": data}
    fix, _ = select_fix(case)
    if fix is None:
        return case

    fix_entry = Entry(entry.ecosystem, entry.name, fix)
    try:
        residual, failures = advisories_for([fix_entry], fetch)
        advisory_count = "failed" if failures else len(residual)
    except LookupFailed:
        advisory_count = "failed"
    record = {"advisories": advisory_count, "provenance": None}
    data["versions"][fix] = record
    if entry.ecosystem == "npm":
        data["installed_provenance"] = _provenance_or_failed(npm_provenance, entry.name,
                                                             entry.version, fetch)
        record["provenance"] = _provenance_or_failed(npm_provenance, entry.name, fix, fetch)
    elif entry.ecosystem == "PyPI":
        data["installed_provenance"] = _provenance_or_failed(pypi_provenance, entry.name,
                                                             entry.version, installed_files, fetch)
        _pypi_fix(record, entry.name, fix, fetch)
    return case


def continuity(ecosystem: str, name: str, old: str | None, new: str, fetch) -> str:
    """Compare npm provenance identities for the trusted waiting period."""
    if old is None or ecosystem != "npm":
        return "none"
    try:
        old_repo = npm_provenance(name, old, fetch)
        new_repo = npm_provenance(name, new, fetch)
    except LookupFailed:
        return "failed"
    if "missing" in (old_repo, new_repo):
        return "missing"
    return "same" if old_repo == new_repo else "different"


@dataclass
class TreeVerdict:
    """Outcome of judging one resolved tree.

    code 0 with fixes means: rebuild the tree with these scanned fixes; code 0
    without fixes means the tree is clean. fixes maps a package name to
    (version, receipt, decision)."""
    code: int
    lines: list = field(default_factory=list)
    advisories: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    needs_scan: list = field(default_factory=list)
    young: list = field(default_factory=list)
    fixes: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def _record(entry: Entry, decision: dict, repo: str | None) -> dict:
    return {"package": entry.name, "installed": entry.version, "action": decision["action"],
            "version": decision["version"], "tier": decision["tier"],
            "reason": decision["reason"], "advisories": list(decision["advisories"] or []),
            "repo": repo}


def _decide_entry(entry: Entry, advisories: list, kev, policy: Policy, override, fetch) -> dict:
    """One decision per entry; any unexpected failure of a lookup is no verdict."""
    repo = None
    try:
        case = gather(entry, advisories,
                      installed_files=entry.files if entry.ecosystem == "PyPI" else (),
                      kev=kev, policy=policy, override=override, fetch=fetch)
        decision = decide(case)
        if decision["version"] is not None:
            repo = case["input"]["versions"].get(decision["version"], {}).get("provenance")
    except Exception:  # a different answer shape is no verdict, never a pass
        decision = _decision("no_verdict", reason="lookup_failed")
    record = _record(entry, decision, repo if isinstance(repo, str) else None)
    # A user override that names another version than the fix is never mixed in silently.
    if record["action"] == "install" and override not in (None, record["version"]):
        if override == entry.version:
            record.update(action="no_verdict", reason="override_conflict")
        else:
            record.update(action="report", reason="override_differs")
    return record


def _decision_line(record: dict) -> str:
    label = f"{record['package']}@{record['installed']}"
    ids = ", ".join(record["advisories"]) or "no id"
    reason = record["reason"]
    if record["action"] == "no_verdict":
        return f"NO VERDICT -- {label}: advisory {ids}; the fast lane could not decide ({reason})"
    line = f"[BLOCK] {label}: advisory {ids}; the fast lane gives no install ({reason})"
    if reason == "provenance_missing" and record["version"]:
        line += (f"; to accept {record['version']} anyway scan it, then run with "
                 f"--override {record['package']}={record['version']} --override-reason TEXT")
    if reason == "override_differs" and record["version"]:
        line += f"; the fix to use is {record['version']}"
    return line


def _user_override(entry: Entry, user_overrides: dict) -> str | None:
    """The version the user pinned for this entry; PyPI names compare after PEP 503 normalisation."""
    if entry.ecosystem != "PyPI":
        return user_overrides.get(entry.name)
    wanted = normalize_pypi(entry.name)
    found = {version for name, version in user_overrides.items() if normalize_pypi(name) == wanted}
    if len(found) > 1:
        raise Refused(2, f"NO VERDICT -- several --override versions name {wanted}")
    return found.pop() if found else None


def judge_tree(entries: list[Entry], previous: dict, *, receipts_root: Path, kind: str,
               user_overrides: dict, policy: Policy, fetch, now=None, age_limits=None,
               check=_lockcheck.check, unavailable: str | None = None) -> TreeVerdict:
    """The one rule for a resolved tree: lockfile check, then a decision per affected entry.

    Exit mapping: any report gives 1; otherwise any no verdict, lookup failure or
    missing receipt gives 2. A fix is used only after a complete run with a SAFE
    receipt. `unavailable` turns every install decision into a report (the
    caller cannot rebuild a tree with a fix). `previous` is accepted for the
    callers that judge a list against an installed state; the build path of
    npm_install does not use it."""
    try:
        result = check(entries, now=now, fetch=fetch, min_age_days=policy.min_age_days,
                       age_limits=age_limits)
    except Exception as exc:
        return TreeVerdict(2, [f"NO VERDICT -- lockfile check failed: {type(exc).__name__}: {exc}"])
    verdict = TreeVerdict(result.code, list(result.lines), list(result.advisories),
                          young=list(result.young))
    # A finding that is no advisory (hash or integrity differs) has no fast lane.
    if result.code != 1 or not result.advisories or result.blocking:
        return verdict

    try:
        kev = kev_cves(fetch)
    except Exception:
        kev = None
    groups: dict = {}
    unmatched = []
    for advisory in result.advisories:
        if advisory.entry is None:
            unmatched.append(advisory.id)
        else:
            groups.setdefault(entry_key(advisory.entry), (advisory.entry, []))[1].append(advisory)
    for entry, advisories in groups.values():
        verdict.decisions.append(_decide_entry(entry, advisories, kev, policy,
                                               _user_override(entry, user_overrides), fetch))
    incomplete = bool(result.failures)
    for record in verdict.decisions:
        if record["action"] == "install" and unavailable:
            record.update(action="report", reason="fast_lane_unavailable")
        elif record["action"] == "install" and incomplete:
            record.update(action="no_verdict", reason="incomplete_lookup")

    _check_same_name(entries, verdict)
    for record in verdict.decisions:
        if record["action"] != "install":
            line = _decision_line(record)
            if record["reason"] == "fast_lane_unavailable":
                line += f"; {unavailable}"
            verdict.notes.append(line)
    for advisory_id in unmatched:
        verdict.notes.append(f"[BLOCK] advisory {advisory_id} names no entry of this tree")
    verdict.lines.extend(verdict.notes)

    actions = [record["action"] for record in verdict.decisions]
    if unmatched or "report" in actions:
        verdict.code = 1
    elif any(action != "install" for action in actions) or incomplete or result.young:
        verdict.code = 2  # a young entry next to the fixes waits; it is not a fix
    else:
        verdict.code = 0
        _collect_fixes(verdict, receipts_root, kind)
    return verdict


def _same_name(entry: Entry, name: str) -> bool:
    return entry_key(entry)[:2] == entry_key(Entry(entry.ecosystem, name, ""))[:2]


def _check_same_name(entries: list[Entry], verdict: TreeVerdict) -> None:
    """One override per name changes every instance: all must need the same fix."""
    installs = [record for record in verdict.decisions if record["action"] == "install"]
    for name in sorted({record["package"] for record in installs}):
        named = [record for record in installs if record["package"] == name]
        versions = {record["version"] for record in named}
        present = {entry.version for entry in entries if _same_name(entry, name)}
        if len(versions) > 1 or present != {record["installed"] for record in named}:
            for record in named:
                record.update(action="no_verdict", reason="several_versions")
            verdict.notes.append(f"NO VERDICT -- several versions of {name} need different fixes")


def _collect_fixes(verdict: TreeVerdict, receipts_root: Path, kind: str) -> None:
    blocked = failed = False
    seen = set()
    for record in verdict.decisions:
        name, version = record["package"], record["version"]
        if (name, version) in seen:
            if name in verdict.fixes:
                known = verdict.fixes[name][2]["advisories"]
                known.extend(i for i in record["advisories"] if i not in known)
            continue
        seen.add((name, version))
        try:
            receipt, _ = require_receipt(receipts_root, kind, name, version, None)
        except NeedsScan as exc:
            verdict.needs_scan.extend(item for item in exc.items
                                      if item not in verdict.needs_scan)
            continue
        except Refused as exc:
            verdict.lines.append(f"{'[BLOCK]' if exc.code == 1 else 'NO VERDICT --'} {exc}")
            blocked, failed = blocked or exc.code == 1, True
            continue
        verdict.fixes[name] = (version, receipt, record)
    if blocked:
        verdict.code, verdict.fixes = 1, {}
    elif failed or verdict.needs_scan:
        verdict.code, verdict.fixes = 2, {}
