"""Pure package age and security-fix decisions for the shared contract."""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

import _versions
from _mcp_locked import Refused


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
