"""Public version precedence and interval membership for npm and PyPI."""
from __future__ import annotations

import re

_SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
_SEMVER_PARTS = r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*"
_SEMVER = re.compile(
    rf"(?P<release>{_SEMVER_NUMBER}\.{_SEMVER_NUMBER}\.{_SEMVER_NUMBER})"
    rf"(?:-(?P<pre>{_SEMVER_PARTS}))?(?:\+{_SEMVER_PARTS})?"
)
_PEP440 = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_number>[0-9]+)?)?"
    r"(?:(?:-(?P<post_implicit>[0-9]+))|"
    r"(?:[-_.]?(?P<post>post|rev|r)[-_.]?(?P<post_number>[0-9]+)?))?"
    r"(?:[-_.]?(?P<dev>dev)[-_.]?(?P<dev_number>[0-9]+)?)?",
    re.IGNORECASE | re.ASCII,
)
_PEP440_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
               "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _semver_parts(match: re.Match) -> tuple[tuple, bool, int]:
    release = tuple(map(int, match["release"].split(".")))
    pre = match["pre"]
    identifiers = []
    for part in pre.split(".") if pre else ():
        if part.isdigit():
            if len(part) > 1 and part.startswith("0"):
                raise ValueError("numeric SemVer prerelease identifier has a leading zero")
            identifiers.append((0, int(part)))
        else:
            identifiers.append((1, part))
    return (release, pre is None, tuple(identifiers)), pre is not None, release[0]


def _pep440_parts(match: re.Match) -> tuple[tuple, bool, int]:
    release = list(map(int, match["release"].split(".")))
    while len(release) > 1 and release[-1] == 0:
        release.pop()

    pre = match["pre"]
    post = match["post"] is not None or match["post_implicit"] is not None
    dev = match["dev"] is not None
    # A dev-only release sorts before alphas. Dev attached to a post release
    # instead stays in the final-release group, before that post release.
    if pre:
        phase = (0, _PEP440_PRE[pre.lower()], int(match["pre_number"] or 0))
    elif dev and not post:
        phase = (-1,)
    else:
        phase = (1,)
    post_order = int(match["post_implicit"] or match["post_number"] or 0) if post else -1
    dev_order = (0, int(match["dev_number"] or 0)) if dev else (1,)
    order = (int(match["epoch"] or 0), tuple(release), phase, post_order, dev_order)
    return order, bool(pre) or dev, release[0]


def _parse(ecosystem: str, version: str) -> tuple[tuple, bool, int]:
    if isinstance(version, str):
        if ecosystem == "npm" and (match := _SEMVER.fullmatch(version)):
            return _semver_parts(match)
        if ecosystem == "PyPI" and (match := _PEP440.fullmatch(version.strip())):
            return _pep440_parts(match)
    raise ValueError(f"unreadable {ecosystem} version: {version!r}")


def key(ecosystem: str, version: str) -> tuple:
    return _parse(ecosystem, version)[0]


def is_prerelease(ecosystem: str, version: str) -> bool:
    return _parse(ecosystem, version)[1]


def major(ecosystem: str, version: str) -> int:
    return _parse(ecosystem, version)[2]


def in_interval(ecosystem: str, version: str, interval: dict) -> bool:
    current = key(ecosystem, version)
    lower = None if interval["lower"] is None else key(ecosystem, interval["lower"])
    upper = None if interval["upper"] is None else key(ecosystem, interval["upper"])
    lower_inclusive = interval["lower_inclusive"]
    upper_inclusive = interval["upper_inclusive"]
    if type(lower_inclusive) is not bool or type(upper_inclusive) is not bool:
        raise ValueError("interval boundaries must specify boolean inclusivity")
    if lower is not None and upper is not None and lower > upper:
        raise ValueError("interval lower bound exceeds upper bound")
    return (lower is None or current > lower or (lower_inclusive and current == lower)) and (
        upper is None or current < upper or (upper_inclusive and current == upper)
    )
