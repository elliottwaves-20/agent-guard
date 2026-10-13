"""Recheck YARA findings of the pinned SkillSpector with corrected rules.

Some built-in YARA rules match ordinary prose (one regex spanning a whole line).
Upstream fixes such rules by making them precise, never by ignoring YARA in
documentation. Until a fix is released, _yara_recheck_boot.py matches the
flagged file with the built-in rule and with the corrected one from
triage/yara_corrections.yar.b64. A finding counts as a scanner error only when
the built-in rule matches and the corrected rule does not; every other answer,
and every failure, leaves the finding hard evidence.
"""
from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOOT = HERE / "_yara_recheck_boot.py"
CORRECTIONS = HERE / "triage" / "yara_corrections.toml"
SECONDS = 120


def load_corrections(path: Path = CORRECTIONS) -> dict:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    rules = data.get("rule")
    if (data.get("version") != 1 or not isinstance(data.get("skillspector"), str)
            or not isinstance(data.get("corrected"), str) or not isinstance(rules, list)
            or not rules):
        raise ValueError("yara_corrections.toml needs version, skillspector, corrected, rule")
    for rule in rules:
        if not all(isinstance(rule.get(k), str) and rule.get(k)
                   for k in ("name", "namespace", "original_sha256")):
            raise ValueError(f"incomplete correction {rule.get('name')!r}")
    return data


def parse_answer(item) -> bool | None:
    """True: only the built-in rule matches. False: the corrected rule matches too."""
    if not isinstance(item, dict) or "error" in item:
        return None
    original, corrected = item.get("original"), item.get("corrected")
    if type(original) is not bool or type(corrected) is not bool or not original:
        return None
    return not corrected


def run_boot(python: str, checks: list, rules: dict) -> list:
    request = json.dumps({
        "corrected": str(CORRECTIONS.parent / load_corrections()["corrected"]),
        "rules": {name: {"namespace": r["namespace"], "original_sha256": r["original_sha256"]}
                  for name, r in rules.items()},
        "checks": [{"rule": rule, "file": str(path)} for rule, path in checks]})
    try:
        done = subprocess.run([python, str(BOOT)], input=request.encode("utf-8"),
                              capture_output=True, timeout=SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return [None] * len(checks)
    if done.returncode != 0:
        return [None] * len(checks)
    try:
        out = json.loads(done.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [None] * len(checks)
    if not isinstance(out, list) or len(out) != len(checks):
        return [None] * len(checks)
    return [parse_answer(item) for item in out]


class Rechecker:
    """Callable for _triage.triage(yara=...):
    (skill_dir, [(rule, namespace, rel), ...]) -> {(rule, namespace, rel): True | False | None}.
    `runner(checks, rules) -> [True | False | None, ...]`."""

    def __init__(self, runner, corrections: dict):
        self.runner = runner
        self.skillspector = corrections["skillspector"]
        self.rules = {r["name"]: r for r in corrections["rule"]}

    def __call__(self, skill_dir: Path, checks: list) -> dict:
        base = Path(skill_dir).resolve()
        wanted, out = [], {}
        for key in sorted(set(checks)):
            rule, namespace, rel = key
            correction = self.rules.get(rule)
            if correction is None:
                continue
            path = (base / rel).resolve()
            if (correction["namespace"] == namespace and path.is_relative_to(base)
                    and path.is_file()):
                wanted.append((key, path))
            else:
                out[key] = None
        if wanted:
            try:
                answers = self.runner([(key[0], path) for key, path in wanted],
                                      {n: self.rules[n] for n in {k[0] for k, _ in wanted}})
            except Exception:  # a failed recheck leaves the findings hard
                answers = [None] * len(wanted)
            if not isinstance(answers, list) or len(answers) != len(wanted):
                answers = [None] * len(wanted)
            out.update({key: answer for (key, _), answer in zip(wanted, answers)})
        return out


def from_skillspector():
    """The rechecker for this machine's SkillSpector tool environment, or None."""
    import _skillspector
    python = _skillspector.skillspector_python()
    if python is None:
        return None
    return Rechecker(lambda checks, rules: run_boot(python, checks, rules), load_corrections())
