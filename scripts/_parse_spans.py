"""Where SkillSpector's shell parser gave up: the lines behind an AE1 finding.

SkillSpector reports AE1 ("referenced artifact was not completely inspected")
for a file in which one analyzer's bounded shell parser gave up on a span
(reason `static_parse_limit`). The file itself was read and the other analyzers
saw it; the report does not say which lines the parser could not settle.
_parse_spans_boot.py finds them with the same parser, so the triage can look at
exactly those lines instead of treating the whole file as unseen.

Any failure -- no SkillSpector environment, an import error after an upgrade,
a time limit, more spans than allowed -- returns None for that file, and the
finding simply stays open.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

BOOT = Path(__file__).resolve().parent / "_parse_spans_boot.py"
# The analyzers whose bounded shell parser the boot script replays.
PARSE_SPAN_ANALYZERS = frozenset({"static_patterns_tool_misuse"})
MAX_SPANS = 8
SECONDS_PER_FILE = 60


def parse_answer(item) -> list | None:
    """Spans as [(start, end), ...], or None if the answer is not a full list."""
    if not isinstance(item, dict) or "error" in item:
        return None
    spans = item.get("spans")
    if not isinstance(spans, list) or len(spans) > MAX_SPANS:
        return None
    out = []
    for span in spans:
        if (not isinstance(span, list) or len(span) != 2
                or not all(type(n) is int for n in span) or not 1 <= span[0] <= span[1]):
            return None
        out.append((span[0], span[1]))
    return out


def run_boot(python: str, paths: list) -> list:
    request = json.dumps({"files": [str(p) for p in paths], "max_spans": MAX_SPANS,
                          "seconds": SECONDS_PER_FILE})
    try:
        done = subprocess.run([python, str(BOOT)], input=request.encode("utf-8"),
                              capture_output=True,
                              timeout=SECONDS_PER_FILE * len(paths) + 60)
    except (OSError, subprocess.TimeoutExpired):
        return [None] * len(paths)
    if done.returncode != 0:
        return [None] * len(paths)
    try:
        out = json.loads(done.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [None] * len(paths)
    if not isinstance(out, list) or len(out) != len(paths):
        return [None] * len(paths)
    return [parse_answer(item) for item in out]


class Locator:
    """Callable for _triage.triage(spans=...): (skill_dir, [rel, ...]) -> {rel: spans|None}.
    `runner(paths) -> [spans|None, ...]`."""

    def __init__(self, runner):
        self.runner = runner

    def __call__(self, skill_dir: Path, rels: list) -> dict:
        rels = sorted(set(rels))
        if not rels:
            return {}
        answers = self.runner([Path(skill_dir) / rel for rel in rels])
        return dict(zip(rels, answers))


def from_skillspector():
    """The locator for this machine's SkillSpector tool environment, or None."""
    import _skillspector
    python = _skillspector.skillspector_python()
    if python is None:
        return None
    return Locator(lambda paths: run_boot(python, paths))
