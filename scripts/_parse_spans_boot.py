#!/usr/bin/env python3
"""Locate the lines that make SkillSpector's shell parser give up on a file.

Runs inside SkillSpector's tool environment. Reads one JSON request from stdin:
{"files": ["<absolute path>", ...], "max_spans": 8, "seconds": 60}
and writes one JSON list to stdout, one entry per file:
{"spans": [[start, end], ...]}  every span found; the file parses once they are blanked
{"spans": []}                   the parser does not give up on this file at all
{"error": "..."}                 the spans could not all be located

A span is a smallest window of whole lines that still exhausts the parser on
its own. After a span is found its lines are blanked (line numbers stay) and
the whole file is tested again, so the answer covers every trigger, not just
the first one. Nothing is executed; the parser only reads text.
"""
import json
import sys
import time


class _OutOfTime(Exception):
    pass


def _spans(path, max_spans, seconds):
    from skillspector.nodes.analyzers import static_patterns_tool_misuse as tm
    from skillspector.nodes.analyzers.static_runner import _infer_file_type

    file_type = _infer_file_type(path)
    deadline = time.monotonic() + seconds

    def check():
        if time.monotonic() > deadline:
            raise _OutOfTime()

    def limited(lines):
        check()
        return bool(tm.has_bounded_parse_exhaustion(
            "".join(lines), check, file_type=file_type, complete_context=True))

    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        lines = fh.read().splitlines(keepends=True)
    found = []
    while limited(lines):
        if len(found) == max_spans:
            return {"error": f"more than {max_spans} spans"}
        lo, hi = 0, len(lines)
        step = max(1, (hi - lo) // 2)
        while step >= 1:
            if hi - step > lo and limited(lines[lo:hi - step]):
                hi -= step
            elif lo + step < hi and limited(lines[lo + step:hi]):
                lo += step
            else:
                step //= 2
        if not limited(lines[lo:hi]):
            return {"error": "the trigger needs context outside any window"}
        found.append([lo + 1, hi])
        blank = ["\n" if line.endswith(("\n", "\r")) else "" for line in lines[lo:hi]]
        if blank == [line for line in lines[lo:hi]]:
            return {"error": "a blank span still triggers the parser"}
        lines[lo:hi] = blank
    return {"spans": found}


def main() -> None:
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    out = []
    for path in request["files"]:
        try:
            out.append(_spans(path, int(request.get("max_spans", 8)),
                              float(request.get("seconds", 60))))
        except _OutOfTime:
            out.append({"error": "time limit reached"})
        except Exception as exc:  # every failure is reported, never raised past here
            out.append({"error": f"{type(exc).__name__}: {exc}"[:300]})
    sys.stdout.buffer.write(json.dumps(out).encode("utf-8"))


if __name__ == "__main__":
    main()
