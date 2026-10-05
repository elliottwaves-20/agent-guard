"""Full chain on the benign holdout: LLM scan, triage, span locator, verifier.

  python tests/run_benign_eval.py            # resumable; results outside the repo
  python tests/run_benign_eval.py --only NAME --tag=-recheck   # re-scan for cause analysis
Writes %LOCALAPPDATA%/agent-guard-eval/benign-holdout<tag>.jsonl, every full scan
report and the wrapper's console output under reports/, and prints the summary.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

OUT = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "agent-guard-eval"


def summarize(rows: list) -> dict:
    count = {v: sum(1 for r in rows if r["verdict"] == v)
             for v in ("safe", "dangerous", "unclear", "no_verdict")}
    total = len(rows)
    blocked = total - count["safe"]
    return {"total": total, "go": count["safe"], "blocked": blocked,
            "dangerous": count["dangerous"], "unclear": count["unclear"],
            "no_verdict": count["no_verdict"],
            "false_alarm_rate": blocked / total if total else 0.0}


def keep_report(src: Path, name: str, out: Path = OUT) -> Path | None:
    """Copy the full scan report next to the results: the cause analysis reads it."""
    try:
        data = Path(src).read_bytes()
    except OSError:
        return None
    target = Path(out) / "reports" / f"{name}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", default=[], help="scan only this skill (repeatable)")
    ap.add_argument("--tag", default="", help="suffix of the results file, e.g. -recheck")
    args = ap.parse_args()
    import _corpus
    import _eval
    import _parse_spans
    import _skillspector as ss
    import _triage
    import _verifier
    ss.need_skillspector()
    if not ss.LLM_READY:
        sys.exit(f"LLM not ready: {ss.LLM_REASON}")
    verifier, spans = _verifier.from_profile(), _parse_spans.from_skillspector()
    if verifier is None:
        sys.exit("no agent-CLI verifier profile")
    samples = [s for s in _eval.load() if not args.only or s.id in args.only]
    OUT.mkdir(parents=True, exist_ok=True)
    results = OUT / f"benign-holdout{args.tag}.jsonl"
    done = {json.loads(l)["name"] for l in results.read_text(encoding="utf-8").splitlines()
            if l} if results.exists() else set()
    with tempfile.TemporaryDirectory() as tmp:
        fetched = _corpus.fetch_benign([s for s in samples if s.id not in done], Path(tmp))
        for s in samples:
            if s.id in done or s.id not in fetched:
                continue
            t0, path = time.time(), fetched[s.id]
            out = Path(tmp) / f"{s.id}.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                raw = ss.run_skillspector(path, report_output=out)
            row = {"name": s.id, "source": s.source, "raw": raw,
                   "report": str(keep_report(out, s.id + args.tag) or "")}
            (OUT / "reports").mkdir(parents=True, exist_ok=True)
            (OUT / "reports" / f"{s.id}{args.tag}.log").write_text(buf.getvalue(), encoding="utf-8")
            try:
                data = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = None
            if data is None or raw not in (0, 1):
                row.update(verdict="no_verdict",
                           note=[l.strip()[:300] for l in buf.getvalue().splitlines()
                                 if "NO VERDICT" in l or "LIMIT" in l][:6])
            else:
                result = _triage.triage(data, path, raw, origin=_triage.Origin(s.source, s.ref),
                                        verifier=verifier, spans=spans)
                row.update(verdict=result.verdict,
                           open=[{"rule": d.finding.rule, "status": d.status,
                                  "file": d.finding.evidence_file or d.finding.file,
                                  "reason": d.reason} for d in result.dispositions
                                 if d.status != _triage.CLEARED],
                           cleared=sorted({str(d.check) for d in result.dispositions
                                           if d.status == _triage.CLEARED}))
            row["seconds"] = round(time.time() - t0)
            with results.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            print(f"{row['verdict']:<10} {s.source}/{s.id} ({row['seconds']}s)", flush=True)
    rows = [json.loads(l) for l in results.read_text(encoding="utf-8").splitlines() if l]
    print(json.dumps(summarize(rows), indent=1))


if __name__ == "__main__":
    main()
