#!/usr/bin/env python3
"""Recheck a match of SkillSpector's built-in YARA rules with a corrected rule.

Runs inside SkillSpector's tool environment. Reads one JSON request from stdin:
{"corrected": "<path to yara_corrections.yar.b64>",
 "rules": {"<name>": {"namespace": "malware", "original_sha256": "<hex>"}},
 "checks": [{"rule": "<name>", "file": "<absolute path>"}, ...]}
and writes one JSON list to stdout, one entry per check:
{"original": true, "corrected": false}   what each rule says about the whole file
{"error": "..."}                          the recheck could not be done

The built-in rule text is hashed with LF line ends; a different hash means the
pinned scanner changed the rule, and every check of that rule is an error.
Nothing is executed; YARA only reads bytes.
"""
import base64
import hashlib
import json
import re
import sys


def _rule_text(source, name):
    match = re.search(r"(?ms)^rule\s+" + re.escape(name) + r"\b.*?^\}", source)
    return match.group(0) if match else None


def _builtin_source(namespace):
    from skillspector.nodes.analyzers import static_yara as sy
    for suffix in (".yar.b64", ".yar", ".yara.b64", ".yara"):
        path = sy._BUILTIN_RULES_DIR / (namespace + suffix)
        if path.is_file():
            return sy._read_rule_source(path).replace("\r\n", "\n")
    raise LookupError("no built-in rule file " + namespace)


def _compile(request):
    import yara
    with open(request["corrected"], "rb") as fh:
        corrected = base64.b64decode(b"".join(fh.read().split())).decode("utf-8")
    compiled = {}
    for name, meta in request["rules"].items():
        try:
            original = _rule_text(_builtin_source(meta["namespace"]), name)
            if original is None:
                raise LookupError("built-in rule not found")
            digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
            if digest != meta["original_sha256"]:
                raise LookupError("built-in rule changed")
            fixed = _rule_text(corrected.replace("\r\n", "\n"), name)
            if fixed is None:
                raise LookupError("no corrected rule")
            compiled[name] = (yara.compile(source=original), yara.compile(source=fixed))
        except Exception as exc:  # reported per check below, never raised past here
            compiled[name] = f"{type(exc).__name__}: {exc}"[:300]
    return compiled


def main() -> None:
    from skillspector.constants import MAX_ANALYZABLE_FILE_BYTES
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    compiled = _compile(request)
    out = []
    for check in request["checks"]:
        rules = compiled.get(check.get("rule"))
        if not isinstance(rules, tuple):
            out.append({"error": rules or "rule not requested"})
            continue
        try:
            with open(check["file"], "rb") as fh:
                data = fh.read(MAX_ANALYZABLE_FILE_BYTES + 1)
            if len(data) > MAX_ANALYZABLE_FILE_BYTES:
                out.append({"error": "file too large"})
                continue
            original, fixed = rules
            out.append({"original": bool(original.match(data=data)),
                        "corrected": bool(fixed.match(data=data))})
        except Exception as exc:  # every failure is reported, never raised past here
            out.append({"error": f"{type(exc).__name__}: {exc}"[:300]})
    sys.stdout.buffer.write(json.dumps(out).encode("utf-8"))


if __name__ == "__main__":
    main()
