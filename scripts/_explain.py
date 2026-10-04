"""Tell the user what a triage result means, in everyday language.

The default output names the outcome, the one reason that matters and what to
do next. Rule IDs, severities and per-finding reasons appear only with
details=True; as_dict() carries everything for scripts. A cleared finding is
"checked automatically and harmless", never "false alarm ignored".

Languages: English (default) and German, chosen by AGENT_GUARD_LANG=de|en.
"""
from __future__ import annotations

import os

import _triage

TEXT = {
    "en": {
        "safe": "SAFE: {name} can be installed.",
        "safe_checked": " {n} automatic scanner note(s) were checked and are harmless.",
        "safe_none": " The scan found nothing of concern.",
        "dangerous": "NOT INSTALLED: {name} -- {why}.",
        "dangerous_advice": "Recommendation: do not use this skill.",
        "unclear": "YOUR DECISION: {name} -- {n} point(s) could not be settled automatically.",
        "unclear_advice": "Recommendation: install it only if you trust its publisher.",
        "no_verdict": "NOT INSTALLED: {name} could not be checked completely.",
        "no_verdict_advice": "Nothing was decided; run the check again later.",
        "details": "Details:",
        "status": {"hard": "proof", "confirmed": "confirmed", "open": "open",
                   "cleared": "checked, harmless"},
        "why": {
            "malware": "it matches a known malware signature",
            "hidden_code": "it hides encoded instructions and runs them",
            "exfil": "it sends data such as credentials or files to another server",
            "steer_ai": "it contains hidden instructions that try to steer the AI assistant",
            "foreign_installer": "it downloads and runs a program from a third-party address",
            "credentials": "it reads credential files such as SSH or cloud keys",
            "admin": "it asks for administrator rights",
            "other": "a security check found a serious problem",
        },
    },
    "de": {
        "safe": "SICHER: {name} kann installiert werden.",
        "safe_checked": " {n} automatische Hinweis(e) der Scanner wurden nachgeprüft und sind harmlos.",
        "safe_none": " Die Prüfung hat nichts Bedenkliches gefunden.",
        "dangerous": "NICHT INSTALLIERT: {name} -- {why}.",
        "dangerous_advice": "Empfehlung: diese Skill nicht verwenden.",
        "unclear": "DEINE ENTSCHEIDUNG: {name} -- {n} Punkt(e) ließen sich nicht automatisch klären.",
        "unclear_advice": "Empfehlung: nur installieren, wenn du dem Herausgeber vertraust.",
        "no_verdict": "NICHT INSTALLIERT: {name} konnte nicht vollständig geprüft werden.",
        "no_verdict_advice": "Es wurde nichts entschieden; die Prüfung später wiederholen.",
        "details": "Details:",
        "status": {"hard": "Beleg", "confirmed": "bestätigt", "open": "offen",
                   "cleared": "nachgeprüft, harmlos"},
        "why": {
            "malware": "sie passt zu einer bekannten Schadsoftware-Signatur",
            "hidden_code": "sie versteckt verschlüsselte Anweisungen und führt sie aus",
            "exfil": "sie schickt Daten wie Zugangsdaten oder Dateien an einen anderen Server",
            "steer_ai": "sie enthält versteckte Anweisungen, die den KI-Assistenten steuern sollen",
            "foreign_installer": "sie lädt ein Programm von einer fremden Adresse und führt es aus",
            "credentials": "sie liest Zugangsdateien wie SSH- oder Cloud-Schlüssel",
            "admin": "sie verlangt Administratorrechte",
            "other": "eine Sicherheitsprüfung hat ein ernstes Problem gefunden",
        },
    },
}

# Most telling reason first.
WHY_ORDER = ("malware", "hidden_code", "exfil", "steer_ai", "credentials",
             "foreign_installer", "admin", "other")


def language(env=None) -> str:
    lang = (env if env is not None else os.environ).get("AGENT_GUARD_LANG", "").strip().lower()
    return lang[:2] if lang[:2] in TEXT else "en"


def why_key(rule: str) -> str:
    if rule.startswith("YR"):
        return "malware"
    if rule in ("AST8", "SC3", "AST1", "AST2", "AST6"):
        return "hidden_code"
    if rule in ("TT3", "TT4", "BH2", "E1", "E2", "E3", "E4", "E5"):
        return "exfil"
    if (rule[:1] == "P" and rule[1:].isdigit()) or rule in ("AR1", "AR2", "AR3"):
        return "steer_ai"
    if rule == "PE3":
        return "credentials"
    if rule in ("SC2", "TM2"):
        return "foreign_installer"
    if rule == "PE2":
        return "admin"
    return "other"


def blocking(result: _triage.Result) -> list:
    return [d for d in result.dispositions if d.status in (_triage.HARD, _triage.CONFIRMED)
            or (d.status == _triage.OPEN and not d.finding.unconfirmed)]


def explain(result: _triage.Result, name: str, *, lang: str | None = None,
            details: bool = False) -> str:
    t = TEXT[lang or language()]
    cleared = result.by_status(_triage.CLEARED)
    if result.verdict == _triage.SAFE:
        lines = [t["safe"].format(name=name)
                 + (t["safe_checked"].format(n=len(cleared)) if cleared else t["safe_none"])]
    elif result.verdict == _triage.DANGEROUS:
        keys = {why_key(d.finding.rule) for d in blocking(result)} or {"other"}
        top = next(k for k in WHY_ORDER if k in keys)
        lines = [t["dangerous"].format(name=name, why=t["why"][top]), t["dangerous_advice"]]
    elif result.verdict == _triage.UNCLEAR:
        lines = [t["unclear"].format(name=name, n=len(result.by_status(_triage.OPEN))),
                 t["unclear_advice"]]
    else:
        lines = [t["no_verdict"].format(name=name), t["no_verdict_advice"]]
    if details and result.dispositions:
        lines.append(t["details"])
        for d in result.dispositions:
            f = d.finding
            where = f"{f.evidence_file or f.file}:{f.line if not f.evidence_lines else f.evidence_lines[0]}"
            lines.append(f"  {f.severity} {f.rule} @ {where} -- {t['status'][d.status]}: {d.reason}")
    return "\n".join(lines)


def as_dict(result: _triage.Result, name: str) -> dict:
    return {"name": name, "verdict": result.verdict,
            "findings": [{"rule": d.finding.rule, "severity": d.finding.severity,
                          "file": d.finding.evidence_file or d.finding.file,
                          "line": d.finding.line, "unconfirmed": d.finding.unconfirmed, "status": d.status,
                          "check": d.check, "reason": d.reason} for d in result.dispositions]}
