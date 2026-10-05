"""Verify raw SkillSpector findings before they reach the user.

The raw scan stays fully sensitive; this module decides, finding by finding,
which HIGH/CRITICAL results are backed by evidence and which match a known
false-positive pattern *at their own location*. It never weakens a fail-closed
result: a raw NO VERDICT stays NO VERDICT, and hard evidence is final.

Stages, cheapest first:
  a) hard evidence (HARD_RULES)                -> dangerous, never cleared
  b) file already approved by content hash     -> cleared
  c) known-noise catalog check for this finding -> cleared, or stays open
  d) verifier LLM (_verifier.py), if given    -> benign clears, malicious confirms

Verdict: dangerous if any hard evidence, any finding the verifier confirmed, or
any open finding the scanner stands behind; unclear if the only open findings
are ones SkillSpector's own LLM meta-review did not confirm (tag
`llm-unconfirmed`) or coverage gaps (COVERAGE_RULES); safe otherwise. A
static-only scan has no meta-review, so every other open finding there counts
as dangerous.

A coverage gap says that part of a file was not settled, not that anything in
it is harmful. It never makes a skill dangerous on its own, and never safe
either: unclear goes to quarantine like dangerous does.
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

CATALOG = Path(__file__).resolve().parent / "triage" / "known_noise.toml"

SAFE, DANGEROUS, UNCLEAR, NO_VERDICT = "safe", "dangerous", "unclear", "no_verdict"
HARD, CLEARED, OPEN, CONFIRMED = "hard", "cleared", "open", "confirmed"

# Evidence no catalog entry, approval or verifier may clear: malware signatures,
# decoded-payload execution, obfuscated code, credentials flowing to the network,
# hooks that send local content to a remote host.
HARD_RULES = frozenset({"YR1", "YR2", "YR3", "YR4", "AST8", "SC3", "TT3", "BH2"})
# Findings that show data leaving the machine; any of them (or hard evidence) in
# a file blocks every catalog check for the other findings in that file.
EXFIL_RULES = frozenset({"E1", "E2", "E3", "E4", "E5", "P3", "TT1", "TT2", "TT3", "TT4", "BH2"})
BLOCKING = frozenset({"HIGH", "CRITICAL"})
# AE1, a referenced artifact that was not completely inspected: a gap in
# coverage, not evidence of harm (SkillSpector's own documentation agrees).
COVERAGE_RULES = frozenset({"AE1"})
PARSE_LIMIT = "static_parse_limit"

CREDENTIAL_STORE = re.compile(
    r"\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/|\.azure/|\.config/gcloud|"
    r"\.git-credentials|\.npmrc|\.pypirc|\.netrc|\.config/gh\b|\.docker/config|"
    r"\.kube/config|\.gnupg|keychain|login\.keychain|\bcredentials\.json\b",
    re.IGNORECASE)
SUDO = re.compile(r"\bsudo\b|\bdoas\b|\brunas\b", re.IGNORECASE)
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"`<>)\]]+", re.IGNORECASE)
# One named setting of the skill's own service: FOO_API_KEY, FOO_TOKEN, ...
SERVICE_VAR = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_KEY|KEY|TOKEN|SECRET|PATH|URL|"
                         r"ENDPOINT|PROJECT|REGION)\b")
DOTENV = re.compile(r"(?:^|[\s'\"/(~])\.env\b")
# Snippet content that is never "just off-purpose".
RISK_SIGNAL = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\bdel\s+/[sq]|\bRemove-Item\b.*-Recurse|"
    r"\bmkfs\b|\bformat\s+[a-z]:|\bchmod\s+(?:-R\s+)?[0-7]*7[0-7]{2}\b|"
    r"\bcrontab\b|\bschtasks\b|\breg(?:\.exe)?\s+add\b|\blaunchctl\b|"
    r"\bsystemctl\s+(?:--user\s+)?enable\b|\.bashrc\b|\.zshrc\b|\$PROFILE\b|"
    r"\beval\b|\bexec\s*\(|\bInvoke-Expression\b|\biex\b|FromBase64String|"
    r"\bbase64\s+(?:-d|--decode)\b|\b(?:printenv|env)\s*\|",
    re.IGNORECASE)
GITHUB_HOSTS = frozenset({"github.com", "raw.githubusercontent.com",
                          "objects.githubusercontent.com", "codeload.github.com"})
GENERIC_OWNER_TOKENS = frozenset({"ai", "hq", "dev", "inc", "io", "app", "labs", "lab", "official",
                                  "team", "org", "oss", "community", "skills", "cli", "sdk"})


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Origin:
    """Where a skill came from; `source` is `owner/repo`, `ref` a full commit SHA."""
    source: str
    ref: str

    @property
    def owner(self) -> str:
        return self.source.split("/", 1)[0].lower()


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int | None
    snippet: str
    unconfirmed: bool   # meta-review by the LLM did not confirm it (tag llm-unconfirmed)
    evidence_file: str | None = None
    evidence_lines: tuple = ()
    raw: dict = field(default_factory=dict, repr=False)
    # AE1 only: the lines on which the shell parser gave up in the target file;
    # None until located (or if they could not be).
    parse_spans: tuple | None = None

    @property
    def coverage_target(self) -> str:
        """AE1: the referenced file that was not completely inspected."""
        return str((self.raw.get("evidence") or {}).get("target_path") or "")

    def only_parse_limit(self) -> bool:
        """AE1 whose every reason is the shell parser giving up: the file was read."""
        ev = self.raw.get("evidence") or {}
        reasons = ev.get("reasons")
        return (self.rule in COVERAGE_RULES and ev.get("target_disposition") == "partial"
                and ev.get("reasons_truncated") is not True
                and isinstance(reasons, list) and bool(reasons)
                and all(isinstance(r, dict) and r.get("reason_code") == PARSE_LIMIT
                        for r in reasons))

    @classmethod
    def from_issue(cls, issue: dict) -> "Finding":
        loc = issue.get("location") or {}
        ev = issue.get("evidence") or {}
        tags = [str(t) for t in issue.get("tags") or []]
        lines = ()
        if ev.get("code_start_line"):
            start = int(ev["code_start_line"])
            lines = (start, int(ev.get("code_end_line") or start))
        return cls(rule=str(issue.get("id") or ""), severity=str(issue.get("severity") or "").upper(),
                   file=str(loc.get("file") or ""), line=loc.get("start_line"),
                   snippet=str(issue.get("code_snippet") or ""),
                   unconfirmed="llm-unconfirmed" in tags,
                   evidence_file=ev.get("code_path"), evidence_lines=lines, raw=issue)


@dataclass
class Disposition:
    finding: Finding
    status: str          # HARD, CLEARED, OPEN or CONFIRMED
    check: str | None    # catalog entry id, "approved", "verifier" or None
    reason: str


@dataclass
class Result:
    verdict: str
    dispositions: list

    def by_status(self, status: str) -> list:
        return [d for d in self.dispositions if d.status == status]


# -- catalog ------------------------------------------------------------------

def load_catalog(path: Path = CATALOG) -> dict:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("skillspector"), str):
        raise CatalogError("known_noise.toml needs version = 1 and a skillspector version")
    for entry in data.get("entry", []):
        if entry.get("check") not in CHECKS:
            raise CatalogError(f"unknown check {entry.get('check')!r} in {entry.get('id')!r}")
        if set(entry.get("rules") or ()) & HARD_RULES or not entry.get("rules"):
            raise CatalogError(f"{entry.get('id')!r} must name rules, and never hard evidence")
    return data


# -- helpers --------------------------------------------------------------------

def file_text(skill_dir: Path, rel: str | None) -> str:
    if not rel:
        return ""
    base = Path(skill_dir).resolve()
    path = (base / rel).resolve()
    if not path.is_relative_to(base) or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def flagged_text(f: Finding, skill_dir: Path) -> str:
    """The exact lines the finding points at: evidence lines, else its own line."""
    if f.evidence_file and f.evidence_lines:
        lines = file_text(skill_dir, f.evidence_file).splitlines()
        start, end = f.evidence_lines
        return "\n".join(lines[max(start - 1, 0):end])
    if f.line:
        lines = file_text(skill_dir, f.file).splitlines()
        if 0 < int(f.line) <= len(lines):
            return lines[int(f.line) - 1]
    return ""


def owner_tokens(origin: Origin) -> set:
    owner = origin.owner
    tokens = {t for t in owner.split("-") if len(t) >= 4 and t not in GENERIC_OWNER_TOKENS}
    return tokens | {owner}


def vendor_url(url: str, origin: Origin | None) -> bool:
    if origin is None:
        return False
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        return False
    if host in GITHUB_HOSTS:
        first = parts.path.strip("/").split("/", 1)[0].lower()
        return first == origin.owner
    labels = host.split(".")
    return len(labels) >= 2 and labels[-2] in owner_tokens(origin)


def pinned(origin: Origin | None) -> bool:
    return origin is not None and re.fullmatch(r"[0-9a-f]{40}", origin.ref or "") is not None


# -- catalog checks: True clears this one finding, with a reason --------------------

def check_vendor_installer(f, skill_dir, origin, exfil_files):
    text = flagged_text(f, skill_dir)
    urls = URL.findall(text)
    if not pinned(origin):
        return False, "source is not a pinned repository"
    if not urls:
        return False, "no URL on the flagged line"
    if not all(vendor_url(u, origin) for u in urls):
        return False, "a URL does not belong to the publisher"
    if SUDO.search(f.snippet or text) or CREDENTIAL_STORE.search(f.snippet or text):
        return False, "uses sudo or a credential store"
    if f.file in exfil_files:
        return False, "the file also shows data leaving the machine"
    return True, f"installer from the publisher's own address ({urlsplit(urls[0]).hostname})"


def check_service_key_env(f, skill_dir, origin, exfil_files):
    text = flagged_text(f, skill_dir)
    context = f"{f.snippet}\n{text}"
    if CREDENTIAL_STORE.search(context):
        return False, "touches a credential store"
    if f.file in exfil_files:
        return False, "the file also shows data leaving the machine"
    if not (SERVICE_VAR.search(context) or DOTENV.search(context)):
        return False, "no named service setting on the flagged lines"
    return True, "names a setting of the skill's own service"


def check_no_risk_signal(f, skill_dir, origin, exfil_files):
    text = flagged_text(f, skill_dir)
    if not text.strip():
        return False, "evidence lines not found"
    if not all(vendor_url(u, origin) for u in URL.findall(text)):
        return False, "a URL does not belong to the publisher"
    if SUDO.search(text) or CREDENTIAL_STORE.search(text) or RISK_SIGNAL.search(text):
        return False, "the snippet carries a risk signal"
    if (f.evidence_file or f.file) in exfil_files:
        return False, "the file also shows data leaving the machine"
    return True, "differs from the declared purpose but carries no risk signal"


def check_parse_limit_span(f, skill_dir, origin, exfil_files):
    if not f.only_parse_limit():
        return False, "the file was not completely read"
    target = f.coverage_target
    lines = file_text(skill_dir, target).splitlines()
    if not lines:
        return False, "the referenced file is not part of the skill"
    if target in exfil_files:
        return False, "the file also shows data leaving the machine"
    if f.parse_spans is None:
        return False, "the lines the scanner could not settle were not located"
    if not f.parse_spans:
        return False, "the pinned scanner does not reproduce the gap"
    text = "\n".join("\n".join(lines[start - 1:end]) for start, end in f.parse_spans)
    if not all(vendor_url(u, origin) for u in URL.findall(text)):
        return False, "a URL in the unsettled lines does not belong to the publisher"
    if SUDO.search(text) or CREDENTIAL_STORE.search(text) or RISK_SIGNAL.search(text):
        return False, "the unsettled lines carry a risk signal"
    return True, (f"the scanner's shell parser stumbled over {len(f.parse_spans)} "
                  f"passage(s) in {target}; they carry no risk signal")


CHECKS = {"vendor_installer": check_vendor_installer,
          "service_key_env": check_service_key_env,
          "no_risk_signal": check_no_risk_signal,
          "parse_limit_span": check_parse_limit_span}


# -- triage -------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def triage(report: dict, skill_dir: Path, raw_code: int, *, origin: Origin | None = None,
           catalog: dict | None = None, approved: frozenset = frozenset(),
           verifier=None, spans=None) -> Result:
    """Judge a SkillSpector report. `raw_code` is verdict_skillspector's exit code;
    `approved` holds SHA-256 hashes of files a person already approved;
    `verifier(open_dispositions, skill_dir) -> answers` is stage d (optional);
    `spans(skill_dir, [rel, ...]) -> {rel: [(start, end), ...] | None}` locates
    the lines behind parser-limit AE1 findings (_parse_spans.py, optional)."""
    if raw_code not in (0, 1):
        return Result(NO_VERDICT, [])
    catalog = catalog if catalog is not None else load_catalog()
    version = str((report.get("metadata") or {}).get("skillspector_version") or "")
    entries = catalog.get("entry", []) if version == catalog.get("skillspector") else []
    findings = [Finding.from_issue(i) for i in report.get("issues") or []]
    exfil_files = set()
    for f in findings:
        if f.rule in EXFIL_RULES or f.rule in HARD_RULES:
            exfil_files.update(p for p in (f.file, f.evidence_file) if p)
    locate_spans(findings, skill_dir, spans)

    out = []
    for f in findings:
        if f.rule in HARD_RULES:
            out.append(Disposition(f, HARD, None, "hard evidence"))
            continue
        if f.severity not in BLOCKING:
            continue
        target = Path(skill_dir) / (f.evidence_file or f.file)
        if approved and target.is_file() and sha256_file(target) in approved:
            out.append(Disposition(f, CLEARED, "approved", "file content approved before"))
            continue
        disposition = Disposition(f, OPEN, None, "no check cleared this finding")
        for entry in entries:
            if f.rule in entry["rules"]:
                ok, reason = CHECKS[entry["check"]](f, skill_dir, origin, exfil_files)
                if ok:
                    disposition = Disposition(f, CLEARED, entry["id"], reason)
                    break
                disposition.reason = reason
        out.append(disposition)

    still_open = [d for d in out if d.status == OPEN]
    if verifier is not None and still_open and not any(d.status == HARD for d in out):
        for d, answer in zip(still_open, verifier(still_open, Path(skill_dir))):
            if answer.verdict == "benign":
                d.status, d.check, d.reason = CLEARED, "verifier", answer.reason
            elif answer.verdict == "malicious":
                d.status, d.check, d.reason = CONFIRMED, "verifier", answer.reason
            elif answer.reason:
                d.reason = f"{d.reason}; verifier unsure: {answer.reason}"

    if any(blocks(d) for d in out):
        verdict = DANGEROUS
    elif any(d.status == OPEN for d in out):
        verdict = UNCLEAR
    else:
        verdict = SAFE
    return Result(verdict, out)


def blocks(d: Disposition) -> bool:
    """Whether this one disposition makes the skill dangerous."""
    if d.status in (HARD, CONFIRMED):
        return True
    return (d.status == OPEN and not d.finding.unconfirmed
            and d.finding.rule not in COVERAGE_RULES)


def locate_spans(findings: list, skill_dir: Path, spans) -> None:
    """Attach the unsettled lines to every parser-limit AE1 finding. With lines
    found, the finding's evidence becomes those lines of the target file, so
    an approval, the verifier and its cache all look at what was not settled."""
    wanted = [f for f in findings if f.only_parse_limit() and f.coverage_target]
    if spans is None or not wanted:
        return
    try:
        found = spans(Path(skill_dir), [f.coverage_target for f in wanted])
    except Exception:  # a failed locator leaves the findings open, nothing more
        return
    for f in wanted:
        located = found.get(f.coverage_target) if isinstance(found, dict) else None
        if located is None:
            continue
        f.parse_spans = tuple(located)
        if located:
            f.evidence_file = f.coverage_target
            f.evidence_lines = (min(s for s, _ in located), max(e for _, e in located))
