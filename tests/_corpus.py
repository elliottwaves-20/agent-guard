"""Load the calibration corpus described in tests/corpus/manifest.toml.

Every entry is fetched from a pinned commit into a caller-owned directory and
checked against its tree hash; a mismatch raises instead of handing a changed
sample to a test. Nothing here installs anything.
"""
import importlib
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
staging = importlib.import_module("_staging")
resolver = importlib.import_module("_url_resolver")

MANIFEST = ROOT / "tests" / "corpus" / "manifest.toml"
VERDICTS = {"safe", "dangerous"}


class CorpusError(RuntimeError):
    pass


@dataclass(frozen=True)
class Sample:
    id: str
    kind: str          # "benign" or "malicious"
    expect: str        # "safe" or "dangerous"
    tree_hash: str
    source: str
    ref: str
    hard: bool = False
    noise: tuple = ()
    needs_llm: bool = False
    open: tuple = ()    # rules left open on purpose until `open_until` lands
    open_until: str = ""


def load_manifest(path: Path = MANIFEST) -> tuple:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise CorpusError(f"unknown corpus manifest version {data.get('version')!r}")
    repo = data["malicious_repo"]
    samples = []
    for e in data.get("benign", []):
        samples.append(Sample(e["name"], "benign", e["expect"], e["tree_hash"],
                              e["source"], e["ref"], noise=tuple(e.get("noise", ())),
                              open=tuple(e.get("open", ())),
                              open_until=e.get("open_until", "")))
    for e in data.get("malicious", []):
        samples.append(Sample(e["id"], "malicious", e["expect"], e["tree_hash"],
                              repo["source"], repo["ref"], hard=bool(e.get("hard")),
                              needs_llm=bool(e.get("needs_llm"))))
    return tuple(samples)


def verify(sample: Sample, path: Path) -> Path:
    actual = staging.tree_digest(path)
    if actual != sample.tree_hash:
        raise CorpusError(f"{sample.id}: content hash {actual} does not match the "
                          f"manifest ({sample.tree_hash})")
    return path


def fetch_benign(samples: list, workdir: Path) -> dict:
    """Stage benign samples through the pinned skills CLI, one call per commit."""
    groups = {}
    for s in samples:
        groups.setdefault((s.source, s.ref), []).append(s)
    out = {}
    for n, ((source, ref), group) in enumerate(sorted(groups.items())):
        target = workdir / f"benign-{n}"
        target.mkdir(parents=True)
        staged = staging.stage(source, ref, [s.id for s in group], target)
        for s in group:
            if s.id not in staged:
                raise CorpusError(f"{s.id}: {source}#{ref} no longer has this skill")
            out[s.id] = verify(s, staged[s.id].path)
    return out


def fetch_malicious(samples: list, workdir: Path) -> dict:
    """Download the corpus repository once as a commit-pinned ZIP snapshot."""
    if not samples:
        return {}
    source, ref = samples[0].source, samples[0].ref
    if any((s.source, s.ref) != (source, ref) for s in samples):
        raise CorpusError("malicious samples must come from one pinned commit")
    if not staging.SHA.fullmatch(ref):
        raise CorpusError(f"malicious_repo ref must be a full commit SHA, got {ref!r}")
    target = workdir / "malicious"
    target.mkdir(parents=True)
    data = resolver.http_bytes(f"https://github.com/{source}/archive/{ref}.zip")
    resolver.safe_extract_zip(data, target)
    root = resolver.first_child_dir(target) / "malicious"
    return {s.id: verify(s, root / s.id) for s in samples}


def fetch_all(workdir: Path, samples: tuple | None = None) -> dict:
    samples = samples if samples is not None else load_manifest()
    benign = [s for s in samples if s.kind == "benign"]
    malicious = [s for s in samples if s.kind == "malicious"]
    return {**fetch_benign(benign, workdir), **fetch_malicious(malicious, workdir)}
