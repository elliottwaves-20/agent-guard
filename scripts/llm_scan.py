#!/usr/bin/env python3
"""Bounded SkillSpector selfscans: plan TARGET, run SESSION, resume SESSION.

Sessions share one campaign ledger, outside every target. The provider, its
prices, quotas and budget caps come from the [llm.use] campaign profile of the
user config (kind = "api", protocol = "openai"); the key is read only from the
variable that profile names. No installation or baseline approval is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from _llm_budget import Budget, Paused, atomic_json, digest, exclusive_lock, policy_from_profile


def campaign_root():
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "state"))
    return base / "agent-guard" / "llm-campaign"


def adapter_identity():
    root = Path(__file__).parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("llm_scan.py", "_llm_adapter.py", "_llm_budget.py")}


def manifest(root):
    entries = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise Paused("Snapshot contains a link or junction")
        if path.is_file():
            entries[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return entries


def new_session(target, campaign, policy):
    target, campaign = target.resolve(strict=True), campaign.resolve()
    if not target.is_dir():
        raise Paused("plan requires a local directory")
    if campaign == target or campaign.is_relative_to(target) or target.is_relative_to(campaign):
        raise Paused("Campaign and target must be disjoint directories")
    # Explicit census, preserving tests/docs. Git metadata and runtime caches are
    # never source. Local credential/config files are reported as exclusions.
    excluded, paths = [], []
    skip_dirs = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
    for parent, directories, files in os.walk(target, followlinks=False):
        for name in list(directories):
            path = Path(parent) / name
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise Paused("Target contains a directory link; explicit source review required")
            if name in skip_dirs:
                directories.remove(name)
                excluded.append({"path": path.relative_to(target).as_posix(), "reason": "runtime/metadata directory"})
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(target).as_posix()
            if path.is_symlink():
                raise Paused("Target contains a file link; explicit source review required")
            if (name == ".env" or (name.startswith(".env.") and name != ".env.example")
                    or relative in (".claude/settings.local.json", ".codex/config.toml")):
                excluded.append({"path": relative, "reason": "local credentials/configuration"})
            else:
                paths.append((path, relative))
    session = campaign / "sessions" / uuid.uuid4().hex
    snapshot = session / "snapshot"
    snapshot.mkdir(parents=True)
    for source, relative in paths:
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    files = manifest(snapshot)
    # Catch ordinary edits while copying; do not claim an atomic live checkout.
    if any(hashlib.sha256(source.read_bytes()).hexdigest() != files[relative] for source, relative in paths):
        raise Paused("Target changed while creating snapshot; plan again")
    binding = {"files": files, "policy": policy, "adapter": adapter_identity()}
    info = {"target": str(target), **binding, "excluded": excluded,
            "identity": digest(binding), "campaign": str(campaign)}
    atomic_json(session / "session.json", info)
    return session


def validate_session(session, campaign, policy):
    session = session.resolve(strict=True)
    if session.parent != campaign.resolve() / "sessions":
        raise Paused("Session does not belong to this campaign")
    info = json.loads((session / "session.json").read_text(encoding="utf-8"))
    files = manifest(session / "snapshot")
    binding = {"files": files, "policy": policy, "adapter": adapter_identity()}
    if (info["files"] != files or info["policy"] != policy or
            info["identity"] != digest(binding)):
        raise Paused("Snapshot/policy changed; cached responses cannot be reused")
    return info


def campaign_policy(env=None) -> dict:
    """Policy of the [llm.use] campaign profile; Paused when none is usable."""
    import _llm_profile
    import _pins
    import _user_config
    env = os.environ if env is None else env
    try:
        selected = _llm_profile.select_profile(_user_config.load_config(env=env), "campaign", env)
        if selected is None:
            raise Paused("No [llm.use] campaign profile configured; see config.example.toml")
        return policy_from_profile(*selected, _pins.SKILLSPECTOR_VERSION)
    except (_user_config.ConfigError, _llm_profile.ProfileError) as exc:
        raise Paused(str(exc)) from None


def scan(session, campaign, preview, policy):
    info = validate_session(session, campaign, policy)
    from _llm_adapter import ProviderError, install, live_transport
    budget = Budget(campaign, session, info["identity"], policy=policy, preview=preview)
    # Check installed contract before touching any provider network endpoint.
    try:
        install(budget)
        if not preview:
            budget.transport = live_transport(policy)
    except (Paused, ProviderError, OSError, ValueError, KeyError) as exc:
        budget.stopped = f"Preflight failed: {type(exc).__name__}"
        if isinstance(exc, ProviderError):
            budget.stopped += f" (HTTP {exc.status_code})"
        summary = budget.summary()
        summary["session"] = str(session)
        atomic_json(session / ("plan.json" if preview else "progress.json"), summary)
        print(budget.stopped)
        return 2
    from skillspector.cli import app
    report = session / "report.json"
    if report.exists():
        report.unlink()  # Previous partial report is not evidence for this pass.
    exit_code = 2
    try:
        app(args=["scan", str(session / "snapshot"), "--format", "json", "--output", str(report)],
            standalone_mode=False)
        exit_code = 0
    except SystemExit as exc:
        exit_code = exc.code
    finally:
        summary = budget.summary()
        summary["snapshot_intact"] = manifest(session / "snapshot") == info["files"]
        summary["session"] = str(session)
        atomic_json(session / ("plan.json" if preview else "progress.json"), summary)
        print(json.dumps({k: v for k, v in summary.items() if k != "prompts"}, indent=2))
    if preview:
        return 2  # A preview never constitutes a security verdict.
    if (not summary["snapshot_intact"] or not budget.observed or
            any(v["state"] == "pending" for v in budget.observed.values())):
        return 2
    os.environ["AGENT_GUARD_NO_DOTENV"] = "1"
    from _skillspector import _load_report, llm_run_incomplete, verdict_skillspector
    data = _load_report(report)
    if data is None or llm_run_incomplete(data, expected=True):
        return 2
    verdict = verdict_skillspector(report, exit_code)
    summary["complete"] = verdict in (0, 1)
    summary["verdict_exit_code"] = verdict
    atomic_json(session / "progress.json", summary)
    return verdict


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "run", "resume"))
    parser.add_argument("path", type=Path, help="Target for plan; printed session directory for run/resume")
    args = parser.parse_args()
    # Re-exec in the installed scanner environment, with a bounded owned tree.
    try:
        importlib.metadata.version("skillspector")
    except importlib.metadata.PackageNotFoundError:
        os.environ["AGENT_GUARD_NO_DOTENV"] = "1"
        from _skillspector import skillspector_python, run_bounded
        interpreter = skillspector_python()
        if not interpreter:
            raise Paused("SkillSpector tool Python unavailable; run setup first")
        result = run_bounded([interpreter, str(Path(__file__).resolve()), *sys.argv[1:]],
                             timeout=700, env=dict(os.environ))
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return result.returncode
    policy = campaign_policy()
    campaign = campaign_root().resolve()
    with exclusive_lock(campaign / "campaign.lock"):
        session = (new_session(args.path, campaign, policy) if args.command == "plan"
                   else args.path.resolve())
        print(f"Session: {session}", flush=True)
        return scan(session, campaign, args.command == "plan", policy)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Paused, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"INCOMPLETE: {exc}", file=sys.stderr)
        sys.exit(2)
