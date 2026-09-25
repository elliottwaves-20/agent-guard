"""Durable, single-writer budget and response cache for bounded API scans.

Amounts are integer nano-dollars; unknown transport outcomes retain reservations.
This module has no scanner dependency and never reads dotenv files.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from decimal import Decimal, InvalidOperation

from _llm_profile import ProfileError


class Paused(RuntimeError):
    """A persisted, fail-closed stop; never an empty successful response."""


def _nano_usd(name, section, field, value, per=1):
    """Dollar amount (or $/Mtok when per=10**6) as integer nano-dollars."""
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        amount = Decimal(-1)
    if isinstance(value, bool) or value is None or not amount.is_finite() or amount < 0:
        raise ProfileError(f"profile {name}: {section}.{field} must be a non-negative number")
    nano = amount * 10**9 / per
    if nano != nano.to_integral_value():
        raise ProfileError(f"profile {name}: {section}.{field} is finer than a nano-dollar")
    return int(nano)


def policy_from_profile(name: str, profile: dict, scanner: str) -> dict:
    """Build the campaign policy from an api/openai profile.

    Everything provider-specific (model, endpoint, prices, quotas, caps) comes
    from the profile; the policy is bound into every cache key and the ledger,
    so changing any of it pauses an existing campaign for review."""
    for section in ("price", "budget"):
        if not isinstance(profile.get(section), dict):
            raise ProfileError(f"profile {name}: [{section}] is required for budgeted campaigns")
    if "max_output" not in profile:
        raise ProfileError(f"profile {name}: max_output is required for budgeted campaigns")
    price, budget = profile["price"], profile["budget"]
    limits = profile.get("limits") or {}
    for field in ("rpm", "tpm"):
        value = limits.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ProfileError(f"profile {name}: limits.{field} must be an integer >= 1")
    requests = budget.get("step_requests", 10)
    if isinstance(requests, bool) or not isinstance(requests, int) or requests < 1:
        raise ProfileError(f"profile {name}: budget.step_requests must be an integer >= 1")
    return {"version": 2, "scanner": scanner, "profile": name,
            "model": profile["model"], "base_url": profile["base_url"].rstrip("/"),
            "key_env": profile["key_env"], "pricing_url": profile.get("pricing_url"),
            "input_tokens": profile.get("max_input", 8192),
            "output_tokens": profile["max_output"],
            "total_nusd": _nano_usd(name, "budget", "total_usd", budget.get("total_usd")),
            "step_nusd": _nano_usd(name, "budget", "step_usd", budget.get("step_usd")),
            "probe_nusd": _nano_usd(name, "budget", "probe_usd", budget.get("probe_usd", 0.1)),
            "step_requests": requests,
            "input_nusd": _nano_usd(name, "price", "input_usd_per_mtok",
                                    price.get("input_usd_per_mtok"), 10**6),
            "output_nusd": _nano_usd(name, "price", "output_usd_per_mtok",
                                     price.get("output_usd_per_mtok"), 10**6),
            "rpm": limits.get("rpm"), "tpm": limits.get("tpm")}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def atomic_json(path: Path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


@contextmanager
def exclusive_lock(path: Path):
    """OS-released lock: process crashes do not leave a stale lock owner."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise Paused("Another budgeted scan owns the campaign lock") from exc
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise Paused("Another budgeted scan owns the campaign lock") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


class Budget:
    """Caller must hold the campaign OS lock for the entire instance lifetime."""

    def __init__(self, campaign: Path, session: Path, identity: str, *, policy: dict,
                 preview=False, transport=None, clock=time.time, sleep=time.sleep):
        self.campaign, self.session, self.identity = campaign, session, identity
        self.policy = policy
        self.preview, self.transport, self.clock, self.sleep = preview, transport, clock, sleep
        self.path = campaign / "budget.json"
        self.data = (json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists()
                     else {"policy": policy, "attempts": [], "not_before": 0})
        if self.data["policy"] != policy:
            raise Paused("Campaign policy changed; review required")
        self.step_limit = self.policy["probe_nusd"] if not self.data["attempts"] else self.policy["step_nusd"]
        self.request_limit = 1 if not self.data["attempts"] else self.policy["step_requests"]
        self.step_start = len(self.data["attempts"])
        self.stopped = None
        self.observed = {}
        self.mutex = threading.RLock()

    def save(self):
        atomic_json(self.path, self.data)

    def quota_headers(self, headers):
        """Respect lower provider quotas, without guessing that missing means zero."""
        headers = {str(k).lower(): str(v) for k, v in headers.items()}
        quotas = {}
        for name, value in headers.items():
            if not name.startswith("x-ratelimit-remaining-"):
                continue
            suffix = name[len("x-ratelimit-remaining-"):]
            try:
                remaining = float(value)
                reset = headers.get("x-ratelimit-reset-" + suffix)
                duration = 86400 if "day" in suffix else 3600 if "hour" in suffix else 60
                if reset:
                    import re
                    parts = re.findall(r"([0-9.]+)(ms|s|m|h|d)", reset)
                    if parts:
                        duration = sum(float(n) * {"ms": .001, "s": 1, "m": 60, "h": 3600, "d": 86400}[u]
                                       for n, u in parts)
                    else:
                        number = float(reset)
                        duration = number - self.clock() if number > 1_000_000_000 else number
                if math.isfinite(remaining) and math.isfinite(duration):
                    quotas[suffix] = {"remaining": remaining, "reset": self.clock() + max(1, duration)}
            except (ValueError, TypeError):
                continue
        self.data["quotas"] = quotas

    def stop(self, reason):
        self.stopped = reason
        raise Paused(reason)

    def measure(self, payload, context):
        # Byte upper bound rather than chars/4: deliberately conservative for
        # multilingual text. Includes JSON schema, messages and framing margin.
        size = len(canonical(payload).encode("utf-8"))
        estimated = math.ceil(size / 3)
        upper = size + 1024
        key = digest({"identity": self.identity, "policy": self.policy,
                      "payload": payload, "context": context})
        self.observed[key] = {"id": key, **context, "bytes": size,
                              "estimated_input_tokens": estimated,
                              "reserved_input_tokens": upper, "state": "pending"}
        return key, estimated, upper

    def call(self, payload, context, validate):
        with self.mutex:
            key, estimated, upper = self.measure(payload, context)
            cache = self.session / "responses" / (key + ".json")
            if cache.exists():
                saved = json.loads(cache.read_text(encoding="utf-8"))
                result = validate(saved["content"])
                self.observed[key]["state"] = "cached"
                return result, saved.get("usage")
            if self.preview:
                raise Paused("Offline preview: no model request sent")
            if self.stopped:
                raise Paused(self.stopped)
            if context.get("analyzer") == "meta_analyzer" and any(
                v["state"] == "pending" and v.get("analyzer") != "meta_analyzer"
                for v in self.observed.values()
            ):
                self.stop("Meta analysis deferred until prerequisite batches complete")
            if estimated > self.policy["input_tokens"]:
                self.stop("Final prompt exceeds input limit; no content was truncated")
            if any(a["id"] == key and a["state"] not in ("complete", "rate_limited") for a in self.data["attempts"]):
                self.stop("Previous request has an unresolved outcome; explicit review required")
            reserve = upper * self.policy["input_nusd"] + self.policy["output_tokens"] * self.policy["output_nusd"]
            attempts = self.data["attempts"]
            if len(attempts) - self.step_start >= self.request_limit:
                self.stop("Etappe complete: request limit reached")
            if sum(a["charged_nusd"] for a in attempts[self.step_start:]) + reserve > self.step_limit:
                self.stop("Etappe budget exhausted")
            if sum(a["charged_nusd"] for a in attempts) + reserve > self.policy["total_nusd"]:
                self.stop("Campaign budget exhausted")
            now = self.clock()
            if self.data["not_before"] > now:
                self.stop(f"Provider pause; resume after Unix time {self.data['not_before']}")
            for name, quota in self.data.get("quotas", {}).items():
                needed = estimated + self.policy["output_tokens"] if "token" in name else 1
                if quota["reset"] > now and quota["remaining"] < needed:
                    self.data["not_before"] = quota["reset"]
                    self.save()
                    self.stop(f"Provider quota low; resume after Unix time {quota['reset']}")
            # Provider quotas from the profile: a rolling per-minute token window
            # and even request spacing (60/rpm seconds plus a small margin).
            recent = [a for a in attempts if now - a["time"] < 60]
            token_load = sum(a["estimated_tokens"] for a in recent)
            if (self.policy["tpm"] and recent
                    and token_load + estimated + self.policy["output_tokens"] > self.policy["tpm"]):
                self.sleep(max(0, 60 - (now - recent[0]["time"])))
            if attempts and self.policy["rpm"]:
                self.sleep(max(0, attempts[-1]["time"] + 60 / self.policy["rpm"] + 0.1 - self.clock()))
            attempt = {"id": key, "time": self.clock(), "state": "reserved",
                       "charged_nusd": reserve, "reserved_nusd": reserve,
                       "estimated_tokens": estimated + self.policy["output_tokens"],
                       "session": self.session.name}
            attempts.append(attempt)
            self.save()  # Durable BEFORE dispatch, also on interruption/crash.
            try:
                response, headers = self.transport(payload)
                self.quota_headers(headers)
                usage = response.get("usage")
                if isinstance(usage, dict) and all(type(usage.get(k)) is int and usage[k] >= 0
                                                 for k in ("prompt_tokens", "completion_tokens")):
                    actual = usage["prompt_tokens"] * self.policy["input_nusd"] + usage["completion_tokens"] * self.policy["output_nusd"]
                    attempt["charged_nusd"] = actual
                    attempt["usage"] = usage
                    if actual > reserve:
                        raise Paused("Provider usage exceeded reservation; review estimator")
                choice = response["choices"][0]
                if choice.get("finish_reason") != "stop":
                    raise Paused("Response incomplete or output ceiling reached")
                content = choice["message"]["content"]
                result = validate(content)
                cache.parent.mkdir(exist_ok=True)
                atomic_json(cache, {"content": content, "usage": usage})
                attempt["state"] = "complete"
                self.observed[key]["state"] = "complete"
                self.save()
                return result, usage
            except Exception as exc:
                # Never log provider response bodies (may contain source/secrets).
                attempt["state"] = "unresolved"
                attempt["error"] = type(exc).__name__
                if getattr(exc, "status_code", None) == 429:
                    retry = getattr(exc, "retry_after", 60)
                    self.data["not_before"] = self.clock() + retry
                    attempt["state"] = "rate_limited"
                self.save()
                self.stop(f"Request paused: {type(exc).__name__}; inspect budget.json")

    def summary(self):
        return {"policy": self.policy, "preview": self.preview,
                "requests_this_step": len(self.data["attempts"]) - self.step_start,
                "requests_total": len(self.data["attempts"]),
                "charged_or_reserved_usd": sum(a["charged_nusd"] for a in self.data["attempts"]) / 1e9,
                "pause_reason": self.stopped, "not_before": self.data["not_before"],
                "prompts": list(self.observed.values()),
                "dependent_prompts": "Meta prompts remain provisional until all semantic results exist",
                "complete": False}
