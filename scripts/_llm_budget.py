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

MODEL = "gpt-oss-120b"
POLICY = {"version": 1, "scanner": "2.12.0", "model": MODEL,
          "input_tokens": 8192, "output_tokens": 4096,
          "total_nusd": 4_000_000_000, "step_nusd": 500_000_000,
          "probe_nusd": 100_000_000, "step_requests": 10,
          "input_nusd": 350, "output_nusd": 750}


class Paused(RuntimeError):
    """A persisted, fail-closed stop; never an empty successful response."""


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

    def __init__(self, campaign: Path, session: Path, identity: str, *, preview=False,
                 transport=None, clock=time.time, sleep=time.sleep):
        self.campaign, self.session, self.identity = campaign, session, identity
        self.preview, self.transport, self.clock, self.sleep = preview, transport, clock, sleep
        self.path = campaign / "budget.json"
        self.data = (json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists()
                     else {"policy": POLICY, "attempts": [], "not_before": 0})
        if self.data["policy"] != POLICY:
            raise Paused("Campaign policy changed; review required")
        self.step_limit = POLICY["probe_nusd"] if not self.data["attempts"] else POLICY["step_nusd"]
        self.request_limit = 1 if not self.data["attempts"] else POLICY["step_requests"]
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
        key = digest({"identity": self.identity, "policy": POLICY,
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
            if estimated > POLICY["input_tokens"]:
                self.stop("Final prompt exceeds input limit; no content was truncated")
            if any(a["id"] == key and a["state"] not in ("complete", "rate_limited") for a in self.data["attempts"]):
                self.stop("Previous request has an unresolved outcome; explicit review required")
            reserve = upper * POLICY["input_nusd"] + POLICY["output_tokens"] * POLICY["output_nusd"]
            attempts = self.data["attempts"]
            if len(attempts) - self.step_start >= self.request_limit:
                self.stop("Etappe complete: request limit reached")
            if sum(a["charged_nusd"] for a in attempts[self.step_start:]) + reserve > self.step_limit:
                self.stop("Etappe budget exhausted")
            if sum(a["charged_nusd"] for a in attempts) + reserve > POLICY["total_nusd"]:
                self.stop("Campaign budget exhausted")
            now = self.clock()
            if self.data["not_before"] > now:
                self.stop(f"Provider pause; resume after Unix time {self.data['not_before']}")
            for name, quota in self.data.get("quotas", {}).items():
                needed = estimated + POLICY["output_tokens"] if "token" in name else 1
                if quota["reset"] > now and quota["remaining"] < needed:
                    self.data["not_before"] = quota["reset"]
                    self.save()
                    self.stop(f"Provider quota low; resume after Unix time {quota['reset']}")
            # Three requests/minute and a conservative rolling 30K token budget.
            recent = [a for a in attempts if now - a["time"] < 60]
            token_load = sum(a["estimated_tokens"] for a in recent)
            if recent and token_load + estimated + POLICY["output_tokens"] > 30000:
                self.sleep(max(0, 60 - (now - recent[0]["time"])))
            if attempts:
                self.sleep(max(0, attempts[-1]["time"] + 20.1 - self.clock()))
            attempt = {"id": key, "time": self.clock(), "state": "reserved",
                       "charged_nusd": reserve, "reserved_nusd": reserve,
                       "estimated_tokens": estimated + POLICY["output_tokens"],
                       "session": self.session.name}
            attempts.append(attempt)
            self.save()  # Durable BEFORE dispatch, also on interruption/crash.
            try:
                response, headers = self.transport(payload)
                self.quota_headers(headers)
                usage = response.get("usage")
                if isinstance(usage, dict) and all(type(usage.get(k)) is int and usage[k] >= 0
                                                 for k in ("prompt_tokens", "completion_tokens")):
                    actual = usage["prompt_tokens"] * POLICY["input_nusd"] + usage["completion_tokens"] * POLICY["output_nusd"]
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
        return {"policy": POLICY, "preview": self.preview,
                "requests_this_step": len(self.data["attempts"]) - self.step_start,
                "requests_total": len(self.data["attempts"]),
                "charged_or_reserved_usd": sum(a["charged_nusd"] for a in self.data["attempts"]) / 1e9,
                "pause_reason": self.stopped, "not_before": self.data["not_before"],
                "prompts": list(self.observed.values()),
                "dependent_prompts": "Meta prompts remain provisional until all semantic results exist",
                "complete": False}
