"""One canonical place for which model each part of the lab asks for, and for proving which model actually ran.

Three identities are kept apart and never conflated:
- REQUESTED: the model the deployment is configured to use for a role (a name, normalised with Ollama's own rule that no tag means `latest`).
- RESOLVED: what Ollama reports it has installed under exactly that name (digest, size, quantization), read from /api/tags, plus Ollama's version.
- EXECUTED: the model name Ollama says answered, checked against the request after the call (and, for a Loan Desk run, whether the digest changed during it).

Matching is EXACT on the normalised name. A family prefix (`llama3.2` matching `llama3.2:latest`), a different tag or a different model never
satisfies a request: the run is refused (fail closed) and nothing is substituted. This module only reads; it never pulls or deletes a model.

Roles keep their own defaults on purpose. The AcmeBank pipeline labs and the Loan Desk have always used different models (the Loan Desk's
default was chosen by the Batch 2 whole-loop benchmark); collapsing them into one would silently change what a configured installation runs.
Unifying them is a decision for the benchmark phase, not for this module.
"""
from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import requests

from agentsec.model_names import (NAME_RE, ROLES, ModelConfigError, default_for, normalize, requested,  # noqa: F401  (re-exported: the one public API)
                                  requested_or_raw)

RESOLVE_TTL_SEC = 5.0
MAX_RESPONSE_MODELS = 16

EXACT, NOT_INSTALLED, UNREACHABLE, ERROR, INVALID = "EXACT", "NOT_INSTALLED", "UNREACHABLE", "ERROR", "INVALID_NAME"


@dataclass(frozen=True)
class Resolution:
    status: str
    requested: str
    normalized: str
    name: str | None = None
    digest: str | None = None
    size_bytes: int | None = None
    family: str | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    ollama_version: str | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == EXACT

    @property
    def identity_status(self) -> str:
        """DIGEST_RECORDED: exact name and Ollama reported a digest. NAME_VERIFIED: exact name, no digest reported. Otherwise the status itself."""
        if self.status != EXACT:
            return self.status
        return "DIGEST_RECORDED" if self.digest else "NAME_VERIFIED"

    def as_dict(self) -> dict:
        return {"status": self.status, "identity_status": self.identity_status, "requested": self.requested, "name": self.name, "digest": self.digest,
                "size_bytes": self.size_bytes, "family": self.family, "parameter_size": self.parameter_size, "quantization": self.quantization,
                "ollama_version": self.ollama_version, "detail": self.detail}


def ollama_version(base_url: str, *, get: Callable | None = None, timeout: float = 3) -> str | None:
    get = get or requests.get          # looked up at call time so a patched requests.get is honoured
    try:
        r = get(f"{base_url.rstrip('/')}/api/version", timeout=timeout)
        v = r.json().get("version") if r.status_code == 200 else None
        return v if isinstance(v, str) and v else None
    except (requests.RequestException, ValueError, AttributeError):
        return None


def _s(v: object, n: int) -> str | None:
    """Ollama-supplied text is data: only a non-empty string, cut to a bound, ever reaches evidence."""
    return v[:n] if isinstance(v, str) and v.strip() else None


def resolve(base_url: str, requested_name: str, *, get: Callable | None = None, timeout: float = 3) -> Resolution:
    """Ask Ollama what it has installed under EXACTLY this name. Never raises; never pulls."""
    get = get or requests.get
    try:
        normalized = normalize(requested_name)
    except ModelConfigError as exc:
        return Resolution(INVALID, str(requested_name)[:200], str(requested_name)[:200], detail=f"The configured model name is invalid: {exc}")
    base = base_url.rstrip("/")
    try:
        r = get(f"{base}/api/tags", timeout=timeout)
    except requests.RequestException as exc:
        return Resolution(UNREACHABLE, requested_name, normalized, detail=f"Ollama is not reachable ({type(exc).__name__}).")
    except Exception as exc:  # a patched or odd transport must not turn a health probe into a crash
        return Resolution(ERROR, requested_name, normalized, detail=f"Ollama could not be queried ({type(exc).__name__}).")
    if r.status_code != 200:
        return Resolution(ERROR, requested_name, normalized, detail=f"Ollama answered HTTP {r.status_code} for the model list.")
    try:
        listed = r.json().get("models") or []
        if not isinstance(listed, list):
            raise TypeError("models is not a list")
        models = [m for m in listed if isinstance(m, dict)]
    except (ValueError, AttributeError, TypeError):
        return Resolution(ERROR, requested_name, normalized, detail="Ollama's model list was not valid JSON.")
    hits = [m for m in models if _same(str(m.get("name") or m.get("model") or ""), normalized)]
    if len({str(m.get("digest") or "") for m in hits}) > 1:
        return Resolution(ERROR, requested_name, normalized, detail=f"Ollama lists {normalized!r} more than once with different digests; refusing to guess which one runs.")
    if hits:
        m = hits[0]
        d = m.get("details") if isinstance(m.get("details"), dict) else {}
        size = m.get("size")
        return Resolution(EXACT, requested_name, normalized, name=_s(m.get("name") or m.get("model"), 200), digest=_s(m.get("digest"), 128),
                          size_bytes=size if isinstance(size, int) and not isinstance(size, bool) else None, family=_s(d.get("family"), 64),
                          parameter_size=_s(d.get("parameter_size"), 64), quantization=_s(d.get("quantization_level"), 64),
                          ollama_version=_s(ollama_version(base, get=get, timeout=timeout), 64), detail="The requested model is installed.")
    return Resolution(NOT_INSTALLED, requested_name, normalized,
                      detail=f"Ollama has no model named exactly {normalized!r}. Nothing else is used in its place.")


def _same(a: str, b_normalized: str) -> bool:
    if a != a.strip():            # padded names are not the same name
        return False
    try:
        return normalize(a) == b_normalized
    except ModelConfigError:
        return False


def response_matches(requested_name: str, response_model: object) -> bool | None:
    """True/False when Ollama named the model that answered; None when it did not say (cannot be verified, not a mismatch)."""
    if not isinstance(response_model, str) or not response_model.strip():
        return None
    try:
        return _same(response_model, normalize(requested_name))
    except ModelConfigError:
        return False


class ResolutionCache:
    """Short-lived cache so a busy pipeline does not ask Ollama for its model list on every call. Failures are cached for the same short time."""

    def __init__(self, ttl: float = RESOLVE_TTL_SEC, clock: Callable[[], float] = time.monotonic):
        self.ttl, self.clock, self._items, self._lock = ttl, clock, {}, threading.Lock()

    def get(self, base_url: str, requested_name: str, *, get: Callable | None = None) -> Resolution:
        try:
            key = (base_url.rstrip("/"), normalize(requested_name))
        except ModelConfigError:
            return resolve(base_url, requested_name, get=get)     # invalid name: a fresh ERROR, nothing to cache
        now = self.clock()
        with self._lock:
            hit = self._items.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
        res = resolve(base_url, requested_name, get=get)
        if res.status in (EXACT, NOT_INSTALLED):     # a transient timeout or error is never remembered: the next call asks again
            with self._lock:
                self._items[key] = (now, res)
                if len(self._items) > 64:
                    self._items.pop(next(iter(self._items)))
        return res

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# ---- what actually ran: summarised from THIS run's own calls ------------------------------------------------------------------------------
def summarize_calls(requested_name: str, identities: list) -> dict:
    """The identity block for an evidence manifest, built only from the per-call identity records the model client attached to THIS run's results
    (OllamaClient.generate -> LLMResult.identity). Nothing is remembered between runs, so no run can inherit another run's digest.
    Verdict order: MISMATCH (a different model answered) > a refusal status (NOT_INSTALLED, INVALID_NAME, UNREACHABLE, ERROR) > CALL_FAILED (every call timed out or lost its connection) > UNVERIFIED_RESPONSE (an answer
    that did not name its model) > DIGEST_CHANGED (the digest differed between calls) > DIGEST_RECORDED / NAME_VERIFIED. The digest is the one Ollama observed
    before each call; it is not proof of which weights produced each token."""
    ids = [i for i in (identities or []) if isinstance(i, dict)]
    base = {"requested": str(requested_name)[:200], "calls": len(ids)}
    if not ids:
        return {**base, "identity_status": "NOT_RESOLVED", "resolved": None, "executed_response_models": [],
                "note": "This run made no model call that recorded an identity (a stub, a replay, a tool-path launch, or no call reached the model client)."}
    failed = [i for i in ids if i.get("call_error")]            # sent, but no answer came back (timeout, connection error): no verdict on the answering model
    executed = [i.get("executed") for i in ids if isinstance(i.get("executed"), dict)]
    names = sorted({str(e["response_model"])[:200] for e in executed if e.get("response_model")})[:MAX_RESPONSE_MODELS]
    refusals = [str(i.get("status")) for i in ids if i.get("status") != EXACT]
    ok = [i for i in ids if i.get("status") == EXACT]
    digests = {i.get("digest") for i in ok if i.get("digest")}
    if any(e.get("name_matches_requested") is False for e in executed):
        status = "MISMATCH"
    elif refusals:
        status = refusals[0]
    elif failed and len(failed) == len(ids):
        status = "CALL_FAILED"
    elif any(e.get("name_matches_requested") is None for e in executed):
        status = "UNVERIFIED_RESPONSE"
    elif len(digests) > 1:
        status = "DIGEST_CHANGED"
    else:
        status = ok[0].get("identity_status") or "NAME_VERIFIED"
    first = ok[0] if ok else {}
    resolved = {k: first.get(k) for k in ("name", "digest", "size_bytes", "family", "parameter_size", "quantization", "ollama_version")} if ok else None
    return {**base, "identity_status": status, "resolved": resolved, "executed_response_models": names, "digest_observed_before_call": bool(ok)}
