"""Server-side search service for the Academy notebook, run inside the Attack Service.

The browser sends a template id and validated parameters for a run this service launched; the SPL is built here from the fixed templates in
`agentsec.loan_desk.search` and sent only through the strict-TLS REST client (`agentsec.splunk_client`) under the read-only policy (`agentsec.spl_policy`).
There is no docker backend, no host verifier and no free-form SPL on this path. When no search access is provisioned the service says so
(`unavailable`) and never reports an empty result as if a search had run.

Results are bounded (rows, columns, characters), kept in memory only, and addressed by an unguessable id that is tied to the run it was made for.
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from agentsec import splunk_client as sc
from agentsec.loan_desk import search as srch

log = logging.getLogger(__name__)

SEARCH_ID = re.compile(r"^[0-9a-f]{16}$")
PER_RUN_PER_MIN = 20
GLOBAL_PER_HOUR = 300
MAX_INFLIGHT = 8
MAX_KEPT = 400
WINDOW = "earliest=-24h (the run's last 24 hours)"          # every template in agentsec.loan_desk.search carries this bound


class SearchService:
    def __init__(self, *, env: dict | None = None, clock: Callable[[], float] = time.time, workers: int = 2,
                 backend_factory: Callable[[dict], "srch.Backend | None"] | None = None, evidence_class: str = "LIVE"):
        import os
        self._env = env if env is not None else os.environ
        self._clock = clock
        self._backend_factory = backend_factory or self._default_backend
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="academy-search")
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()
        self.evidence_class = evidence_class

    # ------------------------------------------------------------------ availability
    @staticmethod
    def _default_backend(env) -> "srch.Backend | None":
        try:
            client = sc.client_for_mode(dict(env))
        except sc.SplunkError:
            return None
        return None if client is None else srch.RestBackend(client)

    def backend(self) -> "srch.Backend | None":
        """Re-evaluated on every request: provisioning after start-up takes effect at once, and a revoked or removed credential fails closed at once."""
        return self._backend_factory(self._env)

    def available(self) -> bool:
        return self.backend() is not None

    # ------------------------------------------------------------------ catalog and preview
    def templates(self) -> list[dict]:
        return [t.public() for t in srch.TEMPLATES.values()]

    def preview(self, run_id: str, template: object, params: object, compare_run: object = None) -> tuple[str, dict]:
        """The exact SPL a template search would run. Nothing is executed. Ownership of the run is the caller's check."""
        try:
            spl, clean = srch.get_template(template).build(run_id, params, compare_run)
        except srch.SearchError as exc:
            return "BAD_REQUEST", {"detail": str(exc)}
        return "OK", {"template": template, "params": clean, "spl": spl, "evidence_class": self.evidence_class, "window": WINDOW,
                      **({"compare_run": compare_run} if compare_run else {})}

    # ------------------------------------------------------------------ execution
    def request(self, run_id: str, template: object, params: object, compare_run: object = None) -> tuple[str, dict]:
        """(code, info): REQUESTED | BAD_REQUEST | UNAVAILABLE | RATE_LIMITED."""
        code, info = self.preview(run_id, template, params, compare_run)
        if code != "OK":
            return code, info
        return self.submit(run_id, info)

    def submit(self, run_id: str, info: dict) -> tuple[str, dict]:
        """Queue an already-built, already-validated search (`info` carries template, params, spl and optionally window / compare_run). The SPL always comes
        from a fixed server-side template; this method never composes or accepts SPL from a browser."""
        backend = self.backend()
        if backend is None:
            return "UNAVAILABLE", {"reason": "search_access_not_provisioned"}
        now = self._clock()
        with self._lock:
            self._forget(now)
            recent = [j for j in self._jobs.values() if now - j["at"] < 3600]
            if len(recent) >= GLOBAL_PER_HOUR or sum(1 for j in self._jobs.values() if not j["future"].done()) >= MAX_INFLIGHT:
                return "RATE_LIMITED", {"retry_after_s": 60}
            if sum(1 for j in recent if j["run"] == run_id and now - j["at"] < 60) >= PER_RUN_PER_MIN:
                return "RATE_LIMITED", {"retry_after_s": 10}
            sid = secrets.token_hex(8)
            fut: Future = self._pool.submit(self._run, backend, info["spl"])
            self._jobs[sid] = {"run": run_id, "at": now, "future": fut, "info": info}
        return "REQUESTED", {**info, "search_id": sid}

    @staticmethod
    def _run(backend, spl: str) -> "srch.Outcome":
        try:
            return backend.run(spl, timeout_s=srch.SEARCH_TIMEOUT_S, max_rows=srch.MAX_ROWS)
        except Exception:                                   # a backend bug must read as a failure, never as an empty success
            log.warning("academy search backend raised")
            return srch.Outcome(False, error="search_failed")

    def _forget(self, now: float) -> None:
        if len(self._jobs) < MAX_KEPT:
            return
        for sid in sorted(self._jobs, key=lambda k: self._jobs[k]["at"])[: len(self._jobs) - MAX_KEPT + 1]:
            if self._jobs[sid]["future"].done():
                del self._jobs[sid]

    def result(self, run_id: str, search_id: str) -> dict | None:
        """None for an unknown id or an id made for another run. Otherwise the same document shape the notebook has always read."""
        if not SEARCH_ID.fullmatch(search_id):
            return None
        with self._lock:
            job = self._jobs.get(search_id)
        if job is None or job["run"] != run_id:
            return None
        info, fut = job["info"], job["future"]
        meta = {"template": info["template"], "params": info["params"], "spl": info["spl"], "backend": "rest", "evidence_class": self.evidence_class,
                "window": info.get("window", WINDOW), **({"compare_run_id": info["compare_run"]} if info.get("compare_run") else {})}
        if not fut.done():
            return {"status": "PENDING", **meta}
        out = fut.result()
        if not out.ok:
            return {"status": "UNAVAILABLE" if out.error == "backend_unavailable" else "FAILED", "ok": False, "error": out.error or "search_failed",
                    "duration_ms": out.duration_ms, **meta}
        return {"status": "READY", "ok": True, "columns": out.columns, "rows": out.rows, "row_count": len(out.rows), "truncated": out.truncated,
                "row_cap": srch.MAX_ROWS, "duration_ms": out.duration_ms, "checked_at": self._clock(), **meta}
