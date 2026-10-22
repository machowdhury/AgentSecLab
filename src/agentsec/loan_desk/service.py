"""Run lifecycle for the Loan Desk: validate -> store -> background agent loop -> inspectable record."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import threading
import time
from collections import OrderedDict

from agentsec.loan_desk.agent import MAX_STEPS, run_agent
from agentsec.loan_desk.data import ApplicationStore, validate_application
from agentsec.loan_desk.events import LoanDeskEmitter
from agentsec.loan_desk.model import ChatModel
from agentsec.loan_desk.tools import TOOLS
from agentsec.settings import Settings
from agentsec.timeline import build_timeline

MAX_RUNS = 200


class LoanDeskService:
    def __init__(self, *, settings: Settings, model: ChatModel, sink, store: ApplicationStore | None = None,
                 background: bool = True) -> None:
        self.settings, self.model, self.sink = settings, model, sink
        self.store = store or ApplicationStore()
        self.background = background
        self._runs: OrderedDict[str, dict] = OrderedDict()
        self._events: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    # -- public ---------------------------------------------------------------
    def submit(self, form: object) -> tuple[dict | None, dict[str, str]]:
        record, errors = validate_application(form)
        if errors:
            return None, errors
        app_id = self.store.add(record)
        if app_id is None:
            return None, {"_form": "The demo store is full. Restart the lab to clear it."}
        emitter = LoanDeskEmitter(sink=self.sink.emit, settings=dataclasses.replace(self.settings, ollama_model=self.model.name),
                                  model=self.model.name, user_id="applicant-web")
        run_id = str(emitter.run_id)
        view = {"run_id": run_id, "applicant_id": app_id, "status": "RUNNING", "stop_reason": None, "error": None,
                "application": {k: v for k, v in record.items()},
                "model": {"name": self.model.name, "provider": "ollama", "proposal_source": self.model.source,
                  "identity": self.model.identity() if hasattr(self.model, "identity") else {}},
                "bounds": {"max_steps": MAX_STEPS, "tools": sorted(TOOLS)},
                "steps": [], "final": None, "events": 0}
        steps = view["steps"]
        with self._lock:
            self._runs[run_id] = view
            while len(self._runs) > MAX_RUNS:
                old, _ = self._runs.popitem(last=False)
                self._events.pop(old, None)
            self._events[run_id] = emitter.events
        args = (run_id, app_id, record, emitter, steps)
        if self.background:
            threading.Thread(target=self._execute, args=args, daemon=True).start()
        else:
            self._execute(*args)
        return self.view(run_id), {}

    def view(self, run_id: str) -> dict | None:
        with self._lock:
            base = self._runs.get(run_id)
            if base is None:
                return None
            events = list(self._events.get(run_id, []))
            out = dict(base)
            out["steps"] = [dict(s) for s in base["steps"]]
        out["events"] = len(events)
        out["timeline"] = build_timeline(events, run_id=run_id, source="LIVE")
        splunk = self._splunk_status(run_id, len(events))
        out["evidence"] = {
            "run_id": run_id, "event_count": len(events), "source": "LIVE",
            "schema": "agentsec.loan_desk_event 1.0.0",
            "splunk_search": f'index=agentsec_telemetry sourcetype="otel:agentic:json" "agentsec.run.id"="{run_id}" | sort agentsec.sequence',
            "indexed_status": splunk["status"], "splunk": splunk,
            "host_check": f"python scripts/loan_desk_verify.py {run_id} --record artifacts/loan_desk",
            "note": "LOCAL evidence = events AcmeBank emitted. SPLUNK-VERIFIED needs a host-side reconciliation record; "
                    "this page cannot reach Splunk and never assumes indexing.",
        }
        return out

    def _splunk_status(self, run_id: str, local_count: int) -> dict:
        """Read the host-written reconciliation record, if any. Only runs this process created are looked up."""
        path = Path(self.settings.artifacts_dir) / "loan_desk" / f"{run_id}.splunk.json"
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"status": "NOT_VERIFIED"}
        ok = (isinstance(rec, dict) and rec.get("run_id") == run_id and isinstance(rec.get("reconciled"), bool)
              and isinstance(rec.get("local_events"), int) and isinstance(rec.get("indexed_events"), int))
        if not ok:
            return {"status": "NOT_VERIFIED", "detail": "unreadable reconciliation record ignored"}
        base = {"indexed_events": rec["indexed_events"], "local_events": rec["local_events"],
                "checked_at": rec.get("checked_at"), "problems": rec.get("problems", [])}
        if rec["local_events"] != local_count:
            return {**base, "status": "STALE", "detail": "the run has more or fewer events than when it was checked"}
        return {**base, "status": "SPLUNK_VERIFIED" if rec["reconciled"] else "SPLUNK_MISMATCH"}

    def events_ndjson(self, run_id: str) -> str | None:
        import json
        with self._lock:
            ev = self._events.get(run_id)
            return None if ev is None else "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in ev)

    # -- worker ---------------------------------------------------------------
    def _execute(self, run_id: str, app_id: str, record: dict, emitter: LoanDeskEmitter, steps: list) -> None:
        t0 = time.monotonic()
        try:
            emitter.run_started()
            result = run_agent(app_id=app_id, record=record, model=self.model, store=self.store, emitter=emitter, steps=steps)
            ms = int((time.monotonic() - t0) * 1000)
            if result.stop_reason in ("final_answer", "step_budget_exhausted", "timeout"):
                emitter.run_completed(outcome="completed_denied" if result.denied else "completed_allowed", duration_ms=ms,
                                      stop_reason=result.stop_reason, executed=result.executed, denied=result.denied)
                status = "COMPLETED" if result.stop_reason == "final_answer" else "INCOMPLETE"
            else:
                emitter.run_failed(error_type=result.stop_reason, message=result.error or result.stop_reason,
                                   stop_reason=result.stop_reason)
                status = "FAILED"
            patch = {"status": status, "stop_reason": result.stop_reason, "error": result.error,
                     "final": result.final, "duration_ms": ms,
                     "counts": {"executed": result.executed, "denied": result.denied}}
        except Exception as exc:  # never leave a run stuck in RUNNING
            patch = {"status": "FAILED", "stop_reason": "internal_error", "error": f"{type(exc).__name__}: {exc}"}
        try:
            flush = getattr(self.sink, "force_flush", None)
            if callable(flush):
                flush(5000)
        except Exception:
            pass
        with self._lock:
            self._runs[run_id].update(patch)
