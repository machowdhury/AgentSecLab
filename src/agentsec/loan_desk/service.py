"""Run lifecycle for the Loan Desk: validate -> store -> background agent loop -> inspectable record."""

from __future__ import annotations

import dataclasses
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
                "model": {"name": self.model.name, "provider": "ollama", "proposal_source": self.model.source},
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
        out["evidence"] = {
            "run_id": run_id, "event_count": len(events), "source": "LIVE",
            "schema": "agentsec.loan_desk_event 1.0.0",
            "splunk_search": f'index=agentsec_telemetry sourcetype="otel:agentic:json" "agentsec.run.id"="{run_id}" | sort agentsec.sequence',
            "indexed_status": "NOT_VERIFIED",
            "note": "These are the events this process emitted. Indexing in Splunk is a separate fact; run the search to check.",
        }
        return out

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
