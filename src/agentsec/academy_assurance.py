"""Academy-native Security Assurance: the validated deterministic engine (`agentsec.assurance.engine`) behind a read-only JSON API.

Nothing here decides a status. The engine does, from observed events only. This module (1) loads events: LIVE and TEST_FIXTURE from Splunk through the strict-TLS
REST client with one fixed search, RECORDED from the committed replay packs (no Splunk); (2) keeps the three evidence classes apart: every view is for ONE class,
so recorded examples can never be read as the current posture; (3) applies a time window by run start; (4) shapes the engine's findings and its metrics into the
screens (tiles with numerator and denominator, a prioritized attention list, control tiles, gaps, retest outcomes) without adding a metric of its own.
A Splunk that cannot be searched is reported as `unavailable`; zero events as `empty`; neither is ever shown as a healthy zero.
"""
from __future__ import annotations

import csv
import io
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from agentsec import splunk_client as sc
from agentsec.assurance import engine as E

TABS = {"live": "LIVE", "recorded": "RECORDED", "fixtures": "TEST_FIXTURE"}
WINDOWS = {"24h": ("Last 24 hours", timedelta(hours=24)), "7d": ("Last 7 days", timedelta(days=7)), "all": ("All time", None)}
GRAIN = "one finding per guarded operation (run, hop, control); a run with no control decision gets one run-level finding"
MAX_EVENTS = 30000
MAX_BYTES = 24 * 1024 * 1024
MAX_EVENT_JSON = 6000
MAX_RAW_EVENTS = 120
FID = re.compile(r"F-[0-9a-f]{12}")
TITLES = {
    "R-DENY-BYPASSED": "A denied call still executed", "RR-RETEST-NOT-PREVENTED": "A defended retest executed with no denial",
    "R-FAILOPEN-EXECUTED": "The vulnerable profile let the call execute (by design)", "R-FAILOPEN-NOT-EXECUTED": "The vulnerable profile allowed a call that did not execute",
    "R-INCOMPLETE": "The run's evidence is incomplete", "RR-NO-DECISION": "A run finished with no control decision", "R-UNCLASSIFIED": "A decision could not be classified",
    "R-OBSERVE-ONLY": "A control observed without blocking", "R-ERROR": "A control reported an error", "R-DENY-HELD": "A control denied the call and nothing executed",
}


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(value) -> float | None:
    try:
        return E._secs(value) if isinstance(value, str) else None
    except ValueError:
        return None


def recorded_events(root: Path = E.ROOT) -> list[dict]:
    out: list[dict] = []
    for p in sorted((root / "learning" / "level_1").glob("*/specimens/*.jsonl")):
        out.extend(E.read_events(p))
    return out


class Dataset:
    """Everything the engine says about one batch of events, before the evidence class and the window are applied."""
    def __init__(self, events: list[dict], recorded_ids: frozenset[str], loaded_at: float, source: str):
        self.events, self.source, self.loaded_at = events, source, loaded_at
        self.runs = E.group_runs(events)
        self.findings = E.evaluate(events, recorded=recorded_ids)
        self.class_of = {rid: self._class(r, recorded_ids) for rid, r in self.runs.items()}
        self.by_id = {f["finding_id"]: f for f in self.findings}

    @staticmethod
    def _class(run: dict, recorded_ids: frozenset[str]) -> str:        # exactly the engine's rule (tested for parity)
        marker = next((x.get("agentsec.lab.id") for x in run["events"] if x.get("agentsec.lab.id")), None)
        return "TEST_FIXTURE" if marker == E.FIXTURE_MARKER else "RECORDED" if run["run_id"] in recorded_ids else "LIVE"

    def slice(self, evidence_class: str, since: float | None):
        """(events, findings, runs) of one class whose runs started at or after `since` (None: no window)."""
        keep = {rid for rid, run in self.runs.items() if self.class_of[rid] == evidence_class and (since is None or self._start(run) is None or self._start(run) >= since)}
        events = [e for rid in keep for e in self.runs[rid]["events"]]
        return events, [f for f in self.findings if f["run_id"] in keep], {rid: self.runs[rid] for rid in keep}

    @staticmethod
    def _start(run: dict) -> float | None:
        return _ts(run.get("start_ts")) or next((t for t in (_ts(e.get("timestamp")) for e in run["events"]) if t is not None), None)


class AssuranceService:
    def __init__(self, *, env: dict | None = None, client_factory: Callable[[dict], object | None] | None = None, clock: Callable[[], float] = time.time,
                 ttl_s: float = 10.0, recorded_root: Path = E.ROOT):
        import os
        self._env = env if env is not None else os.environ
        self._client_factory = client_factory or (lambda env: sc.client_for_mode(dict(env)))
        self._clock, self._ttl, self._root = clock, ttl_s, recorded_root
        self._cache: dict[str, Dataset] = {}
        self._lock = threading.Lock()
        self._controls = E.load_controls()

    @staticmethod
    def origin_lab(f: dict) -> str | None:
        """The workshop whose launch produced this attack id (the launch allowlist is the only authority); a control's own workshop list is only a tie-breaker."""
        from agentsec import launch_catalog as lc
        labs = sorted({r["lab_id"] for r in lc.allowlist_public_rows() if r["attack_id"] == f.get("attack_id")})
        if len(labs) == 1:
            return labs[0]
        pick = [x for x in labs if x in (f.get("workshops") or [])]
        return (pick or labs or [None])[0]

    # ------------------------------------------------------------------ loading
    def _splunk(self, window: str) -> tuple[Dataset | None, str | None]:
        """(dataset, None) or (None, reason). The reason is a fixed code."""
        with self._lock:
            hit = self._cache.get(window)
            if hit and self._clock() - hit.loaded_at < self._ttl:
                return hit, None
        try:
            client = self._client_factory(self._env)
        except sc.SplunkError:
            return None, "not_configured"
        if client is None:
            return None, "not_provisioned"
        span = WINDOWS[window][1]
        earliest = "0" if span is None else f"-{int(span.total_seconds() // 86400) + 1}d"       # one day of margin: a run that began just before the window still has all its events
        spl = f'index=agentsec_telemetry sourcetype="otel:agentic:json" "agentsec.schema.name"="agentsec.security_event" earliest={earliest} | head {MAX_EVENTS} | table _raw'
        try:
            text = client.export_csv(spl, timeout_s=40, max_bytes=MAX_BYTES)
        except sc.SplunkError as exc:
            return None, {"connectivity": "unreachable", "authentication": "access_denied", "authorization": "access_denied"}.get(exc.stage, exc.code if exc.code in ("timeout", "too_large") else "search_failed")
        events, seen = [], set()
        for row in csv.DictReader(io.StringIO(text)):
            raw = row.get("_raw") or ""
            if raw in seen or not raw:
                continue
            seen.add(raw)
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            if isinstance(e, dict):
                events.append(e)
        ds = Dataset(events, E.recorded_run_ids(self._root), self._clock(), "splunk")
        with self._lock:
            self._cache[window] = ds
        return ds, None

    def _recorded(self) -> Dataset:
        with self._lock:
            hit = self._cache.get("recorded")
        if hit:
            return hit
        ds = Dataset(recorded_events(self._root), E.recorded_run_ids(self._root), self._clock(), "committed")
        with self._lock:
            self._cache["recorded"] = ds
        return ds

    def _view(self, tab: str, window: str):
        """(dataset, since, meta) or (None, None, state dict)."""
        if tab == "recorded":
            return self._recorded(), None, None
        ds, reason = self._splunk(window)
        if ds is None:
            return None, None, {"state": "unavailable", "reason": reason}
        span = WINDOWS[window][1]
        return ds, None if span is None else self._clock() - span.total_seconds(), None

    # ------------------------------------------------------------------ overview
    def overview(self, tab: str, window: str) -> dict:
        evidence_class = TABS[tab]
        window = "all" if tab == "recorded" else window
        base = {"tab": tab, "evidence_class": evidence_class, "window": {"key": window, "label": "Committed examples (not time-filtered)" if tab == "recorded" else WINDOWS[window][0]}}
        ds, since, bad = self._view(tab, window)
        if ds is None:
            return {**base, **bad, "provenance": self._prov(None, tab, window, 0, 0, {}, self._clock(), None)}
        events, findings, runs = ds.slice(evidence_class, since)
        others = {c: sum(1 for rid in ds.runs if ds.class_of[rid] == c) for c in ("LIVE", "RECORDED", "TEST_FIXTURE") if c != evidence_class}
        prov = self._prov(ds, tab, window, len(events), len(runs), others, ds.loaded_at, since)
        if not runs:
            return {**base, "state": "empty", "reason": "no_runs_in_window", "provenance": prov}
        summ = E.summary(events, findings, self._controls)
        return {**base, "state": "ok", "provenance": prov, **self._shape(findings, summ, runs, tab)}

    @staticmethod
    def _headline(tab: str, n: int) -> str:
        """Recorded examples are teaching material, never a current incident queue, so they are 'to explore' and say nothing about an operation needing attention."""
        if tab == "recorded":
            return f"{n} finding{'s' if n != 1 else ''} to explore in these recorded examples" if n else "No findings to explore in the recorded examples"
        return (f"{n} finding{'s' if n != 1 else ''} need{'' if n != 1 else 's'} your attention" if n else "Nothing needs your attention in this window")

    def _prov(self, ds, tab, window, n_events, n_runs, others, loaded_at, since) -> dict:
        return {"source": "committed replay packs in this repository (not Splunk)" if tab == "recorded" else "Splunk index agentsec_telemetry",
                "events": n_events, "runs": n_runs, "grain": GRAIN, "computed_at": _iso(loaded_at), "window_start": _iso(since), "other_classes_not_counted": others,
                "evidence_rule": "LIVE = not recorded and not a fixture; RECORDED = committed replay specimen; TEST_FIXTURE = synthetic negative-test data. Classes are never mixed in one view."}

    def _shape(self, findings: list[dict], summ: dict, runs: dict, tab: str = "live") -> dict:
        card = lambda f: {"finding_id": f["finding_id"], "status": f["status"], "status_label": f["status_label"], "by_design": f["by_design"], "title": TITLES.get(f["rule_id"], f["status_label"]),
                          "context": f"{f['attack_id'] or 'no attack id'} · {f['control_id']} · run {f['run_id'][:8]}…" + (f" · hop {f['hop']}" if f["hop"] is not None else ""),
                          "run_id": f["run_id"], "mode": f["mode"], "profile": f["profile"], "rule_id": f["rule_id"], "retest": f["retest"]["outcome"], "control_id": f["control_id"],
                          "lab_id": self.origin_lab(f)}
        ineff = [f for f in findings if f["status"] == "VERIFIED_INEFFECTIVE" and not f["by_design"]]
        gaps = [f for f in findings if f["status"] == "INSUFFICIENT_EVIDENCE"]
        unvalidated = [f for f in findings if f["status"] == "VERIFIED_INEFFECTIVE" and f["by_design"] and f["mode"] == "ATTACK" and f["retest"]["outcome"] != "VALIDATED"]
        attention = [(0, f) for f in ineff] + [(1, f) for f in gaps] + [(2, f) for f in unvalidated]
        attention.sort(key=lambda pf: (pf[0], -(Dataset._start(runs[pf[1]["run_id"]]) or 0), pf[1]["finding_id"]))
        defended_ineff = len(ineff)
        by_design = summ["unauthorized_executed"]["by_design"]
        of_enf = summ["unauthorized_executed"]["of"]
        rt = summ["retest"]
        tiles = [
            {"id": "held", "label": "Held", "n": summ["blocked_verified"]["n"], "of": summ["blocked_verified"]["of_deny_decisions"], "definition": "DENY decisions with no execution in the same hop, in a complete run"},
            {"id": "did_not_hold", "label": "Did not hold", "n": defended_ineff, "of": of_enf, "definition": "findings where a control that should have stopped the call did not (not counting the vulnerable profile, which is by design)",
             "by_design": by_design, "of_definition": "findings that carry an enforcing decision (authorized calls that raise no finding are not counted)"},
            {"id": "retests", "label": "Retests validated", "n": rt["VALIDATED"], "of": rt["of"], "definition": "ineffective ATTACK findings followed by a linked, verified-effective RETEST (same attack, control and evidence class)",
             "not_validated": rt["NOT_VALIDATED"], "no_retest": rt["NO_RETEST"]},
        ]
        statuses = ("VERIFIED_EFFECTIVE", "VERIFIED_INEFFECTIVE", "FINDING_OBSERVED", "INSUFFICIENT_EVIDENCE")
        labels = {s: E.load_rules()["statuses"][s]["label"] for s in statuses}
        by_status = [{"status": s, "label": labels[s], "n": sum(1 for f in findings if f["status"] == s and not (s == "VERIFIED_INEFFECTIVE" and f["by_design"])), "by_design": False} for s in statuses]
        by_status.insert(2, {"status": "VERIFIED_INEFFECTIVE", "label": "Ineffective, by design (vulnerable profile)", "n": sum(1 for f in findings if f["status"] == "VERIFIED_INEFFECTIVE" and f["by_design"]), "by_design": True})
        controls = []
        for cid, c in sorted(self._controls.items()):
            fs = [f for f in findings if f["control_id"] == cid]
            controls.append({"id": cid, "name": c.get("name", cid), "class": c.get("class", ""), "tested": cid not in summ["untested_controls"]["ids"],
                             "counts": {s: sum(1 for f in fs if f["status"] == s) for s in statuses}, "findings": len(fs)})
        return {
            "headline": {"attention": len(attention), "text": self._headline(tab, len(attention))},
            "attention": [card(f) for _, f in attention[:3]], "attention_all": [{**card(f), "priority": p} for p, f in attention[:200]], "tiles": tiles,
            "disclosure": {"controls": {"tested": sum(1 for c in controls if c["tested"]), "of": len(controls), "items": controls}, "gaps": {"n": len(gaps), "items": [card(f) for f in gaps[:50]]},
                           "not_tested": {"n": summ["untested_controls"]["n"], "of": summ["untested_controls"]["of"], "ids": summ["untested_controls"]["ids"]},
                           "by_status": {"total": len(findings), "items": by_status},
                           "how": ["Statuses come from deterministic rules (learning/assurance/rules.json) applied to observed events only; no model decides anything.",
                                   "Every number is n of N with its definition. A count of zero operations is shown as 'no operations', never as a pass.",
                                   "Missing, late or out-of-order events produce Insufficient evidence, never a pass.", f"Grain: {GRAIN}.",
                                   "Retests link by attack id, control id and evidence class only; a recorded retest never validates a live attack.",
                                   "This is evidence of how a control behaved in this lab, not a compliance, certification or organization-wide statement."]},
        }

    # ------------------------------------------------------------------ finding
    def locate(self, tab: str, finding_id: str, window: str = "all"):
        """(dataset, finding, run, since) for a finding of exactly this evidence class; a dict {state: unavailable, reason} when Splunk cannot be read; None when unknown."""
        if not FID.fullmatch(finding_id):
            return None
        window = "all" if tab == "recorded" else window
        ds, since, bad = self._view(tab, window)
        if ds is None:
            return {"state": "unavailable", "reason": bad["reason"], "tab": tab}
        f = ds.by_id.get(finding_id)
        if f is None or ds.class_of.get(f["run_id"]) != TABS[tab]:
            return None
        return ds, f, ds.runs[f["run_id"]], since

    def finding(self, tab: str, finding_id: str, window: str = "all") -> dict | None:
        found = self.locate(tab, finding_id, window)
        if not isinstance(found, tuple):
            return found
        window = "all" if tab == "recorded" else window
        ds, f, run, since = found
        events, truncated = [], False
        for e in run["events"][:MAX_RAW_EVENTS]:
            text = json.dumps(e, sort_keys=True, indent=1)
            cut = len(text) > MAX_EVENT_JSON
            events.append({"sequence": e.get("agentsec.sequence"), "name": e.get("event.name"), "hop": e.get("agentsec.hop.index"), "json": text[:MAX_EVENT_JSON], "truncated": cut})
        truncated = len(run["events"]) > MAX_RAW_EVENTS
        seqs = [e["agentsec.sequence"] for e in run["events"] if isinstance(e.get("agentsec.sequence"), int)]
        gaps = sorted(set(range(1, (max(seqs) if seqs else 0) + 1)) - set(seqs))
        timeline = [{"sequence": e.get("agentsec.sequence"), "name": str(e.get("event.name", "")).replace("agentsec.", ""), "hop": e.get("agentsec.hop.index"),
                     "decision": e.get("agentsec.control.decision"), "executed": e.get("agentsec.operation.executed") in (True, "true", "True") or None,
                     "focus": e.get("agentsec.hop.index") == f["hop"] and f["hop"] is not None} for e in run["events"]]
        retest = next((x for x in ds.findings if x["run_id"] == f["retest"].get("run_id") and x["control_id"] == f["control_id"]), None) if f["retest"].get("run_id") else None
        keys = ("finding_id", "run_id", "hop", "control_id", "control_name", "control_class", "mode", "profile", "attack_id", "decision", "reason", "tool", "rule_id", "status", "status_label",
                "confidence", "by_design", "evidence_class", "boundary", "technique", "spl", "retest", "observation", "interpretation", "impact", "control_interpretation", "recommended_action",
                "retest_check", "executed_in_hop", "maestro_layers", "workshops")
        return {"state": "ok", "tab": tab, "finding": {k: f.get(k) for k in keys} | {"title": TITLES.get(f["rule_id"], f["status_label"])},
                "timeline": timeline, "missing_sequences": gaps, "run": {"complete": run["complete"], "terminal": run["terminal"], "contiguous": run["contiguous"], "events": run["n"], "duplicates": run["duplicates"]},
                "events": events, "events_truncated": truncated,
                "linked_retest": {"run_id": retest["run_id"], "status": retest["status"], "status_label": retest["status_label"], "finding_id": retest["finding_id"]} if retest else None,
                "workshop": {"lab_id": self.origin_lab(f), "run_id": f["run_id"], "mode": f["mode"], "adoptable": tab == "live"},
                "provenance": self._prov(ds, tab, window, run["n"], 1, {}, ds.loaded_at, since)}


def register_assurance(app, service: AssuranceService) -> None:
    """Read-only routes. Live and recorded views are for any authenticated learner (the gateway authenticates); the fixtures view lives under its own path so the gateway
    can require the operator role for it. Nothing here changes state, runs a search the browser describes, or accepts SPL."""
    from flask import jsonify, request
    from agentsec.academy_web import _no_store

    def window_arg(tab: str):
        w = request.args.get("window", "7d")
        if set(request.args) - {"window", "tab"} or w not in WINDOWS:
            return None
        return w

    def overview(tab: str):
        w = window_arg(tab)
        if w is None:
            return _no_store(jsonify({"error": "bad_request", "detail": "window must be 24h, 7d or all"})), 400
        return _no_store(jsonify(service.overview(tab, w))), 200

    def detail(tab: str, finding_id: str):
        w = window_arg(tab)
        if w is None or not FID.fullmatch(finding_id):
            return _no_store(jsonify({"error": "bad_request"})), 400
        res = service.finding(tab, finding_id, w)
        return (_no_store(jsonify(res)), 200) if res is not None else (_no_store(jsonify({"error": "unknown_finding"})), 404)

    @app.get("/api/assurance/overview")
    def assurance_overview():
        tab = request.args.get("tab", "live")
        if tab not in ("live", "recorded"):
            return _no_store(jsonify({"error": "bad_request", "detail": "tab must be live or recorded"})), 400
        return overview(tab)

    @app.get("/api/assurance/findings/<finding_id>")
    def assurance_finding(finding_id: str):
        tab = request.args.get("tab", "live")
        if tab not in ("live", "recorded"):
            return _no_store(jsonify({"error": "bad_request"})), 400
        return detail(tab, finding_id)

    @app.get("/api/assurance/fixtures/overview")
    def assurance_fixtures_overview():
        return overview("fixtures")

    @app.get("/api/assurance/fixtures/findings/<finding_id>")
    def assurance_fixtures_finding(finding_id: str):
        return detail("fixtures", finding_id)
