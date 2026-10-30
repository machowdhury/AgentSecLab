"""Investigation notebook for an assurance finding, and the retest comparison, behind the same read-only boundary as `academy_assurance`.

A finding opens a notebook whose cells are FIXED server-side templates. The browser names a finding id, a cell id and at most two validated parameters; the run id,
control id, hop and evidence class always come from the finding the server found, never from the request. For LIVE evidence a cell is a Splunk search run through the
Attack Service's own strict-TLS REST client (`SearchService.submit`); the exact SPL is returned for display and copying. RECORDED examples and TEST_FIXTURE data are not
in Splunk's live index for this lab, so their cells read the committed or synthetic events in memory: the result says `source: "local"`, carries no SPL, and states
that no search ran. The retest comparison is built only from the engine's own linked runs; it reports what each run observed per hop and repeats the engine's outcome,
and it computes no score and no effectiveness of its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from agentsec.academy_assurance import FID, TABS, AssuranceService
from agentsec.academy_search import SearchService

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CONTROL = re.compile(r"CTRL-[A-Z0-9-]{1,60}")
CELL_ID = re.compile(r"[a-z_]{1,40}")
MAX_ROWS, MAX_CELL = 50, 400
BASE = 'index=agentsec_telemetry sourcetype="otel:agentic:json" "agentsec.schema.name"="agentsec.security_event" earliest=0 "agentsec.run.id"="{run}"'
WINDOW_TEXT = "all time, limited to this one run id"
_V = lambda f: f"mvindex(mvdedup('{f}'),0)"      # Splunk keeps duplicate multivalue copies of every field; one value per event keeps counts honest
EVENT_COLS = ("seq", "event", "hop", "decision", "executed")
DECISION_COLS = ("seq", "hop", "control", "decision", "reason", "tool", "executed")
EXEC_COLS = ("hop", "decision", "handlers_started", "executed")


def _truthy(v) -> bool:
    return v is True or str(v).lower() == "true"


def _short(v) -> str:
    if isinstance(v, bool):                       # Splunk shows a JSON boolean as true / false; the in-memory twin of a cell says the same so the two can be compared
        return "true" if v else "false"
    return "" if v is None else str(v)[:MAX_CELL]


@dataclass(frozen=True)
class Ctx:
    run: str
    hop: int | None
    control: str | None          # None when the finding is about the whole run


@dataclass(frozen=True)
class Cell:
    id: str
    title: str
    question: str
    proves: str
    not_proves: str
    hint: str
    scoped: bool                 # True: honours the hop scope; control cells also honour the control scope
    control_scoped: bool
    columns: tuple[str, ...]
    spl: Callable[[Ctx, dict], str]
    local: Callable[[list[dict], Ctx, dict], list[list[str]]]

    def params(self, ctx: Ctx) -> list[dict]:
        out = [{"name": "limit", "kind": "int", "default": 20, "label": "Rows", "lo": 1, "hi": MAX_ROWS}]
        if self.scoped and ctx.hop is not None:
            out.insert(0, {"name": "scope", "kind": "enum", "default": "hop", "label": "Which part of the run", "choices": ["hop", "run"],
                           "choice_labels": {"hop": f"Only hop {ctx.hop} (the hop of this finding)", "run": "The whole run"}})
        if self.control_scoped and ctx.control:
            out.insert(0, {"name": "control", "kind": "enum", "default": "this", "label": "Which controls", "choices": ["this", "all"],
                           "choice_labels": {"this": f"Only {ctx.control} (the control of this finding)", "all": "Every control that decided"}})
        return out

    def clean(self, ctx: Ctx, raw: object) -> dict:
        raw = {} if raw is None else raw
        specs = {p["name"]: p for p in self.params(ctx)}
        if not isinstance(raw, dict) or set(raw) - set(specs):
            raise ValueError("Unknown parameter.")
        out = {}
        for name, p in specs.items():
            v = raw.get(name, p["default"])
            if p["kind"] == "int":
                if isinstance(v, bool) or not isinstance(v, int) or not p["lo"] <= v <= p["hi"]:
                    raise ValueError(f"{p['label']} must be a whole number from {p['lo']} to {p['hi']}.")
            elif v not in p["choices"]:
                raise ValueError(f"{p['label']} must be one of: {', '.join(p['choices'])}.")
            out[name] = v
        return out


# ----------------------------------------------------------------------------- SPL (built from validated values only)
def _hop_filter(ctx: Ctx, p: dict) -> str:
    return f" | where tonumber(hop)={ctx.hop}" if ctx.hop is not None and p.get("scope", "hop") == "hop" else ""


def _control_filter(ctx: Ctx, p: dict) -> str:
    return f' | where control="{ctx.control}"' if ctx.control and p.get("control", "this") == "this" else ""


def _spl_events(ctx: Ctx, p: dict) -> str:
    return " ".join((BASE.format(run=ctx.run) + f" | eval seq={_V('agentsec.sequence')}, event={_V('event.name')}, hop={_V('agentsec.hop.index')}, "
                     f"decision={_V('agentsec.control.decision')}, executed={_V('agentsec.operation.executed')}" + _hop_filter(ctx, p)
                     + f" | table {' '.join(EVENT_COLS)} | sort 0 num(seq) | head {p['limit']}").split())


def _spl_decisions(ctx: Ctx, p: dict) -> str:
    return " ".join((BASE.format(run=ctx.run) + f' event.name="agentsec.control.decision" | eval seq={_V("agentsec.sequence")}, hop={_V("agentsec.hop.index")}, '
                     f"control={_V('agentsec.control.id')}, decision={_V('agentsec.control.decision')}, reason={_V('agentsec.control.reason')}, "
                     f"tool={_V('gen_ai.tool.name')}, executed={_V('agentsec.operation.executed')}" + _hop_filter(ctx, p) + _control_filter(ctx, p)
                     + f" | table {' '.join(DECISION_COLS)} | sort 0 num(seq) | head {p['limit']}").split())


def _spl_execution(ctx: Ctx, p: dict) -> str:
    return " ".join((BASE.format(run=ctx.run) + f" | eval ev={_V('event.name')}, hop={_V('agentsec.hop.index')}, ex={_V('agentsec.operation.executed')}" + _hop_filter(ctx, p)
                     + ' | stats values(eval(if(ev="agentsec.control.decision", ' + _V("agentsec.control.decision") + ', null()))) AS decision '
                     'count(eval(ev="agentsec.mcp.started")) AS handlers_started count(eval(ev="agentsec.mcp.started" AND lower(ex)="true")) AS executed by hop '
                     f"| sort 0 num(hop) | head {p['limit']}").split())


# ----------------------------------------------------------------------------- the same tables over events held in memory (recorded, fixtures)
def _in_scope(e: dict, ctx: Ctx, p: dict) -> bool:
    return ctx.hop is None or p.get("scope", "hop") == "run" or e.get("agentsec.hop.index") == ctx.hop


def _local_events(events, ctx, p):
    rows = [[_short(e.get("agentsec.sequence")), _short(e.get("event.name")), _short(e.get("agentsec.hop.index")), _short(e.get("agentsec.control.decision")),
             _short(e.get("agentsec.operation.executed"))] for e in events if _in_scope(e, ctx, p)]
    return sorted(rows, key=lambda r: (int(r[0]) if r[0].lstrip("-").isdigit() else 1 << 30))[: p["limit"]]


def _local_decisions(events, ctx, p):
    rows = [[_short(e.get("agentsec.sequence")), _short(e.get("agentsec.hop.index")), _short(e.get("agentsec.control.id")), _short(e.get("agentsec.control.decision")),
             _short(e.get("agentsec.control.reason")), _short(e.get("gen_ai.tool.name")), _short(e.get("agentsec.operation.executed"))]
            for e in events if e.get("event.name") == "agentsec.control.decision" and _in_scope(e, ctx, p)
            and (not ctx.control or p.get("control", "this") == "all" or e.get("agentsec.control.id") == ctx.control)]
    return sorted(rows, key=lambda r: (int(r[0]) if r[0].lstrip("-").isdigit() else 1 << 30))[: p["limit"]]


def _local_execution(events, ctx, p):
    hops: dict = {}
    for e in events:
        if not _in_scope(e, ctx, p) or e.get("agentsec.hop.index") is None:      # Splunk's `stats ... by hop` leaves out events that carry no hop number (run start and end), so the twin does too
            continue
        h = hops.setdefault(e.get("agentsec.hop.index"), {"decision": set(), "started": 0, "executed": 0})
        if e.get("event.name") == "agentsec.control.decision" and e.get("agentsec.control.decision"):
            h["decision"].add(str(e["agentsec.control.decision"]))
        if e.get("event.name") == "agentsec.mcp.started":
            h["started"] += 1
            h["executed"] += _truthy(e.get("agentsec.operation.executed"))
    key = lambda k: (k is None, k if isinstance(k, int) else 0)
    return [[_short(k), ", ".join(sorted(v["decision"])), str(v["started"]), str(v["executed"])] for k, v in sorted(hops.items(), key=lambda kv: key(kv[0]))][: p["limit"]]


CELLS: dict[str, Cell] = {c.id: c for c in (
    Cell("run_events", "What did this run record?",
         "Read the run's events in order. Which events belong to the part of the run this finding is about?",
         "These events were recorded for this run id, in this order, with the decision and execution flags they carried.",
         "That the events are true, that nothing is missing (the finding page lists missing sequence numbers), or that the run was verified.",
         "Follow the sequence column. A hop starts, a control decides, a handler may start, the hop completes.", True, False, EVENT_COLS, _spl_events, _local_events),
    Cell("control_decisions", "What did the control decide?",
         "Find the control decisions for this finding. What was decided, on what grounds, and did the operation execute?",
         "The control's recorded decision, reason and execution flag for each guarded call.",
         "That the decision was right. A control can decide wrongly and a recorded decision is still only a record.",
         "Look at the decision and reason, then at the executed column: a DENY should not be followed by execution.", True, True, DECISION_COLS, _spl_decisions, _local_decisions),
    Cell("execution_check", "Did a handler start after a decision?",
         "For each hop: how many handlers started, and how many of them executed, next to what the control decided?",
         "How many handlers began and executed in each hop, beside the decisions recorded in the same hop.",
         "That a handler that started finished correctly, or that its output was harmless. Handler starts are counted per hop, not per call.",
         "A DENY with handlers_started above 0 is what the rules call a bypass; ALLOW with handlers_started 0 is a different finding.", True, False, EXEC_COLS, _spl_execution, _local_execution),
)}


class InvestigationService:
    def __init__(self, assurance: AssuranceService, search: SearchService | None):
        self._a, self._s = assurance, search

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _ctx(f: dict) -> Ctx | None:
        if not UUID.fullmatch(str(f.get("run_id", ""))):
            return None
        hop = f.get("hop")
        cid = f.get("control_id")
        return Ctx(f["run_id"], hop if isinstance(hop, int) and not isinstance(hop, bool) and 0 <= hop < 1000 else None, cid if isinstance(cid, str) and CONTROL.fullmatch(cid) else None)

    def _found(self, tab: str, fid: str, window: str):
        """(ds, finding, run, ctx) | a dict to return | None for unknown. Never builds anything from a request value but the finding id."""
        found = self._a.locate(tab, fid, window)
        if not isinstance(found, tuple):
            return found
        ds, f, run, _since = found
        ctx = self._ctx(f)
        return None if ctx is None else (ds, f, run, ctx)

    # ------------------------------------------------------------------ the findings of one live run (the workshop's Investigate and Explain stages)
    def run_findings(self, run_id: str, window: str = "all") -> dict:
        """The assurance findings the rules produced for ONE live run, so a workshop can open its notebook on the learner's own run. `found: false` means Splunk holds no
        scored event for the run (yet): not a pass, and not a failure."""
        if not UUID.fullmatch(run_id or ""):
            return {"state": "bad_request"}
        ds, _since, bad = self._a._view("live", window)
        if ds is None:
            return {"state": "unavailable", "reason": bad["reason"]}
        run = ds.runs.get(run_id)
        if run is None or ds.class_of.get(run_id) != "LIVE":
            return {"state": "ok", "found": False, "run_id": run_id, "findings": []}
        from agentsec.academy_assurance import TITLES
        fs = sorted((f for f in ds.findings if f["run_id"] == run_id), key=lambda f: (f["hop"] is None, f["hop"] if isinstance(f["hop"], int) else 0, f["control_id"]))
        return {"state": "ok", "found": True, "run_id": run_id, "run": {"complete": run["complete"], "terminal": run["terminal"], "events": run["n"]},
                "findings": [{"finding_id": f["finding_id"], "title": TITLES.get(f["rule_id"], f["status_label"]), "status": f["status"], "status_label": f["status_label"], "by_design": f["by_design"],
                              "hop": f["hop"], "control_id": f["control_id"], "mode": f["mode"], "retest": f["retest"]["outcome"]} for f in fs][:50]}

    # ------------------------------------------------------------------ context
    def context(self, tab: str, fid: str, window: str) -> dict | None:
        found = self._found(tab, fid, window)
        if not isinstance(found, tuple):
            return found
        ds, f, run, ctx = found
        live = tab == "live"
        search_ready = bool(live and self._s is not None and self._s.available())
        cells = []
        for c in CELLS.values():
            params = c.params(ctx)
            defaults = c.clean(ctx, None)
            cells.append({"id": c.id, "title": c.title, "question": c.question, "proves": c.proves, "not_proves": c.not_proves, "hint": c.hint, "params": params, "columns": list(c.columns),
                          "spl": c.spl(ctx, defaults) if live else None})
        title = self._a_title(f)
        return {"state": "ok", "tab": tab, "mode": "splunk" if live else "local", "search_ready": search_ready,
                "source": "Splunk, searched by the Attack Service for this run only" if live else
                "committed recorded examples held in memory (no Splunk search runs for these)" if tab == "recorded" else "synthetic test-fixture events held in memory (no Splunk search runs for these)",
                "origin": {"finding_id": f["finding_id"], "title": title, "run_id": ctx.run, "control_id": f["control_id"], "hop": f["hop"], "evidence_class": f["evidence_class"],
                          "attack_id": f["attack_id"], "mode": f["mode"], "profile": f["profile"], "status": f["status"], "status_label": f["status_label"],
                          "lab_id": self._a.origin_lab(f), "adoptable": live},
                "window": WINDOW_TEXT if live else "every event of this run",
                "next": {"defend": f["recommended_action"], "retest": f["retest_check"] or None, "retest_outcome": f["retest"]["outcome"] if f["mode"] == "ATTACK" else None},
                "cells": cells}

    @staticmethod
    def _a_title(f: dict) -> str:
        from agentsec.academy_assurance import TITLES
        return TITLES.get(f["rule_id"], f["status_label"])

    # ------------------------------------------------------------------ cells
    def _cell(self, cell_id: object):
        return CELLS.get(cell_id) if isinstance(cell_id, str) and CELL_ID.fullmatch(cell_id) else None

    def preview(self, tab: str, fid: str, window: str, cell_id: object, params: object) -> tuple[str, dict]:
        found = self._found(tab, fid, window)
        cell = self._cell(cell_id)
        if not isinstance(found, tuple) or cell is None:
            return ("UNKNOWN", {}) if not isinstance(found, dict) else ("UNAVAILABLE", found)
        _ds, f, _run, ctx = found
        try:
            clean = cell.clean(ctx, params)
        except ValueError as exc:
            return "BAD_REQUEST", {"detail": str(exc)}
        return "OK", {"template": f"investigation.{cell.id}", "params": clean, "spl": cell.spl(ctx, clean), "evidence_class": f["evidence_class"], "window": WINDOW_TEXT, "run": ctx.run,
                      "columns": list(cell.columns)}

    def run_live(self, fid: str, window: str, cell_id: object, params: object) -> tuple[str, dict]:
        """Queue one fixed-template Splunk search for a LIVE finding. (code, info): REQUESTED | BAD_REQUEST | UNKNOWN | UNAVAILABLE | RATE_LIMITED."""
        code, info = self.preview("live", fid, window, cell_id, params)
        if code == "UNAVAILABLE":
            return "UNAVAILABLE", {"reason": info.get("reason", "unavailable")}
        if code != "OK":
            return code, info
        if self._s is None:
            return "UNAVAILABLE", {"reason": "not_provisioned"}
        code, out = self._s.submit(info["run"], info)
        return (code, out) if code != "UNAVAILABLE" else ("UNAVAILABLE", {"reason": "not_provisioned"})

    def live_result(self, fid: str, window: str, search_id: str) -> dict | None:
        found = self._found("live", fid, window)
        if not isinstance(found, tuple) or self._s is None:
            return None
        res = self._s.result(found[3].run, search_id)
        return None if res is None else {**res, "finding_id": fid}

    def run_local(self, tab: str, fid: str, window: str, cell_id: object, params: object) -> tuple[str, dict]:
        if tab == "live":
            return "BAD_REQUEST", {"detail": "A live cell runs as a Splunk search."}
        found = self._found(tab, fid, window)
        cell = self._cell(cell_id)
        if not isinstance(found, tuple) or cell is None:
            return ("UNKNOWN", {}) if not isinstance(found, dict) else ("UNAVAILABLE", found)
        _ds, f, run, ctx = found
        try:
            clean = cell.clean(ctx, params)
        except ValueError as exc:
            return "BAD_REQUEST", {"detail": str(exc)}
        rows = cell.local(run["events"], ctx, clean)
        return "OK", {"status": "READY", "ok": True, "source": "local", "columns": list(cell.columns), "rows": rows, "row_count": len(rows), "truncated": False, "row_cap": MAX_ROWS,
                      "params": clean, "evidence_class": f["evidence_class"], "spl": None, "window": "every event of this run",
                      "note": "Computed from events held in memory. No Splunk search ran, so there is no SPL."}

    # ------------------------------------------------------------------ retest comparison
    def comparison(self, tab: str, fid: str, window: str) -> dict | None:
        found = self._found(tab, fid, window)
        if not isinstance(found, tuple):
            return found
        ds, f, run, ctx = found
        base = {"state": "ok", "tab": tab, "evidence_class": f["evidence_class"], "finding_id": f["finding_id"]}
        pair = self._pair(ds, f)
        if pair is None:
            what = {"RETEST": "This finding is from a retest run, but no attack finding in this view links to it (same attack id, control and evidence class).",
                    "BASELINE": "This is a baseline run. A retest compares an attack run with the same attack run under the defended profile."}.get(f["mode"], "")
            return {**base, "kind": "none", "reason": "not_applicable" if f["mode"] != "RETEST" else "no_linked_attack", "message": what or "This finding has no comparison."}
        att, ret, candidates = pair
        if ret is None:
            return {**base, "kind": "no_retest", "attack": self._side(att, None), "message":
                    "No retest has been run for this attack, control and evidence class" + (" in this view" if tab != "live" else "") + ". "
                    + ("A recorded retest never validates a live attack, so recorded runs do not appear here. " if tab == "live" else "")
                    + "Nothing is compared and no effectiveness is claimed.", "outcome": att["retest"]["outcome"]}
        a_run, r_run = ds.runs[att["run_id"]], ds.runs[ret["run_id"]]
        rows = self._rows(a_run["events"], r_run["events"], att["control_id"])
        incomplete = [s for s, r in (("attack", a_run), ("retest", r_run)) if not r["complete"]]
        notes = []
        if len(candidates) > 1:
            notes.append(f"{len(candidates)} retest runs exist for this attack and control. The rules link the one with the lowest run id; the others are not compared here.")
        if incomplete:
            notes.append("The " + " and ".join(incomplete) + " run's evidence is incomplete, so the engine reports insufficient evidence and the rows below are what was recorded, not a comparison you can rely on.")
        return {**base, "kind": "linked", "outcome": att["retest"]["outcome"], "comparable": not incomplete, "control_id": att["control_id"],
                "attack": self._side(att, a_run), "retest": self._side(ret, r_run), "rows": rows, "notes": notes, "candidates": len(candidates),
                "how": ["The outcome is the engine's: a retest validates an attack only when the linked retest finding is verified effective.",
                        "Linking uses attack id, control id and evidence class only. Timestamps and order are never used.",
                        "The table shows what each run recorded for this control per hop. It is evidence to read, not a score."]}

    @staticmethod
    def _pair(ds, f: dict):
        """(attack finding, linked retest finding or None, all linked candidates) for an ATTACK finding, or the pair that links to a RETEST finding."""
        if f["mode"] == "ATTACK":
            att = f
        elif f["mode"] == "RETEST":
            att = next((a for a in ds.findings if a["mode"] == "ATTACK" and a["control_id"] == f["control_id"] and a["retest"].get("run_id") == f["run_id"]
                        and a["evidence_class"] == f["evidence_class"]), None)
            if att is None:
                return None
        else:
            return None
        cands = [x for x in ds.findings if x["mode"] == "RETEST" and x["attack_id"] == att["attack_id"] and x["control_id"] == att["control_id"] and x["evidence_class"] == att["evidence_class"]] if att["attack_id"] else []
        rid = att["retest"].get("run_id")
        ret = next((x for x in cands if x["run_id"] == rid and x["control_id"] == att["control_id"]), None) if rid else None
        return att, ret, cands

    @staticmethod
    def _side(f: dict, run: dict | None) -> dict:
        return {"finding_id": f["finding_id"], "run_id": f["run_id"], "mode": f["mode"], "profile": f["profile"], "status": f["status"], "status_label": f["status_label"], "by_design": f["by_design"],
                "hop": f["hop"], "complete": None if run is None else run["complete"], "events": None if run is None else run["n"]}

    @staticmethod
    def _rows(a_events: list[dict], r_events: list[dict], control: str) -> list[dict]:
        def per_hop(events):
            out: dict = {}
            for e in events:
                hop = e.get("agentsec.hop.index")
                if hop is None:
                    continue
                s = out.setdefault(hop, {"decision": None, "reason": None, "handler_started": False, "executed": False})
                if e.get("event.name") == "agentsec.control.decision" and e.get("agentsec.control.id") == control:
                    s["decision"], s["reason"] = e.get("agentsec.control.decision"), e.get("agentsec.control.reason")
                if e.get("event.name") == "agentsec.mcp.started":
                    s["handler_started"] = True
                    s["executed"] = s["executed"] or _truthy(e.get("agentsec.operation.executed"))
            return {h: s for h, s in out.items() if s["decision"] is not None}
        a, r = per_hop(a_events), per_hop(r_events)
        side = lambda s: None if s is None else {"decision": _short(s["decision"]), "reason": _short(s["reason"]), "handler_started": s["handler_started"], "executed": s["executed"]}
        return [{"hop": h, "attack": side(a.get(h)), "retest": side(r.get(h))} for h in sorted(set(a) | set(r))]


def register_investigation(app, service: InvestigationService) -> None:
    """GET routes for reading (read tier; the fixtures copy under its own path for the operator role), plus the two routes that start and read a LIVE Splunk search
    (attack tier at the gateway, because they spend the search budget). No route accepts SPL, a run id, a control id or a hop from the browser."""
    from flask import jsonify, request
    from agentsec.academy_assurance import WINDOWS
    from agentsec.academy_web import _no_store

    def window(tab: str):
        w = request.args.get("window", "7d")
        return w if w in WINDOWS and not (set(request.args) - {"window", "tab", "limit", "scope", "control"}) else None

    def body():
        raw = request.get_json(silent=True, force=True) if request.get_data(cache=True) else {}
        return raw if isinstance(raw, dict) else None

    def reply(obj, code=200):
        return _no_store(jsonify(obj)), code

    def ctx_route(tab: str, fid: str):
        w = window(tab)
        if w is None or not FID.fullmatch(fid) or tab not in TABS:
            return reply({"error": "bad_request"}, 400)
        res = service.context(tab, fid, w)
        return reply(res if res is not None else {"error": "unknown_finding"}, 200 if res is not None else 404)

    def cmp_route(tab: str, fid: str):
        w = window(tab)
        if w is None or not FID.fullmatch(fid) or tab not in TABS:
            return reply({"error": "bad_request"}, 400)
        res = service.comparison(tab, fid, w)
        return reply(res if res is not None else {"error": "unknown_finding"}, 200 if res is not None else 404)

    def explore_route(tab: str, fid: str, cell: str):
        w = window(tab)
        if w is None or not FID.fullmatch(fid) or tab not in ("recorded", "fixtures"):
            return reply({"error": "bad_request"}, 400)
        params = {}
        for k in ("limit",):
            if k in request.args:
                try:
                    params[k] = int(request.args[k])
                except ValueError:
                    return reply({"error": "bad_request", "detail": "limit must be a whole number"}, 400)
        for k in ("scope", "control"):
            if k in request.args:
                params[k] = request.args[k]
        code, info = service.run_local(tab, fid, w, cell, params)
        if code == "OK":
            return reply(info)
        return reply({"error": {"UNKNOWN": "unknown_finding", "BAD_REQUEST": "bad_request", "UNAVAILABLE": "unavailable"}[code], **({"detail": info["detail"]} if "detail" in info else {})},
                     {"UNKNOWN": 404, "BAD_REQUEST": 400, "UNAVAILABLE": 503}[code])

    @app.get("/api/assurance/runs/<run_id>/findings")
    def inv_run_findings(run_id: str):
        if set(request.args) - {"window"} or not UUID.fullmatch(run_id):
            return reply({"error": "bad_request"}, 400)
        return reply(service.run_findings(run_id, "all"))

    @app.get("/api/assurance/findings/<finding_id>/investigation")
    def inv_context(finding_id: str):
        tab = request.args.get("tab", "live")
        return ctx_route(tab, finding_id) if tab in ("live", "recorded") else reply({"error": "bad_request"}, 400)

    @app.get("/api/assurance/findings/<finding_id>/comparison")
    def inv_comparison(finding_id: str):
        tab = request.args.get("tab", "live")
        return cmp_route(tab, finding_id) if tab in ("live", "recorded") else reply({"error": "bad_request"}, 400)

    @app.get("/api/assurance/findings/<finding_id>/explore/<cell_id>")
    def inv_explore(finding_id: str, cell_id: str):
        tab = request.args.get("tab", "")
        return explore_route(tab, finding_id, cell_id) if tab == "recorded" else reply({"error": "bad_request", "detail": "tab must be recorded"}, 400)

    @app.post("/api/assurance/findings/<finding_id>/cells/<cell_id>")
    def inv_run(finding_id: str, cell_id: str):
        data = body()
        w = request.args.get("window", "7d")
        if data is None or w not in WINDOWS or not FID.fullmatch(finding_id) or set(request.args) - {"window"} or set(data) - {"params"}:
            return reply({"error": "bad_request"}, 400)
        code, info = service.run_live(finding_id, w, cell_id, data.get("params"))
        if code == "REQUESTED":
            return reply({"search_id": info["search_id"], "spl": info["spl"], "params": info["params"], "evidence_class": info["evidence_class"], "window": info["window"]}, 202)
        if code == "UNKNOWN":
            return reply({"error": "unknown_finding"}, 404)
        if code == "BAD_REQUEST":
            return reply({"error": "bad_request", "detail": info.get("detail", "")}, 400)
        if code == "RATE_LIMITED":
            return reply({"error": "rate_limited", **info}, 429)
        return reply({"error": "search_unavailable", "reason": info.get("reason", "unavailable")}, 503)

    @app.get("/api/assurance/findings/<finding_id>/searches/<search_id>")
    def inv_result(finding_id: str, search_id: str):
        w = request.args.get("window", "7d")
        if w not in WINDOWS or not FID.fullmatch(finding_id) or set(request.args) - {"window"}:
            return reply({"error": "bad_request"}, 400)
        res = service.live_result(finding_id, w, search_id)
        return reply(res if res else {"error": "unknown_search"}, 200 if res else 404)

    # the fixtures copy: synthetic data, operator only at the gateway, local cells only
    @app.get("/api/assurance/fixtures/findings/<finding_id>/investigation")
    def inv_fx_context(finding_id: str):
        return ctx_route("fixtures", finding_id)

    @app.get("/api/assurance/fixtures/findings/<finding_id>/comparison")
    def inv_fx_comparison(finding_id: str):
        return cmp_route("fixtures", finding_id)

    @app.get("/api/assurance/fixtures/findings/<finding_id>/explore/<cell_id>")
    def inv_fx_explore(finding_id: str, cell_id: str):
        return explore_route("fixtures", finding_id, cell_id)
