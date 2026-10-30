"""Reference evaluator for the AI Security Assurance rules (learning/assurance/rules.json).

The dashboards compute findings in Splunk with SPL that scripts/build_assurance_app.py generates from the same rules. This module applies the same rules in
Python so they can be tested offline against committed telemetry and compared with what Splunk shows. It is deterministic: no language model, no network,
no clock. A finding's status comes only from observed events: a control decision, an execution event in the same hop, and the completeness of the run.
"""
from __future__ import annotations

import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[3]
RULES_PATH = ROOT / "learning" / "assurance" / "rules.json"
CONTROLS_PATH = ROOT / "learning" / "assurance" / "controls.json"
SECURITY_SCHEMA = "agentsec.security_event"
FAIL_OPEN = "vulnerable_profile_fail_open"
FIXTURE_MARKER = "assurance-test-fixture"
INDEX_SEARCH = 'index=agentsec_telemetry sourcetype=otel:agentic:json'


def load_rules() -> dict:
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))


def load_controls() -> dict:
    return {c["id"]: c for c in json.loads(CONTROLS_PATH.read_text(encoding="utf-8"))["controls"]}


def recorded_run_ids(root: Path = ROOT) -> frozenset[str]:
    """Run ids committed as replay specimens: the only way to tell recorded runs from live ones (both say execution.mode=LIVE)."""
    return frozenset(p.stem for p in (root / "learning" / "level_1").glob("*/specimens/*.jsonl"))


def read_events(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _g(e: dict, key: str):
    return e.get(key)


def _first_match(rules: dict, decision, reason, executed: bool, incomplete: bool):
    """The first rule (ascending order) whose cond matches; returns (rule id, status, obs_note key)."""
    for r in sorted(rules["rules"], key=lambda x: x["order"]):
        c = r["cond"]
        if c.get("incomplete") and not incomplete:
            continue
        if incomplete and not c.get("incomplete"):
            continue
        if c.get("unclassified"):
            continue                                 # the fall-through, returned below when nothing else matches
        if "decision" in c and c["decision"] != decision:
            continue
        if "reason_prefix" in c and not str(reason).startswith(c["reason_prefix"]):
            continue
        if "executed" in c and c["executed"] != executed:
            continue
        return r["id"], r["status"], NOTE_KEYS.get(r["id"])
    return "R-UNCLASSIFIED", "INSUFFICIENT_EVIDENCE", None


NOTE_KEYS = {"R-OBSERVE-ONLY": "OBSERVE", "R-ERROR": "ERROR", "R-FAILOPEN-NOT-EXECUTED": "FAIL_OPEN_NOT_EXECUTED"}


def _truthy(v) -> bool:
    return v is True or str(v).lower() == "true"


def group_runs(events: Iterable[dict]) -> dict[str, dict]:
    """Per run: de-duplicated events by sequence plus completeness facts. Only the security-event schema is scored."""
    by_run: dict[str, dict[int, dict]] = defaultdict(dict)
    dups: dict[str, int] = defaultdict(int)
    for e in events:
        if _g(e, "agentsec.schema.name") != SECURITY_SCHEMA or not _g(e, "agentsec.run.id"):
            continue
        rid, seq = str(e["agentsec.run.id"]), _g(e, "agentsec.sequence")
        if seq in by_run[rid]:
            dups[rid] += 1
            continue
        by_run[rid][seq] = e
    runs = {}
    for rid, evs in by_run.items():
        seqs = sorted(s for s in evs if isinstance(s, int))
        ordered = [evs[s] for s in seqs]
        names = [e.get("event.name") for e in ordered]
        terminal = "agentsec.run.completed" in names or "agentsec.run.failed" in names
        contiguous = bool(seqs) and seqs == list(range(1, len(seqs) + 1))
        started = next((e for e in ordered if e.get("event.name") == "agentsec.run.started"), ordered[0] if ordered else {})
        first_decision = next((e for e in ordered if e.get("event.name") == "agentsec.control.decision"), None)
        runs[rid] = {
            "run_id": rid, "events": ordered, "n": len(ordered), "duplicates": dups.get(rid, 0), "terminal": terminal, "contiguous": contiguous,
            "complete": terminal and contiguous, "failed": "agentsec.run.failed" in names,
            "mode": _g(started, "agentsec.testbed.mode"), "profile": _g(started, "agentsec.security.profile"), "attack_id": _g(started, "agentsec.attack.id"),
            "start_ts": _g(started, "timestamp"), "first_decision_ts": _g(first_decision, "timestamp") if first_decision else None,
        }
    return runs


def _tpl(text: str, fields: dict) -> str:
    return text.format_map(_Safe(fields))


class _Safe(dict):
    def __missing__(self, k):                      # a placeholder with no value renders empty, never raises
        return ""


def _hop_executed(run: dict, hop, rules: dict) -> bool:
    names = set(rules["unit"]["execution_events"])
    return any(e.get("event.name") in names and _truthy(e.get("agentsec.operation.executed")) and e.get("agentsec.hop.index") == hop for e in run["events"])


def evaluate(events: Iterable[dict], *, recorded: frozenset[str] | None = None, rules: dict | None = None, controls: dict | None = None) -> list[dict]:
    rules, controls = rules or load_rules(), controls or load_controls()
    recorded = recorded_run_ids() if recorded is None else recorded
    nar = rules["narrative"]
    out: list[dict] = []
    for rid, run in group_runs(events).items():
        decisions = [e for e in run["events"] if e.get("event.name") == "agentsec.control.decision"]
        marker = next((x.get("agentsec.lab.id") for x in run["events"] if x.get("agentsec.lab.id")), None)
        evidence_class = "TEST_FIXTURE" if marker == FIXTURE_MARKER else "RECORDED" if rid in recorded else "LIVE"
        executed_any = False
        denied_by_enforcer = False
        for e in decisions:
            cid, decision, reason = e.get("agentsec.control.id"), e.get("agentsec.control.decision"), str(e.get("agentsec.control.reason") or "")
            hop = e.get("agentsec.hop.index")
            ctl = controls.get(cid, {})
            executed = hop is not None and _hop_executed(run, hop, rules)
            executed_any = executed_any or executed
            if decision == "DENY" and ctl.get("class", "ENFORCE") == "ENFORCE":
                denied_by_enforcer = True
            by_design = False
            incomplete = hop is None or not run["complete"]
            rule_id, status, note_key = _first_match(rules, decision, reason, executed, incomplete)
            by_design = bool(next(r for r in rules["rules"] if r["id"] == rule_id).get("by_design"))
            if rule_id == "R-ALLOW-EXPECTED":
                continue                              # R-ALLOW-EXPECTED: authorized activity, not a finding
            out.append(_finding(run, e, ctl, rule_id, status, by_design, note_key, executed, evidence_class, rules, nar))
        if run["complete"] and not decisions and run["mode"] in rules["run_rules"][0]["cond"]["modes"]:
            out.append(_run_finding(run, "(none)", "RR-NO-DECISION", "INSUFFICIENT_EVIDENCE", evidence_class, rules, nar, why="the run recorded no control decision"))
        elif run["complete"] and decisions and run["mode"] == "RETEST" and run["profile"] == "defended" and executed_any and not denied_by_enforcer:
            out.append(_run_finding(run, "(run)", "RR-RETEST-NOT-PREVENTED", "VERIFIED_INEFFECTIVE", evidence_class, rules, nar, why=""))
    _link_retests(out, rules)
    return out


def _base(run: dict, ctl: dict, control_id, rule_id, status, evidence_class, rules, hop=None, decision=None, reason=None, tool=None, by_design=False) -> dict:
    st = rules["statuses"][status]
    fid = hashlib.sha256(f"{run['run_id']}|{hop}|{control_id}|{rule_id}".encode()).hexdigest()[:12]
    return {
        "finding_id": f"F-{fid}", "run_id": run["run_id"], "hop": hop, "control_id": control_id, "control_name": ctl.get("name", control_id), "control_class": ctl.get("class", ""),
        "mode": run["mode"], "profile": run["profile"], "attack_id": run["attack_id"], "decision": decision, "reason": reason, "tool": tool, "rule_id": rule_id,
        "status": status, "status_label": st["label"], "confidence": st["confidence"], "by_design": by_design, "evidence_class": evidence_class,
        "boundary": ctl.get("boundary", ""), "maestro_layers": ctl.get("maestro_layers", []), "workshops": ctl.get("workshops", []), "technique": ctl.get("technique", ""),
        "spl": f'{INDEX_SEARCH} "agentsec.run.id"="{run["run_id"]}" | sort agentsec.sequence',
        "retest": {"outcome": "NOT_APPLICABLE", "run_id": None},
    }


def _finding(run, e, ctl, rule_id, status, by_design, note_key, executed, evidence_class, rules, nar) -> dict:
    cid, hop = e.get("agentsec.control.id"), e.get("agentsec.hop.index")
    f = _base(run, ctl, cid, rule_id, status, evidence_class, rules, hop, e.get("agentsec.control.decision"), e.get("agentsec.control.reason"), e.get("gen_ai.tool.name"), by_design)
    key = "VERIFIED_INEFFECTIVE_BY_DESIGN" if by_design else status
    fields = {"run_id": run["run_id"], "mode": run["mode"], "profile": run["profile"], "evidence_class": evidence_class, "control_id": cid, "decision": f["decision"], "reason": f["reason"],
              "hop": hop if hop is not None else "(missing)", "tool_part": f" for tool {f['tool']}" if f["tool"] else "", "exec_part": nar["exec_part"]["executed" if executed else "not_executed"],
              "boundary": ctl.get("boundary", ""), "guards": ctl.get("guards", "operation"), "technique": ctl.get("technique", "this"), "why": _why(run, hop, f["decision"])}
    fields["obs_note"] = _tpl(nar["obs_note"][note_key], fields) if note_key else ""
    f.update(observation=_tpl(nar["observation"], fields), interpretation=_tpl(nar["interpretation"][key], fields), impact=_tpl(nar["impact"][key], fields),
             control_interpretation=_tpl(nar["control_interpretation"][key], fields), recommended_action=_action(ctl, status, nar), retest_check=ctl.get("retest", ""),
             executed_in_hop=executed, evidence_refs=[{"sequence": x.get("agentsec.sequence"), "event": x.get("event.name")} for x in run["events"] if x.get("agentsec.hop.index") == hop and x.get("event.name") in ("agentsec.control.decision", *rules["unit"]["execution_events"])])
    return f


def _run_finding(run, control_id, rule_id, status, evidence_class, rules, nar, why) -> dict:
    f = _base(run, {}, control_id, rule_id, status, evidence_class, rules)
    rr = next(r for r in rules["run_rules"] if r["id"] == rule_id)
    f.update(observation=f"Run {run['run_id']} ({run['mode']} mode, {run['profile']} profile, {evidence_class} evidence): {rr['when']}.", interpretation=rr["explain"],
             impact=nar["impact"][status], control_interpretation=nar["control_interpretation"][status],
             recommended_action=nar["default_action_insufficient"] if status == "INSUFFICIENT_EVIDENCE" else "Check which control should have denied this retest, whether the defended profile was really applied, and whether the control matches this technique.",
             retest_check="Re-run the retest after the change and read the same hop.", executed_in_hop=None, evidence_refs=[])
    return f


def _why(run: dict, hop, decision=None) -> str:
    parts = []
    if decision not in ("ALLOW", "DENY", "OBSERVE", "ERROR"):
        parts.append("the decision value is missing or unknown")
    if hop is None:
        parts.append("the decision has no hop index")
    if not run["terminal"]:
        parts.append("no terminal run event yet")
    if not run["contiguous"]:
        parts.append("the event sequence has gaps")
    return "; ".join(parts)


def _action(ctl: dict, status: str, nar: dict) -> str:
    if status == "INSUFFICIENT_EVIDENCE":
        return nar["default_action_insufficient"]
    return ctl.get("remediation", "Investigate the run in Splunk with the SPL shown.")


def _link_retests(findings: list[dict], rules: dict) -> None:
    """ATTACK findings are linked to RETEST findings with the same attack id and control id. No other relation (timestamps, order) is used."""
    retests = defaultdict(list)
    for f in findings:
        if f["mode"] == "RETEST" and f["attack_id"] and f["control_id"] not in ("(none)", "(run)"):
            retests[(f["attack_id"], f["control_id"], f["evidence_class"])].append(f)
    for f in findings:
        if f["mode"] != "ATTACK":
            continue
        linked = retests.get((f["attack_id"], f["control_id"], f["evidence_class"]), []) if f["attack_id"] else []
        if not linked:
            f["retest"] = {"outcome": "NO_RETEST", "run_id": None}
        else:
            linked = sorted(linked, key=lambda x: x["run_id"])        # Splunk shows the lexicographically first run id; so does this
            ok = [x for x in linked if x["status"] == "VERIFIED_EFFECTIVE"]
            f["retest"] = {"outcome": "VALIDATED", "run_id": ok[0]["run_id"]} if ok else {"outcome": "NOT_VALIDATED", "run_id": linked[0]["run_id"]}


def summary(events: Iterable[dict], findings: list[dict], controls: dict | None = None) -> dict:
    """The dashboard metrics, each with its numerator and denominator, from the same events and findings."""
    controls = controls or load_controls()
    runs = group_runs(events)
    enforcing = [f for f in findings if f["decision"] in ("ALLOW", "DENY", "ERROR") and f["control_id"] not in ("(none)", "(run)")]
    deny = [f for f in findings if f["decision"] == "DENY"]
    ineff = [f for f in findings if f["status"] == "VERIFIED_INEFFECTIVE" and f["control_id"] not in ("(none)", "(run)")]
    run_level_ineff = [f for f in findings if f["status"] == "VERIFIED_INEFFECTIVE" and f["control_id"] == "(run)"]
    attack_ineff = [f for f in ineff if f["mode"] == "ATTACK"]
    tested = {f["control_id"] for f in findings if f["mode"] in ("ATTACK", "RETEST")}
    lat = []
    for r in runs.values():
        if r["start_ts"] and r["first_decision_ts"]:
            lat.append(_secs(r["first_decision_ts"]) - _secs(r["start_ts"]))
    return {
        "attack_runs": sum(1 for r in runs.values() if r["mode"] == "ATTACK"), "runs": len(runs),
        "unauthorized_executed": {"n": len(ineff), "of": len(enforcing), "by_design": sum(1 for f in ineff if f["by_design"]), "run_level_retest_failures": len(run_level_ineff)},
        "blocked_verified": {"n": sum(1 for f in findings if f["status"] == "VERIFIED_EFFECTIVE"), "of_deny_decisions": len(deny)},
        "retest": {k: sum(1 for f in attack_ineff if f["retest"]["outcome"] == k) for k in ("VALIDATED", "NOT_VALIDATED", "NO_RETEST")} | {"of": len(attack_ineff)},
        "complete_runs": {"n": sum(1 for r in runs.values() if r["complete"]), "of": len(runs)},
        "untested_controls": {"n": len([c for c in controls if c not in tested]), "of": len(controls), "ids": sorted(c for c in controls if c not in tested)},
        "decision_latency_s": {"median": statistics.median(lat), "max": max(lat), "runs": len(lat)} if lat else None,
    }


def _secs(ts: str) -> float:
    from datetime import datetime, timezone
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
