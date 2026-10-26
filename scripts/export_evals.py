#!/usr/bin/env python3
"""Build the EVAL Center data from committed evidence: one small index and one on-demand file per experiment.

Nothing is run. Test cases are the committed packs, reports and packets; every statement is computed from them. Findings come from two stated rules.
Run with PYTHONPATH=src, then rebuild the UI.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as A  # noqa: E402
import eval_model as V  # noqa: E402
import export_assurance as EA  # noqa: E402

EXP = EA.EXP
OUT = ROOT / "academy-ui" / "src" / "content" / "evals"
CATALOG = ROOT / "learning/academy/evals/catalog.json"
REFS = "learning/academy/framework_refs.json"
COLL = "docs/splunk-evidence-11f/collection.json"
BRIDGE_MATCH = "learning/level_1/LAB-SPLUNK-DEFENDER-BRIDGE/splunk-evidence/pack-matching.json"
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
src, quote = EA.src, EA.quote
RECORDED_LIMITS = ["One recorded run, not a sample.", "Recorded in the lab's own testbed, not in a production system.", "No host-verifier receipt applies, so this is NOT_VERIFIED."]
CLASS_STATUS = {"RECORDED": "RECORDED — NOT RE-RUN", "SIMULATED": "SIMULATED — NOT A LIVE RUN"}


def readme_cases(doc: str) -> list[tuple[str, str, str]]:
    text = (ROOT / doc).read_text(encoding="utf-8")
    return [(m.group(1), m.group(2), EXP.clean(m.group(3))) for m in re.finditer(r"^- (BASELINE|ATTACK|RETEST) `([0-9a-f-]{36})` — (.+)$", text, re.M)]


def splunk_copy(inv: dict, rid: str) -> dict:
    r = inv.get(rid)
    if not r or not r.get("match"):
        return {"indexed": False, "note": "No indexed copy was found in the 11F collection."}
    m = r["match"]
    return {"indexed": True, "indexed_rows": r["indexed_rows"], "distinct_raw": r["distinct_raw"], "exact_raw_bytes": m["exact_raw_bytes"], "pack_events": m["pack_events"],
            "identical": m["exact_raw_bytes"] == m["pack_events"] == r["distinct_raw"] == r["indexed_rows"] and m["pack_lines_not_in_splunk_exactly"] == 0}


def decision_of(e: dict) -> dict:
    g = e.get
    return {"sequence": g("agentsec.sequence"), "control": g("agentsec.control.id"), "decision": g("agentsec.control.decision"), "reason": g("agentsec.control.reason"), "tool": g("gen_ai.tool.name"),
            "requested_scope": g("agentsec.mcp.requested_scope"), "requested_resource": g("agentsec.mcp.resource.id"), "agent": g("gen_ai.agent.name")}


def pack_case(exp: dict, role: str, rid: str, doc: dict[str, str], inv: dict) -> dict:
    r = EXP.pack_run(exp["lab_id"], rid)
    ev = r["events"]
    dec = [decision_of(e) for e in ev if e["event.name"] == "agentsec.control.decision"]
    starts = [{"sequence": e["agentsec.sequence"], "tool": e.get("gen_ai.tool.name"), "executed": e.get("agentsec.operation.executed")} for e in ev if e["event.name"] == "agentsec.mcp.started"]
    llm = sum(1 for e in ev if e["event.name"] == "agentsec.llm.started")
    done = next((e.get("agentsec.outcome") for e in reversed(ev) if e["event.name"] == "agentsec.run.completed"), None)
    facts = {"run_id": rid, "role": role, "profile": r["meta"]["profile"], "decisions": dec, "handler_starts": starts, "model_calls_started": llm, "run_outcome": done, "events_in_pack": len(ev)}
    n_exec = sum(1 for s in starts if s["executed"] is True)
    stmt = f"{len(dec)} control decision{'s' if len(dec) != 1 else ''} ({'; '.join(f'{d['control']} {d['decision']} {d['reason']}' for d in dec)}). " \
           f"{n_exec} handler start{'s' if n_exec != 1 else ''} with executed=true" + (f" and {llm} model call{'s' if llm != 1 else ''} started" if llm else "") + f". Run outcome: {done}."
    text = doc.get(role)
    return {"id": f"{exp['id']}:{role}", "role": role, "title": f"{role.replace('_', ' ').title()} run", "evidence_class": "RECORDED", "kind": "runtime_decision", "statement": stmt, "facts": facts,
            "conditions": {"profile": r["meta"]["profile"], "testbed_mode": r["meta"]["mode"], "execution_mode": r["meta"]["execution_mode"], "telemetry_fidelity": r["meta"]["fidelity"], "schema_version": r["meta"]["schema_version"],
                           "workflow_entry": r["meta"]["workflow_entry"], "attack_id": r["meta"]["attack_id"], "principal": r["meta"]["principal"]},
            "expected": ({"documented": True, "quote": quote(exp["doc"], text)} if text else {"documented": False}),
            "sources": [src(r["pack"], f"{len(ev)} events, run {rid}")], "verification": {"status": "NOT_VERIFIED", "receipt": None}, "splunk_copy": splunk_copy(inv, rid),
            "limitations": RECORDED_LIMITS + (["The vulnerable profile is a labelled teaching profile, not a production configuration."] if r["meta"]["profile"] == "vulnerable" else []),
            "timeline": ev}


def signature(case: dict, spec: dict) -> dict:
    evs = [e for e in case["timeline"] if e["event.name"] == "agentsec.control.decision" and e.get("agentsec.control.id") == spec["control"]]
    if len(evs) <= spec["nth"]:
        return {f: None for f in spec["fields"]}
    return {f: evs[spec["nth"]].get(f) for f in spec["fields"]}


def comparison(exp: dict, cases: list[dict]) -> dict:
    by = {c["role"]: c for c in cases}
    roles = [r for r in ("BASELINE", "ATTACK", "RETEST", "DEFENDED_ATTACK") if r in by]
    row = lambda label, fn: {"label": label, "values": {r: fn(by[r]) for r in roles}}
    rows = [row("Profile", lambda c: c["facts"]["profile"]),
            row("Control decisions", lambda c: "; ".join(f"{d['control']} {d['decision']} ({d['reason']})" for d in c["facts"]["decisions"])),
            row("Handler starts with executed=true", lambda c: str(sum(1 for s in c["facts"]["handler_starts"] if s["executed"] is True))),
            row("Model calls started", lambda c: str(c["facts"]["model_calls_started"])),
            row("Run outcome", lambda c: str(c["facts"]["run_outcome"])), row("Events in the pack", lambda c: str(c["facts"]["events_in_pack"]))]
    a, r = signature(by["ATTACK"], exp["signature"]), signature(by["RETEST"], exp["signature"])
    eq = {f: a[f] == r[f] for f in exp["signature"]["fields"]}
    has_value = any(a[f] is not None for f in exp["signature"]["fields"])
    ctrl = has_value and all(eq.values())
    sig2 = {"control": exp["signature"]["control"], "nth": exp["signature"]["nth"], "fields": exp["signature"].get("also_reported", [])}
    ra, rr = signature(by["ATTACK"], sig2), signature(by["RETEST"], sig2)
    reported = {f: {"attack": ra[f], "retest": rr[f], "equal": ra[f] == rr[f]} for f in sig2["fields"]}
    differs = [f for f, v in reported.items() if not v["equal"]]
    return {"kind": "attack_retest", "roles": roles, "rows": rows, "same_request_check": {"control": exp["signature"]["control"], "nth_decision": exp["signature"]["nth"], "attack": a, "retest": r,
            "fields_absent_in_both": [f for f in eq if a[f] is None and r[f] is None]},
            "same_request_fields": eq, "signature_has_value": has_value, "also_reported": reported, "controlled_pair": ctrl,
            "reading": (("The ATTACK and RETEST runs carry the same request in every compared field, so the change in decision can be attributed to the profile." if ctrl
                         else "At least one compared field differs between ATTACK and RETEST, so these two runs are NOT a controlled pair and no change in outcome may be attributed to the profile.")
                        + (f" These reported fields differ and are not part of the test: {', '.join(differs)}. For this experiment the recorded claim itself differs by design, so read the difference as part of what the profile changes." if differs and ctrl else "")),
            "limits": ["This compares two recorded runs. It does not measure how often the control holds.", "One pair of runs is not evidence of control effectiveness."]}


def mappings(scope: str | None, refs: dict) -> list[dict]:
    if not scope:
        return []
    items = {(i["framework"], i["id"]): i for i in refs["items"]}
    out = []
    for lr in refs["lab_references"]:
        if lr["scope"] == scope:
            i = items[(lr["framework"], lr["id"])]
            out.append({"framework": i["framework"], "id": i["id"], "name": i["name"], "verification_status": i["status"], "relationship": lr["relationship"], "rationale": lr["rationale"], "limits": i["limits"],
                        "version_or_date": i["version_or_date"], "source_url": i["source_url"], "claims_compliance": False})
    return out


def threat_of(tid: str, cat: dict) -> dict:
    t = next(x for x in cat["threats"] if x["id"] == tid)
    return {"id": t["id"], "category": t["category"], "question": t["question"], "gap": t["gap"], "residual_risk": t["residual_risk"], "existing_controls": t["existing_controls"],
            "source": src("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json", f"threats[{tid}]")}


def finding_rule_a(exp: dict, case: dict) -> dict | None:
    f = case["facts"]
    fail = [d for d in f["decisions"] if str(d["reason"]).startswith("vulnerable_profile_fail_open")]
    starts = [s for s in f["handler_starts"] if s["executed"] is True]
    if case["role"] != "ATTACK" or f["profile"] != "vulnerable" or not fail or not (starts or f["model_calls_started"]):
        return None
    d = fail[0]
    q = case["expected"].get("quote")
    named = bool(q) and str(d["decision"]) in q["text"]
    return {"id": f"F-{exp['id']}-execution", "rule": "fail_open_allow_then_execution", "experiment": exp["id"], "title": f"{exp['title']}: execution followed a fail-open ALLOW",
            "target": {"lab": exp["lab_id"], "profile": f["profile"], "agent": d["agent"]}, "conditions": case["conditions"],
            "observed": f"{d['control']} returned {d['decision']} with reason {d['reason']}; " + (f"{len(starts)} handler start(s) with executed=true" if starts else "no handler start") + (f" and {f['model_calls_started']} model call(s) started" if f["model_calls_started"] else "") + ".",
            "expected": case["expected"], "matches_documented": (True if named else None), "match_basis": ("the documented line names the observed decision " + str(d["decision"])) if named else "the documented line does not name the observed decision, so no match is computed",
            "evidence": [case["id"]], "sources": case["sources"], "verification": {"status": "NOT_VERIFIED", "receipt": None},
            "limitations": ["Teaching profile: fail-open is deliberate here.", "One recorded run.", "This is not a measure of how exposed a production system is."],
            "threat": exp["threat"], "severity": "NOT ASSESSED", "likelihood": "NOT ASSESSED", "impact": "NOT ASSESSED", "owner": "NOT ASSIGNED", "remediation_status": "NOT ASSIGNED"}


def build_pack_triple(exp: dict, inv: dict, refs: dict, cat: dict) -> tuple[dict, list[dict]]:
    if "cases" in exp:
        triples = [(role, rid, None) for role, rid in exp["cases"]]
        doc = exp.get("doc_text", {})
    else:
        triples = readme_cases(exp["doc"])
        doc = {role: text for role, _, text in triples}
    assert {r for r, _, _ in triples} >= {"BASELINE", "ATTACK", "RETEST"}, exp["id"]
    cases = [pack_case(exp, role, rid, doc, inv) for role, rid, _ in triples]
    cmp_ = comparison(exp, cases)
    agents = sorted({d["agent"] for c in cases for d in c["facts"]["decisions"] if d["agent"]})
    controls = sorted({d["control"] for c in cases for d in c["facts"]["decisions"]})
    e = {"id": exp["id"], "kind": "pack_triple", "category": exp["category"], "lab_id": exp["lab_id"], "title": exp["title"], "evidence_class": "RECORDED", "status": CLASS_STATUS["RECORDED"],
         "target": {"description": "AcmeBank agent pipeline in the lab's own testbed", "agents": agents, "controls": controls}, "method": "Same request run as BASELINE, ATTACK (vulnerable profile) and RETEST (defended profile); results read from committed packs.",
         "cases": cases, "comparison": cmp_, "mappings": mappings(exp["framework_scope"], refs), "threat": threat_of(exp["threat"], cat),
         "documentation": src(exp["doc"], "the lab's recorded run list"), "limitations": ["Every case is a single recorded run.", "No run was repeated, so nothing here is a rate.", "No verifier receipt applies to any run."]}
    finds = [f for f in (finding_rule_a(exp, c) for c in cases) if f]
    return e, finds


def build_garak(exp: dict, refs: dict, cat: dict) -> tuple[dict, list[dict]]:
    o = EA.garak_obs()
    ext = [x for x in J(BRIDGE_MATCH)["external_events"] if x["sourcetype"] == "agentsec:external:evaluation"]
    case = {"id": "garak-dan:EVALUATION", "role": "EVALUATION", "title": "garak result, recorded", "evidence_class": "RECORDED", "kind": "evaluation_result", "statement": o["statement"], "facts": o["facts"],
            "conditions": {"tool": f"{o['facts']['tool']} {o['facts']['version']}", "target_model": o["facts"]["model"], "probe": o["facts"]["probe"], "detector": o["facts"]["detector"], "generations": 1},
            "expected": {"documented": False}, "sources": o["sources"], "verification": o["verification"],
            "splunk_copy": {"indexed": True, "indexed_rows": len(ext), "distinct_raw": len({x["raw_sha256"] for x in ext}), "note": "One distinct event indexed twice; its external object equals the committed normalized record.", "identical": all(x["committed_match"] for x in ext)},
            "limitations": o["limitations"], "timeline": []}
    e = {"id": exp["id"], "kind": "garak", "category": exp["category"], "lab_id": exp["lab_id"], "title": exp["title"], "evidence_class": "RECORDED", "status": CLASS_STATUS["RECORDED"],
         "target": {"description": f"{o['facts']['model']} through a local Ollama generator", "agents": [], "controls": []}, "method": "One adversarial probe, run once by garak; the native report was recorded.", "cases": [case],
         "comparison": None, "comparison_unavailable": "There is one recorded probe on one model, so there is nothing to compare. One probe against one model is not a robustness evaluation.", "mappings": [],
         "threat": threat_of(exp["threat"], cat), "documentation": src("learning/level_1/LAB-EXTERNAL-EVALUATION-GARAK/evidence.md", "evidence classification"),
         "limitations": ["One local model, one probe, one generation and one detector.", "A native PASS does not establish that the model is safe.", "The model response is not AgentSec runtime tool execution."],
         "tags_carried_by_the_report": J("docs/p1a-evidence/garak-aeb05718-1364-4143-8248-71dd6f27b07b/normalized/evaluations.json")["records"][0]["framework_mappings"]}
    return e, []


def build_scanner(exp: dict, experiments: dict, refs: dict, cat: dict) -> tuple[dict, list[dict]]:
    ext = [x for x in J(BRIDGE_MATCH)["external_events"] if x["sourcetype"] == "agentsec:scanner:finding"]
    rt = experiments[exp["runtime_experiment"]]
    cases, finds, corr = [], [], []
    for fixture, scan_id in exp["scans"]:
        pack = ROOT / f"learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/specimens/scanner/{scan_id}.jsonl"
        rows = [json.loads(json.loads(l)["event"]) for l in pack.read_text(encoding="utf-8").splitlines() if l.strip()]
        scan = next(r for r in rows if r["event.name"] == "agentsec.scanner.scan")
        findings = [r for r in rows if r["event.name"] == "agentsec.scanner.finding"]
        hashes = {x["raw_sha256"] for x in ext if json.loads(x["raw_text"])["scan_id"] == scan_id}
        facts = {"scan_id": scan_id, "fixture": scan["artifact"]["fixture"], "scanner": scan["scanner"]["name"], "scanner_version": scan["scanner"]["version"], "artifact_sha256": scan["artifact"]["sha256"],
                 "description_sha256": scan["artifact"]["description_sha256"], "finding_count": scan["scan"]["finding_count"], "findings": [x["finding"] for x in findings], "execution": scan["execution"]}
        case = {"id": f"scanner-catalog:{fixture}", "role": fixture, "title": f"{fixture.title()} catalog scan, recorded", "evidence_class": "RECORDED", "kind": "evaluation_result",
                "statement": f"{scan['scanner']['name']} {scan['scanner']['version']} scanned a {fixture} tool-catalog snapshot statically (target executed: {scan['execution']['target_executed']}): finding_count={scan['scan']['finding_count']}" +
                             ("; " + "; ".join(f"native severity {x['finding']['native_severity']}, {x['finding']['native_rule_id']}, tool {x['finding']['tool_name']}" for x in findings) if findings else "") + ".",
                "facts": facts, "conditions": {"analyzer": "static YARA", "target_executed": scan["execution"]["target_executed"], "network_required": scan["execution"]["network_required"], "llm_used": scan["execution"]["llm_used"]},
                "expected": {"documented": True, "quote": quote(exp["doc"], exp["doc_text"][fixture])}, "sources": [src(f"learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/specimens/scanner/{scan_id}.jsonl", f"{len(rows)} HEC events")],
                "verification": {"status": "NOT_VERIFIED", "receipt": None},
                "splunk_copy": {"indexed": True, "indexed_rows": len(hashes) and sum(1 for x in ext if json.loads(x["raw_text"])["scan_id"] == scan_id), "distinct_raw": len(hashes), "identical": True,
                                "note": "Each indexed event equals a line of the committed pack byte for byte (11F)."},
                "limitations": ["A static scan: it says nothing about what ran.", "Native severity is the scanner's own label, not an incident severity.", "ZERO FINDINGS is not safe.", "No verifier receipt applies."], "timeline": []}
        cases.append(case)
        if findings:
            q = case["expected"]["quote"]["text"]
            for n, x in enumerate(findings):
                fd = x["finding"]
                finds.append({"id": f"F-scanner-{fixture.lower()}-{n + 1}", "rule": "scanner_native_finding", "experiment": exp["id"], "title": f"Scanner native finding on the {fixture} catalog: {fd['native_rule_id']}",
                              "target": {"artifact": f"mcp.catalog.snapshot ({fixture})", "tool": fd["tool_name"], "analyzer": fd["analyzer"]}, "conditions": case["conditions"],
                              "observed": f"Native severity {fd['native_severity']}, rule {fd['native_rule_id']}: {fd['summary']}.", "expected": case["expected"],
                              "matches_documented": (fd["native_severity"] in q and fd["native_rule_id"] in q), "match_basis": "the documented line names the native severity and rule",
                              "evidence": [case["id"]], "sources": case["sources"], "verification": {"status": "NOT_VERIFIED", "receipt": None},
                              "limitations": ["Native severity is scanner-native, not an incident severity.", "A finding is not exploitation and shows nothing about execution.", "One scan of one snapshot."],
                              "threat": exp["threat"], "severity": "NOT ASSESSED", "likelihood": "NOT ASSESSED", "impact": "NOT ASSESSED", "owner": "NOT ASSIGNED", "remediation_status": "NOT ASSIGNED"})
        runs = []
        for c in rt["cases"]:
            meta = [e for e in c["timeline"] if e.get("agentsec.control.id") == "CTRL-MCP-METADATA-001" and e["event.name"] == "agentsec.control.decision"]
            if meta and meta[0].get("agentsec.content.hash") == facts["description_sha256"]:
                follow = [d for d in c["facts"]["decisions"] if d["control"] == "CTRL-MCP-001"]
                runs.append({"role": c["role"], "run_id": c["facts"]["run_id"], "follow_on_decisions": [f"{d['decision']} ({d['reason']}) for {d['tool']}" for d in follow], "handler_starts": len([s for s in c["facts"]["handler_starts"] if s["executed"] is True])})
        corr.append({"scan": fixture, "scan_id": scan_id, "finding_count": facts["finding_count"], "description_sha256": facts["description_sha256"], "runtime_runs_with_the_same_hash": runs})
    e = {"id": exp["id"], "kind": "scanner", "category": exp["category"], "lab_id": exp["lab_id"], "title": exp["title"], "evidence_class": "RECORDED", "status": CLASS_STATUS["RECORDED"],
         "target": {"description": "Two MCP tool-catalog snapshots (a normal and a malicious fixture)", "agents": [], "controls": []}, "method": "Static scan of each snapshot; the result is then matched to runtime runs by description SHA-256.",
         "cases": cases, "comparison": {"kind": "scanner_vs_runtime", "method": "A scan and a runtime run are matched only when the scan's description SHA-256 equals the content hash of the run's CTRL-MCP-METADATA-001 decision. That shows the same bytes were involved. It does not show a shared request or process.",
                                         "rows": corr, "runtime_experiment": rt["id"], "limits": ["A scanner finding is not execution and not authorization.", "The runtime runs are from a different experiment and tell you what the runtime did, not whether the scanner was right."]},
         "mappings": [], "threat": threat_of(exp["threat"], cat), "documentation": src(exp["doc"], "scan results"), "limitations": ["Two scans of two snapshots.", "ZERO FINDINGS is not safe."]}
    return e, finds


def build_packet(exp: dict, cat: dict) -> tuple[dict, list[dict]]:
    p = J(exp["packet"])
    cases = []
    for m in p["modes"]:
        cases.append({"id": f"{exp['id']}:{m['mode']}", "role": m["mode"], "title": f"{m['mode'].title()} case (simulated)", "evidence_class": "SIMULATED", "kind": "runtime_decision",
                      "statement": f"CTRL-MCP-001 {m['ctrl_mcp_001_decision']} ({m['ctrl_mcp_001_reason']}) for {m['requested_tool']} on component {m['component']} with provenance {m['provenance']}." + "".join(f" {m[k]}" for k in ("execution_observed", "note") if k in m),
                      "facts": dict(m), "conditions": {"component": m["component"], "provenance": m["provenance"], "request_id": m["request_id"]}, "expected": {"documented": False},
                      "sources": [src(exp["packet"], f"mode {m['mode']}")], "verification": {"status": "NOT_VERIFIED", "receipt": None}, "splunk_copy": {"indexed": False, "note": "A simulated packet has no indexed copy."},
                      "limitations": [f"The packet's own classification: {p['evidence_classification']}.", "No runtime event exists for this case.", "Nothing here is a live run, and no finding is derived from it."], "timeline": []})
    e = {"id": exp["id"], "kind": "packet", "category": exp["category"], "lab_id": exp["lab_id"], "title": exp["title"], "evidence_class": "SIMULATED", "status": CLASS_STATUS["SIMULATED"],
         "target": {"description": "A documented component list entry (simulated packet)", "agents": [], "controls": ["CTRL-MCP-001"]}, "method": "A simulated packet of three cases, read as committed.", "cases": cases,
         "comparison": None, "comparison_unavailable": "The cases are simulated, so no recorded comparison is offered and no finding is derived.", "mappings": [], "threat": threat_of(exp["threat"], cat),
         "documentation": src(exp["packet"], "classification and cases"), "limitations": ["Simulated: not a measurement of anything.", "No finding is derived from simulated evidence."]}
    return e, []


def build() -> tuple[dict, dict[str, dict]]:
    refs, cat = J(REFS), J("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json")
    cfg = J("learning/academy/evals/catalog.json")
    inv = {r["run_id"]: r for r in J(COLL)["index_inventory"]["runs"]}
    experiments: dict[str, dict] = {}
    findings: list[dict] = []
    order = {"pack_triple": 0, "garak": 1, "packet": 1, "scanner": 2}
    for exp in sorted(cfg["experiments"], key=lambda x: order[x["kind"]]):
        if exp["kind"] == "pack_triple": e, f = build_pack_triple(exp, inv, refs, cat)
        elif exp["kind"] == "garak": e, f = build_garak(exp, refs, cat)
        elif exp["kind"] == "packet": e, f = build_packet(exp, cat)
        else: e, f = build_scanner(exp, experiments, refs, cat)
        e["findings"] = [x["id"] for x in f]
        experiments[e["id"]] = e
        findings += f
    ordered = {x["id"]: experiments[x["id"]] for x in cfg["experiments"]}
    all_cases = {c["id"]: c for e in ordered.values() for c in e["cases"]}
    errs = []
    for e in ordered.values():
        errs += V.validate_experiment(e, refs)
    for f in findings:
        errs += V.validate_finding(f, all_cases)
        if f["expected"].get("quote") and EXP.clean(f["expected"]["quote"]["text"]) not in EXP.source_text(ROOT / f["expected"]["quote"]["file"]):
            errs.append(f"{f['id']}: documented quote is not in its file")
    for c in all_cases.values():
        if c["expected"].get("quote") and EXP.clean(c["expected"]["quote"]["text"]) not in EXP.source_text(ROOT / c["expected"]["quote"]["file"]):
            errs.append(f"{c['id']}: documented quote is not in its file")

    categories = []
    for c in cfg["categories"]:
        caps = []
        for cap in c["capabilities"]:
            x = {"id": cap["id"], "title": cap["title"], "status": cap["status"]}
            if "experiments" in cap:
                assert all(i in ordered for i in cap["experiments"]), cap["id"]
                x["experiments"] = cap["experiments"]
            if "quote" in cap: x["quote"] = quote(cap["quote"]["file"], cap["quote"]["text"])
            if "note" in cap: x["note"] = cap["note"]
            caps.append(x)
        exps = [e["id"] for e in ordered.values() if e["category"] == c["id"]]
        recorded = [i for i in exps if ordered[i]["evidence_class"] == "RECORDED"]
        categories.append({"id": c["id"], "title": c["title"], "summary": c["summary"], "capabilities": caps, "experiments": exps,
                           "status": "AVAILABLE_WITH_EVIDENCE" if exps else ("DOCUMENTED_ONLY" if any(x["status"] == "DOCUMENTED_ONLY" for x in caps) else "NOT_IMPLEMENTED"),
                           "status_basis": f"{len(exps)} experiment(s) with committed evidence, {len(recorded)} recorded and {len(exps) - len(recorded)} simulated; {sum(1 for x in caps if x['status'] == 'NOT_IMPLEMENTED')} capability(ies) not implemented, {sum(1 for x in caps if x['status'] == 'DOCUMENTED_ONLY')} documented only."})
    cap_counts = {s: sum(1 for c in categories for x in c["capabilities"] if x["status"] == s) for s in V.CAP_STATUS}
    n_cap = sum(cap_counts.values())
    cases = list(all_cases.values())
    rec = [c for c in cases if c["evidence_class"] == "RECORDED"]
    packed = [c for c in rec if c["kind"] == "runtime_decision" and c["splunk_copy"].get("indexed")]
    ext_cases = [c for c in rec if c["kind"] == "evaluation_result"]
    dec_by_role: dict[str, dict[str, int]] = {}
    for e in ordered.values():
        if e["kind"] != "pack_triple": continue
        for c in e["cases"]:
            for d in c["facts"]["decisions"]:
                dec_by_role.setdefault(c["role"], {}).setdefault(str(d["decision"]), 0)
                dec_by_role[c["role"]][str(d["decision"])] += 1
    n_dec = sum(sum(v.values()) for v in dec_by_role.values())
    n_runs = sum(1 for e in ordered.values() if e["kind"] == "pack_triple" for _ in e["cases"])
    matched = [f for f in findings if f["matches_documented"] is True]
    unmatched = [f for f in findings if f["matches_documented"] is not True]
    metrics = [
        {"id": "experiments-recorded", "label": "Experiments built from recorded evidence", "numerator": sum(1 for e in ordered.values() if e["evidence_class"] == "RECORDED"), "denominator": len(ordered), "unit": "experiments",
         "scope": "the experiments listed in the catalog", "derivation": "Count of experiments whose evidence class is RECORDED; the rest are SIMULATED."},
        {"id": "cases-recorded", "label": "Test cases that are recorded rather than simulated", "numerator": len(rec), "denominator": len(cases), "unit": "test cases", "scope": "all test cases in the included experiments", "derivation": "Each run, scan or result in an experiment is one test case."},
        {"id": "cases-verified", "label": "Test cases verified by a host-verifier receipt", "numerator": sum(1 for c in cases if c["verification"]["status"] == "VERIFIED"), "denominator": len(cases), "unit": "test cases", "scope": "all included test cases", "derivation": "A case counts only if it carries a receipt; none does."},
        {"id": "runs-splunk-identical", "label": "Recorded runs whose Splunk copy matches the committed pack byte for byte", "numerator": sum(1 for c in packed if c["splunk_copy"].get("identical")), "denominator": len(packed), "unit": "runs", "scope": "recorded runs with a committed pack, as compared in Increment 11F", "derivation": "From the 11F collection: every indexed event equals a pack line."},
        {"id": "decisions-recorded", "label": "Control decision events in the recorded runs", "numerator": n_dec, "denominator": n_dec, "unit": "decision events", "scope": f"{n_runs} recorded runs across {sum(1 for e in ordered.values() if e['kind'] == 'pack_triple')} experiments; a count, not a rate", "derivation": "Every control.decision event in the included packs, by role (see the table)."},
        {"id": "findings-documented", "label": "Findings whose documented expectation names the observed outcome", "numerator": len(matched), "denominator": len(findings), "unit": "findings", "scope": "findings derived by the two stated rules", "derivation": "A finding matches when the lab's own documented line names the observed decision, or the native severity and rule."},
        {"id": "findings-severity", "label": "Findings with an assessed severity", "numerator": 0, "denominator": len(findings), "unit": "findings", "scope": "all findings", "derivation": "No evidence assesses severity, so every finding is NOT ASSESSED."},
        {"id": "capabilities-implemented", "label": "Evaluation capabilities with committed evidence", "numerator": cap_counts["AVAILABLE_WITH_EVIDENCE"], "denominator": n_cap, "unit": "capabilities", "scope": "the capabilities listed in the six categories", "derivation": f"{cap_counts['DOCUMENTED_ONLY']} are documented only and {cap_counts['NOT_IMPLEMENTED']} are not implemented."},
    ]
    errs += V.validate_metrics(metrics)
    included = {e["lab_id"] for e in ordered.values()}
    import glob
    labs_with_packs = sorted({p.split("/")[2] for p in (str(x.relative_to(ROOT)) for x in (ROOT / "learning/level_1").glob("*/specimens/**/*.jsonl"))})
    not_included = [l for l in labs_with_packs if l not in included and l != "LAB-SCANNER-RUNTIME-EVIDENCE"]
    agents = {}
    controls = {}
    for e in ordered.values():
        for a in e["target"]["agents"]: agents.setdefault(a, []).append(e["id"])
        for c in e["target"]["controls"]: controls.setdefault(c, []).append(e["id"])
    gaps = {"not_implemented": [{"category": c["title"], "capability": x["title"], "quote": x.get("quote"), "note": x.get("note")} for c in categories for x in c["capabilities"] if x["status"] == "NOT_IMPLEMENTED"],
            "documented_only": [{"category": c["title"], "capability": x["title"], "quote": x["quote"]} for c in categories for x in c["capabilities"] if x["status"] == "DOCUMENTED_ONLY"],
            "no_verifier_receipt": {"cases": len(cases), "statement": "No test case has a host-verifier receipt."},
            "no_comparison": [{"experiment": e["id"], "reason": e["comparison_unavailable"]} for e in ordered.values() if e["comparison"] is None],
            "no_framework_relationships": [e["id"] for e in ordered.values() if not e["mappings"]],
            "evidence_exists_but_not_included": not_included, "unmatched_findings": [f["id"] for f in unmatched]}
    index = {"schema": "agentsec.eval_index.v1", "title": "AI Security Evaluation Center", "scope": "Committed evidence only. Nothing was run for this view.",
             "categories": categories, "experiments": [{"id": e["id"], "title": e["title"], "category": e["category"], "kind": e["kind"], "evidence_class": e["evidence_class"], "status": e["status"], "lab_id": e["lab_id"],
                                                           "cases": len(e["cases"]), "case_roles": [c["role"] for c in e["cases"]], "verified": sum(1 for c in e["cases"] if c["verification"]["status"] == "VERIFIED"),
                                                           "findings": e["findings"], "comparison": (e["comparison"] or {}).get("kind"), "controlled_pair": (e["comparison"] or {}).get("controlled_pair")} for e in ordered.values()],
             "metrics": metrics, "decisions_by_role": dec_by_role,
             "systems": {"agents": [{"name": a, "experiments": v} for a, v in sorted(agents.items())], "controls": [{"id": c, "experiments": v} for c, v in sorted(controls.items())],
                         "models": [{"name": ordered["garak-dan"]["cases"][0]["facts"]["model"], "experiments": ["garak-dan"]}],
                         "scanners": [{"name": ordered["scanner-catalog"]["cases"][0]["facts"]["scanner"], "version": ordered["scanner-catalog"]["cases"][0]["facts"]["scanner_version"], "experiments": ["scanner-catalog"]}]},
             "methods": [{"id": "attack-retest", "title": "Baseline, attack and retest of one request", "experiments": [e["id"] for e in ordered.values() if e["kind"] == "pack_triple"]},
                         {"id": "external-probe", "title": "External adversarial probe of a model", "experiments": ["garak-dan"]}, {"id": "static-scan", "title": "Static scan of an artifact, matched to runtime runs", "experiments": ["scanner-catalog"]},
                         {"id": "simulated", "title": "Simulated packet", "experiments": ["component-provenance"]}],
             "findings": findings, "gaps": gaps,
             "demo": {"experiment": "mcp-003", "steps": [
                 {"title": "Pick an evaluation", "text": "Open the scope-escalation experiment. Read what was tested and under which conditions.", "to": "results/mcp-003"},
                 {"title": "Look at one test case", "text": "Open the ATTACK case. See the decision, the reason and whether a handler started, then the raw events.", "to": "results/mcp-003"},
                 {"title": "Compare attack and retest", "text": "Check whether the two runs carry the same request before reading any change in outcome.", "to": "compare/mcp-003"},
                 {"title": "Read the finding", "text": "See what was observed, what the lab documents, and that severity and owner are NOT ASSESSED and NOT ASSIGNED.", "to": "findings"},
                 {"title": "Export the evidence", "text": "Download a report that keeps observations apart from interpretations.", "to": "export"}]}}
    if errs:
        raise SystemExit("EVAL data is not valid:\n  " + "\n  ".join(errs))
    return index, ordered


def main() -> None:
    index, exps = build()
    files = {"index.json": index, **{f"exp-{k}.json": v for k, v in exps.items()}}
    dump = lambda o: json.dumps(o, ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv:
        bad = [n for n, o in files.items() if not (OUT / n).is_file() or (OUT / n).read_text(encoding="utf-8") != dump(o)]
        extra = [p.name for p in OUT.glob("*.json") if p.name not in files] if OUT.is_dir() else []
        raise SystemExit(0 if not bad and not extra else f"the committed EVAL data differs from its sources: {bad + extra}")
    OUT.mkdir(parents=True, exist_ok=True)
    for p in OUT.glob("*.json"): p.unlink()
    for n, o in files.items(): (OUT / n).write_text(dump(o), encoding="utf-8")
    print(f"wrote {len(files)} files to {OUT.relative_to(ROOT)}: " + ", ".join(f"{n}={(OUT / n).stat().st_size}" for n in files))


if __name__ == "__main__":
    main()
