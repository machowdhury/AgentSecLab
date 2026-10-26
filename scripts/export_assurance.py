#!/usr/bin/env python3
"""Build the assurance workshop journey from committed sources and validate it with scripts/assurance_model.py.

Every observation is computed from a committed pack, report or comparison; nothing is typed in beside its source. Run with PYTHONPATH=src, then rebuild the UI.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as M  # noqa: E402

_spec = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(EXP)

OUT = ROOT / "academy-ui" / "src" / "content" / "assurance" / "mcp-unauthorized-scope.json"
LAB = "LAB-MCP-003"
RUNS = {"BASELINE": "5b089682-1d5a-49a7-ac43-967265fd6bc6", "ATTACK": "b466ad12-72ec-44b7-be28-aacfaf2c25b1", "RETEST": "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5"}
README = f"learning/level_1/{LAB}/README.md"
TM = "learning/level_1/LAB-THREAT-MODELING-001/"
GARAK = "docs/p1a-evidence/garak-aeb05718-1364-4143-8248-71dd6f27b07b/"
COLL = "docs/splunk-evidence-11f/collection.json"
REFS = "learning/academy/framework_refs.json"
GEV = "learning/level_1/LAB-EXTERNAL-EVALUATION-GARAK/evidence.md"
DETMAN = "learning/level_1/LAB-DETECTION-ENGINEERING/splunk-evidence/manifest.json"
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
src = lambda f, loc: {"file": f, "sha256": M.sha256_file(f), "locator": loc}


def quote(file: str, text: str) -> dict:
    if EXP.clean(text) not in EXP.source_text(ROOT / file):
        raise SystemExit(f"{text!r} is not in {file}")
    return {"file": file, "text": text}


def pack_obs(mode: str) -> dict:
    r = EXP.pack_run(LAB, RUNS[mode])
    ev = r["events"]
    d = next(e for e in ev if e["event.name"] == "agentsec.control.decision")
    starts = [e for e in ev if e["event.name"] == "agentsec.mcp.started" and e.get("agentsec.operation.executed") is True]
    facts = {"run_id": RUNS[mode], "mode": mode, "profile": r["meta"]["profile"], "control": d["agentsec.control.id"], "decision": d["agentsec.control.decision"], "reason": d["agentsec.control.reason"],
             "tool": d["gen_ai.tool.name"], "requested_scope": d["agentsec.mcp.requested_scope"], "handler_started": bool(starts), "events_in_pack": len(ev)}
    seqs = [d["agentsec.sequence"]] + [e["agentsec.sequence"] for e in starts]
    return {"id": f"O-{mode}", "kind": "runtime_decision", "evidence_class": "RECORDED",
            "title": f"{mode} run, recorded", "facts": facts,
            "statement": f"{facts['control']} returned {facts['decision']} ({facts['reason']}) for {facts['tool']} at requested scope {facts['requested_scope']}. " + ("A mcp.started event with executed=true is recorded." if starts else "No mcp.started event is recorded in this pack."),
            "sources": [src(r["pack"], "events " + ", ".join(str(s) for s in sorted(seqs)))],
            "verification": {"status": "NOT_VERIFIED", "receipt": None},
            "limitations": ["One recorded run, not a sample.", "The lab names the runtime handler count as the authority for non-execution; this page shows the events in the pack only.",
                            "The vulnerable profile is a labelled teaching profile, not a production configuration." if mode == "ATTACK" else "Recorded in the lab's own testbed, not in a production system."]}


def splunk_obs() -> dict:
    inv = {r["run_id"]: r for r in J(COLL)["index_inventory"]["runs"]}
    rows = []
    for mode, rid in RUNS.items():
        m = inv[rid]["match"]
        rows.append({"run_id": rid, "mode": mode, "indexed_rows": inv[rid]["indexed_rows"], "distinct_raw": inv[rid]["distinct_raw"], "exact_raw_bytes": m["exact_raw_bytes"], "pack_events": m["pack_events"]})
        assert m["exact_raw_bytes"] == m["pack_events"] == inv[rid]["distinct_raw"] == inv[rid]["indexed_rows"] and m["pack_lines_not_in_splunk_exactly"] == 0
    return {"id": "O-SPLUNK", "kind": "provenance_check", "evidence_class": "RECORDED", "title": "Splunk copy compared with the committed packs", "facts": {"runs": rows},
            "statement": "For all three runs, every indexed event is byte-identical to a line of the committed pack and no extra indexed event exists (" + ", ".join(f"{r['exact_raw_bytes']} of {r['pack_events']}" for r in rows) + ").",
            "sources": [src(COLL, "index_inventory.runs for the three run ids")],
            "verification": {"status": "NOT_VERIFIED", "receipt": None},
            "limitations": ["A comparison made once, when the Increment 11F evidence was collected.", "No host-verifier receipt applies to these runs.", "Equal copies show the indexed events match the pack. They do not show the events are true."]}


def garak_obs() -> dict:
    man = J(GARAK + "manifest.json")
    rows = [json.loads(l) for l in (ROOT / GARAK / "raw/garak-report.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    ev = next(r for r in rows if r["entry_type"] == "eval")
    facts = {"tool": man["tool"]["name"], "version": man["tool"]["version"], "model": man["target"]["model"], "probe": ev["probe"], "detector": ev["detector"], "passed": ev["passed"], "fails": ev["fails"], "total_evaluated": ev["total_evaluated"]}
    return {"id": "O-GARAK", "kind": "evaluation_result", "evidence_class": "RECORDED", "title": "garak evaluation, recorded", "facts": facts,
            "statement": f"garak {facts['version']} ran probe {facts['probe']} with detector {facts['detector']} against {facts['model']}: passed {facts['passed']}, failed {facts['fails']}, evaluated {facts['total_evaluated']}.",
            "sources": [src(GARAK + "manifest.json", "execution, target, limitations"), src(GARAK + "raw/garak-report.jsonl", "the eval row")],
            "verification": {"status": "NOT_VERIFIED", "receipt": None},
            "limitations": man["limitations"][:3] + ["Evidence class is evaluation: it tests a model's response, not the tool-authorization control."]}


def build() -> dict:
    refs, arch, cat = J(REFS), J(TM + "architecture.json"), J(TM + "threat-catalog.json")
    t04 = next(t for t in cat["threats"] if t["id"] == "TM-T04")
    obs = [pack_obs("BASELINE"), pack_obs("ATTACK"), pack_obs("RETEST"), splunk_obs(), garak_obs()]
    f = {o["id"]: o["facts"] for o in obs}
    a, r = f["O-ATTACK"], f["O-RETEST"]
    assert (a["tool"], a["requested_scope"]) == (r["tool"], r["requested_scope"]) and (a["decision"], r["decision"]) == ("ALLOW", "DENY") and not r["handler_started"] and a["handler_started"]
    man = J(GARAK + "manifest.json")
    lim = {x: x for x in man["limitations"]}
    not_runtime = "The model response is not AgentSec runtime tool execution."
    assert not_runtime in lim
    rule = refs["rule"]
    assessments = [
        {"id": "A-RETEST", "statement": "In the recorded retest, CTRL-MCP-001 denied the same tool at the same requested scope that the vulnerable-profile run allowed.", "status": "SUPPORTED", "about": ["O-ATTACK", "O-RETEST"],
         "basis": f"Both runs request {a['tool']} at {a['requested_scope']}; ATTACK shows {a['decision']} ({a['reason']}) with a handler start, RETEST shows {r['decision']} ({r['reason']}) with none.",
         "limitations": ["One recorded retest.", "It shows the defended profile's decision for this request only."]},
        {"id": "A-SPLUNK", "statement": "A Splunk copy of each recorded run matches its committed pack byte for byte.", "status": "SUPPORTED", "about": ["O-SPLUNK"],
         "basis": "The 11F comparison found every indexed event equal to a pack line for all three runs.", "limitations": ["Not verified by the host verifier.", "Says nothing about the other indexed runs."]},
        {"id": "A-GARAK", "statement": "The garak PASS shows that CTRL-MCP-001 works.", "status": "NOT_SUPPORTED", "about": ["O-GARAK"],
         "basis": f"The recorded manifest states: {not_runtime} It also states: garak is not CTRL-MCP-001, Splunk, or AgentSec.", "limitations": []},
        {"id": "A-RISK", "statement": "The impact and likelihood of this risk have been assessed.", "status": "NOT_SUPPORTED", "about": [],
         "basis": "No committed evidence gives a business impact or an occurrence rate, so both are recorded as NOT_ASSESSED on the risk.", "limitations": []},
        {"id": "A-COMPLIANCE", "statement": "The control is compliant with OWASP LLM06:2025.", "status": "NOT_SUPPORTED", "about": [],
         "basis": f"The framework reference file states: {rule}", "limitations": []},
    ]
    risk = {"id": "R-SCOPE", "statement": "An agent could execute a tool at a scope it was not granted.", "authored": True,
            "assets": [x for x in arch["assets"] if x["id"] in t04["assets"]], "threat": {"id": t04["id"], "category": t04["category"], "question": t04["question"]},
            "controls": t04["existing_controls"], "observed_in": ["O-ATTACK"],
            "impact": {"status": "NOT_ASSESSED", "reason": "Impact needs a business owner. No committed evidence assesses it."},
            "likelihood": {"status": "NOT_ASSESSED", "reason": "No committed evidence gives how often this occurs outside the lab."},
            "gap": t04["gap"], "residual_risk": t04["residual_risk"], "owner": "NOT_ASSIGNED",
            "sources": [src(TM + "threat-catalog.json", "threats[TM-T04]"), src(TM + "architecture.json", "assets")]}
    mappings = []
    items = {(i["framework"], i["id"]): i for i in refs["items"]}
    for lr in refs["lab_references"]:
        if lr["scope"] != "MCP-003": continue
        i = items[(lr["framework"], lr["id"])]
        mappings.append({"framework": i["framework"], "id": i["id"], "name": i["name"], "verification_status": i["status"], "relationship": lr["relationship"], "rationale": lr["rationale"], "limits": i["limits"],
                         "version_or_date": i["version_or_date"], "source_url": i["source_url"], "claims_compliance": False})
    controls = [{"id": c["id"], "class": c["class"], "placement": c["placement"], "code_reference": c["evidence"],
                 "observed_in_recorded_runs": ([{"run": m, "decision": f[f"O-{m}"]["decision"], "reason": f[f"O-{m}"]["reason"]} for m in RUNS] if c["id"] == "CTRL-MCP-001" else []),
                 "note": "" if c["id"] == "CTRL-MCP-001" else "Named by the threat catalog. These recorded runs do not show it separately."} for c in t04["existing_controls"]]
    n_prop = sum(1 for m in mappings if m["relationship"] == "PROPOSED")
    coverage = [
        {"notion": "Technique coverage", "statement": f"{n_prop} MITRE ATLAS technique relationship is PROPOSED for this attack, and one ATTACK run was recorded.", "source": REFS},
        {"notion": "Detection", "statement": "No validated detector exists for this attack.", "quote": quote(README, "DET-MCP-001 reused, disabled. No DET-MCP-003.")},
        {"notion": "Control attestation", "statement": "CTRL-MCP-001 decisions are recorded in 3 runs (ALLOW, ALLOW fail-open, DENY).", "source": f"learning/level_1/{LAB}/specimens"},
        {"notion": "Framework mapping", "statement": f"{len(mappings)} educational relationships. None is a compliance assertion.", "source": REFS},
    ]
    remediation = [
        {"id": "RM-1", "action": "Model production downstream credentials and row-level authorization before treating an allowed operation as bounded.", "basis_quote": quote(TM + "threat-catalog.json", t04["gap"]), "owner": "NOT_ASSIGNED", "status": "NOT_STARTED", "authored": True},
        {"id": "RM-2", "action": "Run further garak probes only with approval. This workshop ran none.", "basis_quote": quote(GEV, "Wider probe coverage: NOT MEASURED"), "owner": "NOT_ASSIGNED", "status": "NOT_STARTED", "authored": True},
        {"id": "RM-3", "action": "Obtain a host-verifier receipt for these runs before calling them Splunk-verified.", "basis_quote": quote(DETMAN, "No verifier receipt exists for any run in this bundle, so nothing here is marked verified."), "owner": "NOT_ASSIGNED", "status": "NOT_STARTED", "authored": True},
    ]
    steps = [
        {"id": "learn", "title": "Learn", "instruction": "Read the security question this journey is about, in the lab's own words.", "next_action": "Continue to Practice"},
        {"id": "practice", "title": "Practice", "instruction": "Predict, reveal and compare the three recorded runs in the existing LAB-MCP-003 workbench. This step reuses it; nothing is duplicated here.", "next_action": "Continue to Evaluate"},
        {"id": "evaluate", "title": "Evaluate", "instruction": "Read five recorded observations and decide what kind of evidence each one is.", "next_action": "Continue to Assess Risk"},
        {"id": "risk", "title": "Assess Risk", "instruction": "Read the risk as the sources support it. Impact and likelihood are not assessed. Choose the statements the evidence supports.", "next_action": "Continue to Map Controls"},
        {"id": "controls", "title": "Map Controls", "instruction": "See the control, its recorded decisions and the framework relationships, and what none of them establishes.", "next_action": "Continue to Prove"},
        {"id": "prove", "title": "Prove", "instruction": "Check where every fact comes from, what is not verified and what remains open.", "next_action": "Return to the workshop home"},
    ]
    j = {"schema": M.SCHEMA, "id": "mcp-unauthorized-scope", "title": "An agent asks for a tool at a scope it was not granted", "lab_id": LAB, "generated_from": "committed sources only",
         "learn": {"question": quote(README, "LAB-MCP-003 asks: May this agent call this tool at this requested scope?"),
                   "lines": [quote(README, "a granted MCP tool is not authorized at every scope the tool can name."), quote(README, "The tool is authorized. The excessive scope is not.")]},
         "steps": steps, "observations": obs, "assessments": assessments, "risks": [risk], "controls": controls, "mappings": mappings, "coverage": coverage,
         "coverage_note": "These are four separate facts. They are never added into one number or percentage.",
         "mapping_meaning": {"question": "What does the relationship column in the table mean?", "options": [rule, "A certified compliance mapping.", "Proof that the control passed an audit."], "answer": [rule], "quote": quote(REFS, rule)},
         "upstream_tags": {"note": "Tags the garak report itself carries. They are upstream metadata, not AgentSec mappings.", "tags": J(GARAK + "normalized/evaluations.json")["records"][0]["framework_mappings"]},
         "compliance_assertions": [], "compliance_statement": "No compliance assertion is made. No assessment against any framework exists, and a relationship in the table is an educational link, not certification.",
         "remediation": remediation, "limitations": ["This journey shows one scenario from one lab, built only from committed evidence.", "Nothing here was run, searched or verified by this page.", "No verifier receipt applies to any run shown, so every observation is NOT_VERIFIED."]}
    errs = M.validate(j, refs)
    if errs:
        raise SystemExit("assurance journey is not valid:\n  " + "\n  ".join(errs))
    return j


def main() -> None:
    data = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        raise SystemExit(0 if OUT.read_text(encoding="utf-8") == data else "the committed journey differs from its sources; re-run scripts/export_assurance.py")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(data, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(data)} bytes")


if __name__ == "__main__":
    main()
