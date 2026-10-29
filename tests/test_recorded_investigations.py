"""Increment 11C recorded-evidence labs: every event, scan record and answer shown to a learner comes from a committed pack or a lab document.

Evidence is loaded on demand from academy-ui/src/content/recorded/<LAB>.json. These tests re-read the packs and the lab documents and fail on any
difference, any invented event and any answer that the packs do not support. The answers are recomputed here independently of the UI code.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
DATA = json.loads((ROOT / "academy-ui" / "src" / "content" / "curriculum.json").read_text(encoding="utf-8"))
LABS = {l["id"]: l for l in DATA["labs"]}
FILES = ROOT / "academy-ui" / "src" / "content" / "recorded"
DECISION = ("LAB-MCP-006", "LAB-MCP-CATALOG")
INVESTIGATION = ("LAB-SCANNER-RUNTIME-EVIDENCE", "LAB-BLUE-TEAM-INCIDENT-001", "LAB-MULTI-STAGE-INCIDENT-001", "LAB-ADVANCED-CAPSTONE-MASTERY-001")
BLOCKED = ()   # none: the three Splunk labs became recorded experiences in 11G
SPLUNK = ("LAB-SPLUNK-DEFENDER-BRIDGE", "LAB-DETECTION-ENGINEERING", "LAB-AGENT-IDENTITY-NHI")
CHECKPOINT = ("LAB-A2A-AUTH-DELEGATION", "LAB-ASSET-INVENTORY", "LAB-CHANGE-BOUNDS", "LAB-CODE-AGENT-BOUNDS", "LAB-COMPONENT-PROVENANCE", "LAB-CREDENTIAL-LIFETIME", "LAB-HITL-APPROVAL", "LAB-RAG-PURPOSE", "LAB-RECALL-ISOLATION")
STUDY = ("LAB-EXTERNAL-EVALUATION-GARAK", "LAB-PRIVACY-DATA-GOVERNANCE-001", "LAB-THREAT-MODELING-001")
EXPECTED = {
    "LAB-SCANNER-RUNTIME-EVIDENCE": {"s1": "same", "s2": "same", "s3": "0", "s4": "same", "s5": "DENY", "s6": "yes"},
    "LAB-BLUE-TEAM-INCIDENT-001": {"b1": "ALLOW", "b2": "yes", "b3": "DENY", "b4": "no", "b5": "same", "b6": "same"},
    "LAB-MULTI-STAGE-INCIDENT-001": {"m1": "OBSERVE", "m2": "ALLOW", "m3": "yes", "m4": "DENY", "m5": "no", "m6": "NONE RECORDED", "m7": "same"},
    "LAB-ADVANCED-CAPSTONE-MASTERY-001": {"c1": "OBSERVE", "c2": "DENY", "c3": "extract_full_policy", "c4": "summarize_lending_policy", "c5": "yes"},
}


def rec(lab):
    return json.loads((FILES / LABS[lab]["explainer"]["recorded_ref"]["file"]).read_text(encoding="utf-8"))


def pack_events(lab, run_id):
    return [json.loads(l) for l in (ROOT / "learning/level_1" / lab / "specimens" / f"{run_id}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def all_runs(lab):
    d = rec(lab)
    return d["runs"] if d["kind"] == "decision" else [r for s in d["scenarios"] for r in s["runs"]]


@pytest.mark.parametrize("lab", DECISION + INVESTIGATION)
def test_evidence_is_loaded_on_demand_not_embedded_in_the_main_bundle_data(lab):
    ex = LABS[lab]["explainer"]
    assert "recorded" not in ex and ex["recorded_ref"]["file"] == f"{lab}.json" and (FILES / f"{lab}.json").is_file()
    assert "agentsec.run.id" not in json.dumps(ex), "no event is embedded in curriculum.json for this lab"
    assert LABS[lab]["availability"] in ("replay", "workbench") and LABS[lab]["native"] is None and (LABS[lab]["integrated"] is False or lab in ("LAB-MCP-006", "LAB-MCP-CATALOG"))


@pytest.mark.parametrize("lab", DECISION + INVESTIGATION)
def test_every_event_equals_the_committed_pack_event_for_event(lab):
    for run in all_runs(lab):
        pack = ROOT / run["pack"]
        raw = pack.read_bytes()
        assert pack.parent == ROOT / "learning/level_1" / lab / "specimens"
        assert hashlib.sha256(raw).hexdigest() == run["sha256"], "the pack changed after export"
        source = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
        assert len(source) == len(run["events"]) == run["meta"]["event_count"]
        for src, shown in zip(source, run["events"]):
            assert all(src[k] == v for k, v in shown.items()), (run["run_id"], src["agentsec.sequence"])
            dropped = set(src) - set(shown)
            assert dropped <= set(EXP.RUN_CONSTANT) and all(src[k] == source[0][k] for k in dropped)
        assert all(e.get("agentsec.run.id", run["run_id"]) == run["run_id"] for e in source)
        for mk, sk in EXP.RUN_META.items():
            assert run["meta"][mk] == source[0].get(sk)


@pytest.mark.parametrize("lab", DECISION)
def test_decision_labs_match_what_their_readmes_document(lab):
    runs = {r["role"]: r for r in rec(lab)["runs"]}
    def dec(role):
        e = runs[role]["events"][runs[role]["decisive"] - 1]
        return e["agentsec.control.decision"], e["agentsec.control.reason"]
    def started(role, tool):
        return sum(1 for e in runs[role]["events"] if e["event.name"] == "agentsec.mcp.started" and e["agentsec.operation.executed"] is True and e.get("gen_ai.tool.name") == tool)
    for r in runs.values():
        doc = EXP.clean((ROOT / r["documented_as"]["source"]).read_text(encoding="utf-8"))
        assert r["documented_as"]["text"] in doc and r["run_id"] in r["documented_as"]["text"] and r["role"] in r["documented_as"]["text"]
        assert r["meta"]["mode"] == r["role"] and r["events"][r["decisive"] - 1]["event.name"] == "agentsec.control.decision"
    if lab == "LAB-MCP-006":
        assert dec("BASELINE") == ("ALLOW", "delegation_granted") and dec("RETEST") == ("DENY", "delegated_authority_not_granted")
        assert dec("ATTACK") == ("ALLOW", "vulnerable_profile_fail_open:ambient_deputy_authority")
        assert (started("BASELINE", "lookup_policy"), started("BASELINE", "lookup_customer_tier"), started("ATTACK", "lookup_customer_tier"), started("RETEST", "lookup_customer_tier")) == (1, 0, 1, 0)
    else:
        assert dec("BASELINE") == ("OBSERVE", "metadata_is_data") and dec("RETEST") == ("DENY", "tool_not_granted")
        assert dec("ATTACK") == ("ALLOW", "vulnerable_profile_fail_open:metadata_derived_authority")
        assert (started("BASELINE", "lookup_customer_tier"), started("ATTACK", "lookup_customer_tier"), started("RETEST", "lookup_customer_tier"), started("RETEST", "lookup_policy")) == (0, 1, 0, 1)


def independent_answer(lab, ev):
    """The same questions, answered from the raw packs with separate code."""
    d = rec(lab)
    def run(sc, st):
        return next(r for s in d["scenarios"] if s["id"] == sc for r in s["runs"] if r["stage"] == st)
    def event(ref):
        events = pack_events(lab, run(ref["scenario"], ref["stage"])["run_id"])
        w = ref.get("where", {})
        hits = [e for e in events if (e.get("agentsec.control.id") == w["control"] and e["event.name"] == "agentsec.control.decision" if "control" in w else e["event.name"] == w["event"] if "event" in w else True)]
        return (hits[0] if w.get("nth") == "first" else hits[-1]) if hits else None
    def value(ref):
        if ref["src"] == "run":
            return run(ref["scenario"], ref["stage"])["run_id"]
        if ref["src"] == "external":
            pack = ROOT / "learning/level_1" / lab / "specimens/scanner" / f"{ref['scan']}.jsonl"
            for l in pack.read_text(encoding="utf-8").splitlines():
                v = json.loads(json.loads(l)["event"])
                for k in ref["path"]:
                    v = v.get(k) if isinstance(v, dict) else None
                if v is not None:
                    return str(v)
            return None
        e = event(ref)
        v = None if e is None or ref["field"] not in e else str(e[ref["field"]])
        if v is not None and "json" in ref:
            m = re.search(r'"' + ref["json"] + r'":\s*"([^"]*)"', v)     # previews are cut at 200 characters, so read the text
            v = m.group(1) if m else None
        return v
    if ev["kind"] == "value":
        return value(ev["ref"]) or "NONE RECORDED"
    if ev["kind"] == "equal":
        a, b = value(ev["a"]), value(ev["b"])
        return "not comparable" if a is None or b is None else "same" if a == b else "different"
    events = pack_events(lab, run(ev["scenario"], ev["stage"])["run_id"])
    return "yes" if any(e["event.name"] == "agentsec.mcp.started" and e["agentsec.operation.executed"] is True and e.get("gen_ai.tool.name") == ev["tool"] for e in events) else "no"


@pytest.mark.parametrize("lab", INVESTIGATION)
def test_answers_are_computable_from_the_packs_and_match_the_documents(lab):
    d = rec(lab)
    assert {q["id"] for q in d["questions"]} == set(EXPECTED[lab])
    for q in d["questions"]:
        got = independent_answer(lab, q["eval"])
        assert got == EXPECTED[lab][q["id"]], (q["id"], got)
        assert got in q["choices"], (q["id"], "the computed answer must be one of the choices offered")
        assert EXP.clean(q["quote"]["text"]) in EXP.clean((ROOT / q["quote"]["file"]).read_text(encoding="utf-8")), q["id"]


def test_capstone_answers_agree_with_the_labs_own_recorded_figures():
    inc = json.loads((ROOT / "learning/level_1/LAB-ADVANCED-CAPSTONE-MASTERY-001/incident.json").read_text(encoding="utf-8"))["canonical_runs"]
    d = rec("LAB-ADVANCED-CAPSTONE-MASTERY-001")
    for s in d["scenarios"]:
        assert s["runs"][0]["run_id"] == inc[s["id"]]["run_id"]
        goal = next(e for e in s["runs"][0]["events"] if e.get("agentsec.control.id") == "CTRL-GOAL-INTEGRITY-001")
        assert goal["agentsec.control.decision"] == inc[s["id"]]["goal_decision"]
        if s["id"] == "attack":     # the lab's document says "overlay"; the pack records the full fail-open reason code
            assert inc["attack"]["goal_reason"] == "overlay" and goal["agentsec.control.reason"].startswith("vulnerable_profile_fail_open:")
        else:
            assert goal["agentsec.control.reason"] == inc[s["id"]]["goal_reason"]
        events = s["runs"][0]["events"]
        started = [e for e in events if e["event.name"] == "agentsec.mcp.started" and e["gen_ai.tool.name"] == "lookup_policy"]
        effective = re.search(r'"effective_action":\s*"([^"]*)"', next(e for e in events if e.get("agentsec.control.id") == "CTRL-MCP-001")["agentsec.content.preview"]).group(1)
        assert effective == inc[s["id"]]["effective_action"] and len(started) == 1
        # the lab counts a handler as in-task or wrong-goal by the action it served, not by the tool name
        assert int(effective == "summarize_lending_policy") == inc[s["id"]]["in_task_handler"] and int(effective != "summarize_lending_policy") == inc[s["id"]]["wrong_goal_handler"]


def test_scanner_records_are_the_packs_unchanged_and_join_the_runtime_by_description_hash():
    d = rec("LAB-SCANNER-RUNTIME-EVIDENCE")
    assert {x["scan_id"] for x in d["external"]} == {"7ae3ea64-4e7a-40fe-943f-3e582bce5ee8", "b3061c4e-7a81-445c-8fd8-3108dd14c419"}
    for x in d["external"]:
        raw = (ROOT / x["pack"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == x["sha256"]
        assert x["records"] == [json.loads(json.loads(l)["event"]) for l in raw.decode("utf-8").splitlines() if l.strip()]
    runtime = {s["id"]: next(e["agentsec.content.hash"] for e in s["runs"][0]["events"] if e.get("agentsec.control.id") == "CTRL-MCP-METADATA-001") for s in d["scenarios"]}
    desc = {x["records"][0]["artifact"]["fixture"]: x["records"][0]["artifact"]["description_sha256"] for x in d["external"]}
    assert runtime["attack"] == runtime["retest"] == desc["MALICIOUS"] and runtime["baseline"] == desc["NORMAL"] != desc["MALICIOUS"]
    assert all("agentsec.run.id" not in r for x in d["external"] for r in x["records"]), "the scanner records no run id: the join is by hash only"


@pytest.mark.parametrize("lab", ("LAB-BLUE-TEAM-INCIDENT-001", "LAB-MULTI-STAGE-INCIDENT-001"))
def test_incident_scenarios_use_the_labs_canonical_run_ids_in_stage_order(lab):
    canon = json.loads((ROOT / "learning/level_1" / lab / ("investigations.json" if "BLUE" in lab else "incident.json")).read_text(encoding="utf-8"))["canonical_runs"]
    for s in rec(lab)["scenarios"]:
        if s["id"] in ("attack", "retest", "baseline"):
            assert [r["stage"] for r in s["runs"]] == ["retrieve", "write", "recall"]
            assert [r["run_id"] for r in s["runs"]] == [canon[s["id"]][k] for k in ("retrieve", "write", "recall")]
        else:
            assert s["runs"][0]["run_id"] == canon["benign_comparison"]


@pytest.mark.parametrize("lab", INVESTIGATION)
def test_blocks_graph_and_control_analysis_are_the_labs_documents_unchanged(lab):
    d = rec(lab)
    for b in d["blocks"]:
        src, _, frag = b["source"].partition("#")
        text = EXP.clean((ROOT / src).read_text(encoding="utf-8"))
        if src.endswith(".md"):
            assert all(EXP.clean(i) in text for i in b["items"]), b["title"]
        else:
            doc = json.loads((ROOT / src).read_text(encoding="utf-8"))
            for part in frag.split("."):
                doc = doc[part]
            def leaves(v):
                return [v] if isinstance(v, str) else [x for c in (v.values() if isinstance(v, dict) else v) for x in leaves(c)]
            joined = " ".join(b["items"])
            assert all(EXP.clean(x) in joined for x in leaves(doc)), b["title"]
    for key in ("graph", "control_analysis"):
        if key in d:
            src = json.loads((ROOT / d[key]["source"]).read_text(encoding="utf-8"))
            assert all(d[key][k] == v for k, v in src.items() if k in d[key]) and (key != "graph" or (d[key]["nodes"] == src["nodes"] and d[key]["edges"] == src["edges"]))
    for q in d["spl"]:
        assert q["text"] == (ROOT / q["source"]).read_text(encoding="utf-8").strip()


def test_blocked_labs_have_no_recorded_experience_and_other_labs_are_unchanged():
    for lab in BLOCKED:
        ex = LABS[lab]["explainer"]
        assert ex is None or not ({"recorded", "recorded_ref"} & set(ex)), lab
        assert LABS[lab]["availability"] in ("replay", "workbench")
    with_rec = sorted(l["id"] for l in DATA["labs"] if l["explainer"] and ({"recorded", "recorded_ref"} & set(l["explainer"])))
    assert with_rec == sorted(("LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005") + DECISION + INVESTIGATION + CHECKPOINT + STUDY + SPLUNK)


def test_new_components_make_no_launch_network_or_verification_claim():
    ui = ROOT / "academy-ui" / "src" / "workbench"
    code = "".join((ui / n).read_text(encoding="utf-8") for n in ("InvestigationWorkbench.tsx", "investigation.ts", "RecordedLoader.tsx"))
    assert "RECORDED — NOT RE-RUN" in code or "RECORDED_BADGE" in code
    for forbidden in ("launchLab", "fetch(", "/api/", "SPLUNK-VERIFIED", "splunk_verified", "XMLHttpRequest"):
        assert forbidden not in code, forbidden
