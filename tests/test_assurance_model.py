"""Increment 12A: the assurance evidence model, its validator and the first source-backed journey.

The journey is built by scripts/export_assurance.py from committed packs, reports, the threat catalog and the framework reference file. These tests recompute
every fact from those sources with separate code and prove the validator refuses scores, invented owners, compliance claims and evidence-free judgments.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as M  # noqa: E402

_s = importlib.util.spec_from_file_location("export_assurance", ROOT / "scripts" / "export_assurance.py")
X = importlib.util.module_from_spec(_s)
_s.loader.exec_module(X)
JOURNEY_FILE = ROOT / "academy-ui/src/content/assurance/mcp-unauthorized-scope.json"
sha = lambda b: hashlib.sha256(b).hexdigest()
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
REFS = J("learning/academy/framework_refs.json")


@pytest.fixture
def journey():
    return json.loads(JOURNEY_FILE.read_text(encoding="utf-8"))


def test_the_committed_journey_is_valid_and_is_exactly_what_its_sources_produce(journey):
    assert M.validate(journey, REFS) == []
    assert JOURNEY_FILE.read_text(encoding="utf-8") == json.dumps(X.build(), ensure_ascii=False, indent=2) + "\n"


@pytest.mark.parametrize("mutate,message", [
    (lambda j: j["assessments"][0].update(confidence_score=0.9), "score"),
    (lambda j: j["risks"][0].update(severity_rating="high"), "rating"),
    (lambda j: j["risks"][0]["impact"].update(percent=40), "percentage"),
    (lambda j: j["assessments"][0].update(about=[]), "never passing evidence"),
    (lambda j: j["assessments"][0].update(about=["O-NOPE"]), "unknown observation"),
    (lambda j: j.update(compliance_assertions=[{"framework": "OWASP", "claim": "compliant"}]), "compliance_assertions must be empty"),
    (lambda j: j.update(compliance_statement=""), "compliance_statement"),
    (lambda j: j["mappings"][0].update(id="AML.T9999"), "not in framework_refs"),
    (lambda j: j["mappings"][0].update(claims_compliance=True), "never claims compliance"),
    (lambda j: j["mappings"][0].update(limits="none"), "differs from framework_refs"),
    (lambda j: j["observations"][0]["sources"][0].update(sha256="0" * 64), "does not match"),
    (lambda j: j["observations"][0]["verification"].update(status="VERIFIED"), "needs a receipt"),
    (lambda j: j["observations"][0].update(limitations=[]), "limitations"),
    (lambda j: j["observations"][0].update(evidence_class="MEASURED"), "unknown evidence class"),
    (lambda j: j["remediation"][0].update(owner="Dana"), "owner may not be invented"),
    (lambda j: j["remediation"][0].pop("basis_quote"), "source line"),
    (lambda j: j["risks"][0]["impact"].update(status="SUPPORTED"), "needs a basis"),
    (lambda j: j["steps"].reverse(), "steps must be"),
])
def test_the_validator_refuses_unsupported_claims(journey, mutate, message):
    j = copy.deepcopy(journey)
    mutate(j)
    errs = M.validate(j, REFS)
    assert errs and any(message in e for e in errs), (message, errs)


def test_missing_evidence_is_never_passing_evidence(journey):
    j = copy.deepcopy(journey)
    j["assessments"].append({"id": "A-X", "statement": "The control passes.", "status": "SUPPORTED", "about": [], "basis": "none", "limitations": []})
    assert any("missing evidence" in e for e in M.validate(j, REFS))
    j = copy.deepcopy(journey)
    assert {a["status"] for a in j["assessments"] if not a["about"]} == {"NOT_SUPPORTED"}
    assert j["risks"][0]["impact"]["status"] == j["risks"][0]["likelihood"]["status"] == "NOT_ASSESSED"


def test_four_layers_are_separate_and_no_number_or_percentage_summarises_them(journey):
    assert {"observations", "assessments", "mappings", "compliance_assertions"} <= set(journey)
    assert journey["compliance_assertions"] == []
    text = json.dumps(journey)
    assert not re.search(r"\d\s*%|\d\s*percent|pass rate|compliance score|risk score", text, re.I)
    assert "never added into one number" in journey["coverage_note"]
    assert all(m["claims_compliance"] is False for m in journey["mappings"])


def test_runtime_observations_are_recomputed_from_the_committed_packs(journey):
    for mode, rid in X.RUNS.items():
        pack = ROOT / f"learning/level_1/LAB-MCP-003/specimens/{rid}.jsonl"
        ev = [json.loads(l) for l in pack.read_text(encoding="utf-8").splitlines() if l.strip()]
        d = next(e for e in ev if e["event.name"] == "agentsec.control.decision")
        started = any(e["event.name"] == "agentsec.mcp.started" and e.get("agentsec.operation.executed") is True for e in ev)
        o = next(x for x in journey["observations"] if x["id"] == f"O-{mode}")
        assert o["facts"] == {"run_id": rid, "mode": mode, "profile": o["facts"]["profile"], "control": d["agentsec.control.id"], "decision": d["agentsec.control.decision"], "reason": d["agentsec.control.reason"],
                              "tool": d["gen_ai.tool.name"], "requested_scope": d["agentsec.mcp.requested_scope"], "handler_started": started, "events_in_pack": len(ev)}
        assert o["sources"][0]["sha256"] == sha(pack.read_bytes()) and o["verification"] == {"status": "NOT_VERIFIED", "receipt": None}
    f = {o["id"]: o["facts"] for o in journey["observations"]}
    assert (f["O-BASELINE"]["decision"], f["O-ATTACK"]["decision"], f["O-RETEST"]["decision"]) == ("ALLOW", "ALLOW", "DENY")
    assert f["O-ATTACK"]["tool"] == f["O-RETEST"]["tool"] and f["O-ATTACK"]["requested_scope"] == f["O-RETEST"]["requested_scope"]
    assert [f[f"O-{m}"]["handler_started"] for m in X.RUNS] == [True, True, False]


def test_splunk_and_garak_observations_match_their_committed_records(journey):
    coll = J("docs/splunk-evidence-11f/collection.json")["index_inventory"]["runs"]
    o = next(x for x in journey["observations"] if x["id"] == "O-SPLUNK")
    for row in o["facts"]["runs"]:
        r = next(x for x in coll if x["run_id"] == row["run_id"])
        assert row["indexed_rows"] == r["indexed_rows"] == r["distinct_raw"] == r["match"]["exact_raw_bytes"] == r["match"]["pack_events"] == row["pack_events"]
    assert o["sources"][0]["sha256"] == sha((ROOT / "docs/splunk-evidence-11f/collection.json").read_bytes()) and o["evidence_class"] == "RECORDED"
    g = next(x for x in journey["observations"] if x["id"] == "O-GARAK")
    rows = [json.loads(l) for l in (ROOT / X.GARAK / "raw/garak-report.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    ev = next(r for r in rows if r["entry_type"] == "eval")
    assert (g["facts"]["passed"], g["facts"]["fails"], g["facts"]["total_evaluated"], g["facts"]["probe"]) == (ev["passed"], ev["fails"], ev["total_evaluated"], ev["probe"])
    man = J(X.GARAK + "manifest.json")
    assert g["facts"]["model"] == man["target"]["model"] and all(x in g["limitations"] for x in man["limitations"][:3])
    assert g["kind"] == "evaluation_result" and "not the tool-authorization control" in " ".join(g["limitations"])


def test_risk_assets_threat_and_controls_come_from_the_threat_catalog(journey):
    cat, arch = J(X.TM + "threat-catalog.json"), J(X.TM + "architecture.json")
    t = next(x for x in cat["threats"] if x["id"] == "TM-T04")
    r = journey["risks"][0]
    assert r["gap"] == t["gap"] and r["residual_risk"] == t["residual_risk"] and r["threat"]["id"] == "TM-T04"
    assert {a["id"] for a in r["assets"]} == set(t["assets"]) and all(a in arch["assets"] for a in r["assets"])
    assert [c["id"] for c in journey["controls"]] == [c["id"] for c in t["existing_controls"]]
    assert r["authored"] is True and r["owner"] == "NOT_ASSIGNED"


def test_framework_mappings_are_the_reference_file_entries_for_this_lab(journey):
    want = [x for x in REFS["lab_references"] if x["scope"] == "MCP-003"]
    got = journey["mappings"]
    assert [(m["framework"], m["id"], m["relationship"]) for m in got] == [(w["framework"], w["id"], w["relationship"]) for w in want]
    items = {(i["framework"], i["id"]): i for i in REFS["items"]}
    for m in got:
        i = items[(m["framework"], m["id"])]
        assert (m["name"], m["verification_status"], m["limits"], m["source_url"]) == (i["name"], i["status"], i["limits"], i["source_url"])


def test_every_quote_and_remediation_basis_is_in_its_file(journey):
    ex = X.EXP
    quotes = [journey["learn"]["question"], *journey["learn"]["lines"], journey["mapping_meaning"]["quote"], *[r["basis_quote"] for r in journey["remediation"]], *[c["quote"] for c in journey["coverage"] if "quote" in c]]
    for qt in quotes:
        assert ex.clean(qt["text"]) in ex.source_text(ROOT / qt["file"]), qt
    assert all(r["owner"] == "NOT_ASSIGNED" and r["status"] == "NOT_STARTED" for r in journey["remediation"])
    assert journey["mapping_meaning"]["answer"][0] in journey["mapping_meaning"]["options"] and journey["mapping_meaning"]["answer"][0] == REFS["rule"]


def test_assessments_follow_from_the_observations(journey):
    a = {x["id"]: x for x in journey["assessments"]}
    f = {o["id"]: o["facts"] for o in journey["observations"]}
    assert a["A-RETEST"]["status"] == "SUPPORTED" and (f["O-ATTACK"]["decision"], f["O-RETEST"]["decision"]) == ("ALLOW", "DENY")
    assert a["A-GARAK"]["status"] == "NOT_SUPPORTED" and "not AgentSec runtime tool execution" in a["A-GARAK"]["basis"]
    assert a["A-COMPLIANCE"]["status"] == "NOT_SUPPORTED" and REFS["rule"] in a["A-COMPLIANCE"]["basis"]
    assert a["A-RISK"]["status"] == "NOT_SUPPORTED" and a["A-SPLUNK"]["status"] == "SUPPORTED"


def test_the_journey_is_on_demand_and_the_ui_calls_no_backend():
    main = next((ROOT / "src/agentsec/static/learn/assets").glob("index-*.js")).read_text(encoding="utf-8")
    assert "O-GARAK" not in main and "claims_compliance" not in main and "RM-3" not in main and "A-COMPLIANCE" not in main
    assert (ROOT / "src/agentsec/static/learn/assets").glob("mcp-unauthorized-scope-*.js")
    assert JOURNEY_FILE.stat().st_size < 40_000
    for f in ("pages/Assurance.tsx", "assurance/parts.tsx", "assurance/store.ts"):
        t = (ROOT / "academy-ui/src" / f).read_text(encoding="utf-8")
        for bad in ("fetch(", "XMLHttpRequest", "/api/", "WebSocket"):
            assert bad not in t, (f, bad)
