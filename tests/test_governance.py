"""Phase 12D: Governance Center data, recomputed from the framework reference file, threat catalog, EVAL data and Risk seed by code separate from the exporter."""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import export_governance as X  # noqa: E402
import governance_model as V  # noqa: E402

J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
G = J("academy-ui/src/content/governance/index.json")
REFS = J("learning/academy/framework_refs.json")
CAT = J("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json")
EV = ROOT / "academy-ui/src/content/evals"


def test_data_is_valid_deterministic_and_matches_the_sources():
    assert (ROOT / "academy-ui/src/content/governance/index.json").read_text(encoding="utf-8") == json.dumps(X.build(), ensure_ascii=False, indent=1) + "\n"
    assert V.validate(G, REFS) == []
    for s in G["sources"]:
        assert s["sha256"] == X.A.sha256_file(s["file"])


def test_relationships_are_exactly_the_reference_files_and_attached_to_the_right_threats():
    idx = J("academy-ui/src/content/evals/index.json")
    want: dict[str, set] = {}
    for e in idx["experiments"]:
        for m in json.loads((EV / f"exp-{e['id']}.json").read_text(encoding="utf-8"))["mappings"]:
            thr = json.loads((EV / f"exp-{e['id']}.json").read_text(encoding="utf-8"))["threat"]["id"]
            want.setdefault(thr, set()).add((m["framework"], m["id"], m["relationship"]))
    for t in G["threats"]:
        assert {(r["framework"], r["id"], r["relationship"]) for r in t["relationships"]} == want.get(t["id"], set()) and t["mapped"] == (t["id"] in want)
    refs = {(i["framework"], i["id"]): i for i in REFS["items"]}
    lr = {(x["framework"], x["id"]): x["relationship"] for x in REFS["lab_references"]}
    for r in G["relationships"]:
        i = refs[(r["framework"], r["id"])]
        assert (r["name"], r["verification_status"], r["limits"], r["source_url"]) == (i["name"], i["status"], i["limits"], i["source_url"]) and r["relationship"] == lr[(r["framework"], r["id"])] and r["claims_compliance"] is False
    assert [t["id"] for t in G["threats"] if t["mapped"]] == ["TM-T01", "TM-T04"] and G["gaps"]["unmapped_threats"] == [t["id"] for t in G["threats"] if not t["mapped"]] and len(G["gaps"]["unmapped_threats"]) == 7


def test_controls_come_from_the_catalog_and_evidence_is_only_recorded_decisions():
    ids = [c["id"] for t in CAT["threats"] for c in t["existing_controls"]]
    assert sorted({c["id"] for c in G["controls"]}) == sorted(set(ids)) and len(G["controls"]) == 14
    seed = J("academy-ui/src/content/risk/seed.json")
    for c in G["controls"]:
        rec = [(d["experiment"], d["role"], d["decision"]) for cand in seed["candidates"] for k in cand["controls"] if k["id"] == c["id"] for d in k["recorded_decisions"]]
        assert sorted({(d["experiment"], d["role"], d["decision"]) for d in c["recorded_decisions"]}) == sorted(set(rec))
        assert c["evidence_state"] == ("RECORDED_DECISIONS_EXIST" if rec else "NO_RECORDED_EVIDENCE")
        assert (c["owner"], c["review"], c["attestation"], c["independent_verification"], c["compliance"]) == ("NOT ASSIGNED", "NOT REVIEWED", "NONE RECORDED", "NONE", "NO ASSERTION")
    assert G["gaps"]["owners_assigned"] == 0 and G["gaps"]["controls_attested"] == 0 and G["gaps"]["independently_verified_runs"] == 0


def test_nist_ai_rmf_is_identified_but_not_mapped_or_invented():
    f = next(x for x in G["frameworks"] if x["name"] == "NIST AI RMF")
    assert f["status"] == "NOT_VERIFIED_IN_THIS_REPOSITORY" and f["items"] == [] and f["mapped_relationships"] == 0
    assert "NIST AI RMF" in (ROOT / "docs/FRAMEWORK_MAPPING_MODEL.md").read_text(encoding="utf-8")
    assert not any(r["framework"] == "NIST AI RMF" for r in G["relationships"])
    assert {x["name"] for x in G["frameworks"]} >= {"MITRE ATLAS", "OWASP LLM 2025", "OWASP Agentic 2026"}


def test_no_compliance_score_or_claim_appears_in_the_data():
    text = json.dumps(G)
    assert not re.search(r"\d\s*%|compliance score|certified|compliant\b", text, re.I) or "never claims" in text
    assert [d["name"] for d in G["distinctions"]][-1] == "Formal compliance or certification" and len(G["distinctions"]) == 8


@pytest.mark.parametrize("mutate,message", [
    (lambda g: g["relationships"][0].update(limits="none"), "reference file's"),
    (lambda g: g["relationships"][0].update(relationship="MET"), "PROPOSED or RELATED"),
    (lambda g: g["relationships"][0].update(claims_compliance=True), "never claims compliance"),
    (lambda g: g["controls"][0].update(owner="Dana"), "may not be invented"),
    (lambda g: g["controls"][0].update(attestation="ATTESTED"), "may not be invented"),
    (lambda g: g["controls"][0].update(compliance="COMPLIANT"), "may not be invented"),
    (lambda g: g["controls"][0].update(effectiveness="high"), "not allowed"),
    (lambda g: next(c for c in g["controls"] if c["recorded_decisions"]).update(evidence_state="NO_RECORDED_EVIDENCE"), "does not follow"),
    (lambda g: g["threats"][0].update(mapped=False), "mapped does not follow"),
    (lambda g: g["threats"][1].update(relationships=[g["relationships"][0]]), "mapped does not follow"),
    (lambda g: g["frameworks"][-1]["items"].append({"id": "GOVERN"}), "unverified framework"),
    (lambda g: g.update(score=0.7), "not allowed"),
])
def test_validator_refuses_unsupported_governance_claims(mutate, message):
    g = copy.deepcopy(G)
    mutate(g)
    assert any(message in e for e in V.validate(g, REFS)), V.validate(g, REFS)


def test_governance_is_on_demand_and_calls_no_backend():
    assets = ROOT / "src/agentsec/static/learn/assets"
    main = next(assets.glob("index-*.js")).read_text(encoding="utf-8")
    assert "NOT_VERIFIED_IN_THIS_REPOSITORY" not in main and "agentsec.governance_export.v1" not in main
    assert "agentsec.governance_export.v1" in next(assets.glob("Governance-*.js")).read_text(encoding="utf-8")
    t = (ROOT / "academy-ui/src/pages/Governance.tsx").read_text(encoding="utf-8")
    for bad in ("fetch(", "XMLHttpRequest", "/api/", "WebSocket"):
        assert bad not in t, bad
