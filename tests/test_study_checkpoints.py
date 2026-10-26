"""Increment 11E: the Privacy, Threat Modeling and Garak study checkpoints.

Each lab's options and answers are exported from committed sources. These tests re-read the sources and recompute every answer separately from the exporter
and the UI. Garak is a recorded result and is never re-run; the privacy data map is cross-checked against the existing privacy runtime constants, without
running any pipeline.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
DATA = json.loads((ROOT / "academy-ui" / "src" / "content" / "curriculum.json").read_text(encoding="utf-8"))
LABS = {l["id"]: l for l in DATA["labs"]}
FILES = ROOT / "academy-ui" / "src" / "content" / "recorded"
TM, PRIV, GARAK = "LAB-THREAT-MODELING-001", "LAB-PRIVACY-DATA-GOVERNANCE-001", "LAB-EXTERNAL-EVALUATION-GARAK"
STUDY = [TM, PRIV, GARAK]
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
EV = "docs/p1a-evidence/garak-aeb05718-1364-4143-8248-71dd6f27b07b/"


def cp(lab):
    return json.loads((FILES / LABS[lab]["explainer"]["recorded_ref"]["file"]).read_text(encoding="utf-8"))


def answers(lab):
    return {q["id"]: q for s in cp(lab)["spec"]["steps"] for q in s["questions"]}


@pytest.mark.parametrize("lab", STUDY)
def test_each_lab_has_a_study_checkpoint_and_its_files_hash_to_the_committed_sources(lab):
    d = cp(lab)
    assert LABS[lab]["explainer"]["recorded_ref"]["kind"] == "checkpoint" and d["spec"]["kind"] == "study"
    assert d["files"] and d["packet_file"] == d["files"][0]["file"]
    for f in d["files"]:
        assert hashlib.sha256((ROOT / f["file"]).read_bytes()).hexdigest() == f["sha256"], f["file"]


@pytest.mark.parametrize("lab", STUDY)
def test_every_question_is_well_formed_and_every_quote_is_in_its_file(lab):
    for q in answers(lab).values():
        assert set(q["answer"]) <= set(q["candidates"]) and q["answer"] and len(q["candidates"]) >= 2, q["id"]
        assert q["mode"] != "single" or len(q["answer"]) == 1, q["id"]
        if "quote" in q:
            assert EXP.clean(q["quote"]["text"]) in EXP.source_text(ROOT / q["quote"]["file"]), q["id"]
    spec = cp(lab)["spec"]
    for x in spec.get("documented", []) + spec["limits"]:
        assert EXP.clean(x["text"]) in EXP.source_text(ROOT / x["file"]), x["text"]


@pytest.mark.parametrize("lab", STUDY)
def test_the_prove_view_says_not_verified_and_never_claims_a_live_or_splunk_verified_result(lab):
    spec = cp(lab)["spec"]
    assert "no receipt" in spec["verification"].lower() or "no splunk verifier receipt" in spec["verification"].lower()
    blob = json.dumps(spec).lower()
    assert "splunk-verified" not in blob and "splunk_verified" not in blob
    assert spec["label"].endswith(("NOT AN ASSESSMENT", "NOT A LIVE RUN", "NOT RE-RUN"))


def test_threat_modeling_answers_match_the_committed_architecture_and_catalog():
    arch, cat = J("learning/level_1/LAB-THREAT-MODELING-001/architecture.json"), J("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json")
    t = {x["id"]: x for x in cat["threats"]}
    a = answers(TM)
    assert set(a["a1"]["answer"]) == set(t["TM-T04"]["assets"]) == {"AST-AUTHORITY", "AST-CUSTOMER", "AST-POLICY"}
    assert set(a["a2"]["answer"]) == {x["id"] for x in arch["assets"] if x["category"] == "DATA"}
    assert set(a["a3"]["answer"]) == set(t["TM-T06"]["assets"])
    assert set(a["b1"]["answer"]) == set(t["TM-T03"]["boundaries"])
    assert a["b2"]["answer"] == [b["id"] for b in arch["trust_boundaries"] if "CMP-MCP" in b["between"]] == ["TB-04"]
    assert set(a["b3"]["answer"]) == set(t["TM-T06"]["boundaries"])
    assert set(a["t1"]["answer"]) == {k for k, v in t.items() if "AST-AUTHORITY" in v["assets"]}
    assert set(a["t2"]["answer"]) == {k for k, v in t.items() if "TB-06" in v["boundaries"]}
    assert set(a["m1"]["answer"]) == {c["id"] for c in t["TM-T05"]["existing_controls"]}
    assert set(a["m2"]["answer"]) == {k for k, v in t.items() if not any("PREVENTIVE" in c["class"] for c in v["existing_controls"])} == {"TM-T08", "TM-T09"}
    assert set(a["r1"]["answer"]) == {k for k, v in t.items() if "NOT PROVEN" in v["gap"]}
    assert set(a["r2"]["answer"]) == {k for k, v in t.items() if "NOT MODELED" in v["gap"]}
    for q in a.values():   # every option is a real id from the sources
        assert all(c.startswith(("AST-", "TB-", "TM-", "CTRL-", "MEMORY-", "ALLOW-", "BOUNDED-", "CATALOG-", "EXTERNAL-", "EVIDENCE-", "INV-", "SPLUNK")) for c in q["candidates"]), q["id"]


def test_threat_modeling_does_not_claim_an_assessment_or_a_risk_score():
    spec = cp(TM)["spec"]
    blob = json.dumps(spec).lower()
    assert "reasoning prompts / not a completed threat model" in blob and "numerical risk score" in blob
    assert "risk score:" not in blob and "severity" not in blob and "likelihood" not in blob


def test_privacy_data_map_agrees_with_the_existing_privacy_runtime_constants():
    from agentsec.privacy.pipeline import FULL_RECORD, MINIMIZED_RECORD, REQUIRED_FIELDS, TASK_PURPOSE
    dm = J("learning/level_1/LAB-PRIVACY-DATA-GOVERNANCE-001/data-map.json")
    assert dm["full_record"] == dict(FULL_RECORD) and dm["minimized_record"] == dict(MINIMIZED_RECORD)
    assert set(dm["required_fields"]) == set(REQUIRED_FIELDS) and dm["task"] == TASK_PURPOSE


def test_privacy_answers_are_recomputed_from_the_data_map_and_the_documents():
    dm = J("learning/level_1/LAB-PRIVACY-DATA-GOVERNANCE-001/data-map.json")
    a = answers(PRIV)
    assert set(a["p1"]["answer"]) == {c["field"] for c in dm["classification"] if c["required"]} == set(dm["required_fields"])
    assert set(a["p2"]["answer"]) == set(dm["full_record"]) - set(dm["minimized_record"]) == {"email", "postal_address", "account_balance_band", "internal_case_note"}
    assert set(a["p3"]["answer"]) == {c["field"] for c in dm["classification"] if "PERSONAL" in c["category"]}
    assert set(a["n1"]["answer"]) == {s["stage"] for s in dm["lifecycle"] if "NOT MODELED" in s["status"]}
    assert a["z1"]["answer"] == a["z2"]["answer"] == ["ALLOW"] and a["z3"]["answer"] == ["one"]
    lp = EXP.source_text(ROOT / "docs/reviews/logic-proof-privacy-data-governance-2026-09-25.md")
    assert "CTRL-MCP-001 returns ALLOW / tool_granted" in lp and "each handler invocation count is one" in lp


def test_privacy_comparison_is_the_two_records_unedited():
    d, dm = cp(PRIV), J("learning/level_1/LAB-PRIVACY-DATA-GOVERNANCE-001/data-map.json")
    assert d["packet"]["data_map"] == dm
    c = d["spec"]["compare"]
    assert c["left"]["path"] == "data_map.full_record" and c["right"]["path"] == "data_map.minimized_record"


def test_privacy_never_claims_deletion_retention_breach_or_compliance_was_measured():
    spec = cp(PRIV)["spec"]
    lim = " ".join(x["text"] for x in spec["limits"]).lower()
    for w in ("retention", "deletion", "breach", "legal advice", "compliance validation"):
        assert w in lim, w
    assert "re-verified here" in spec["verification"] and "ran nothing" in spec["verification"]


def test_garak_numbers_are_recomputed_from_the_recorded_report_and_the_hash_is_the_manifests():
    man = J(EV + "manifest.json")
    raw = (ROOT / EV / "raw/garak-report.jsonl").read_bytes()
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == man["provenance"]["raw_evidence_sha256"]
    rows = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
    ev = [r for r in rows if r["entry_type"] == "eval"]
    a = answers(GARAK)
    assert a["g1"]["answer"] == [str(len({man["target"]["model"]}))] == ["1"]
    assert a["g2"]["answer"] == [str(len({r["probe"] for r in ev}))] == ["1"]
    assert a["g3"]["answer"] == [str(ev[0]["total_evaluated"])] and a["g4"]["answer"] == [str(ev[0]["fails"])]
    assert (ev[0]["passed"], ev[0]["fails"], ev[0]["total_evaluated"]) == (1, 0, 1)
    assert a["s2"]["answer"] == a["s3"]["answer"] == ["no"]


def test_garak_packet_keeps_the_original_rows_and_the_model_response_verbatim():
    d = cp(GARAK)
    rows = [json.loads(l) for l in (ROOT / EV / "raw/garak-report.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    for t in ("init", "eval", "probe_summary", "completion"):
        assert d["packet"]["raw"][t] == [r for r in rows if r["entry_type"] == t], t
    att = [r for r in rows if r["entry_type"] == "attempt"]
    assert [x["outputs"] for x in d["packet"]["raw"]["attempt"]] == [x["outputs"] for x in att]
    assert d["packet"]["manifest"] == J(EV + "manifest.json") and d["packet"]["normalized"] == J(EV + "normalized/evaluations.json")
    names = {f["name"] for f in d["files"]}
    assert names == {"manifest", "normalized", "raw"}
    assert {f["sha256"] for f in d["files"] if f["name"] == "raw"} == {hashlib.sha256((ROOT / EV / "raw/garak-report.jsonl").read_bytes()).hexdigest()}


def test_garak_states_one_probe_one_model_is_not_a_comprehensive_evaluation():
    spec = cp(GARAK)["spec"]
    lim = " ".join(x["text"] for x in spec["limits"])
    assert "One local model, one probe, one generation, and one detector." in lim and "narrow" in lim and "NOT PROVEN" in lim and "NOT MEASURED" in lim
    ex = LABS[GARAK]["explainer"]
    blob = json.dumps(ex).lower()
    assert "not a comprehensive" in blob and "one probe" in blob
    assert "re-run" in spec["label"].lower() and "not re-run here" in spec["verification"]


def test_no_study_lab_adds_a_run_or_a_launch_route():
    for lab in STUDY:
        assert LABS[lab]["availability"] != "guided" and not LABS[lab].get("native_route")
