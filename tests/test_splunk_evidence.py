"""Increment 11F: the Splunk search-result evidence bundle for the three evidence-blocked labs.

The bundle is data collected once from the live index with read-only searches. These tests re-read the committed SPL, packs and documents and check the bundle
against them. They never contact Splunk. Nothing in the bundle is marked verified: no verifier receipt exists for any run it depends on.
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
LABS = ("LAB-SPLUNK-DEFENDER-BRIDGE", "LAB-DETECTION-ENGINEERING", "LAB-AGENT-IDENTITY-NHI")
EXPECTED_SEARCHES = {LABS[0]: 10, LABS[1]: 3, LABS[2]: 3}
sha = lambda b: hashlib.sha256(b).hexdigest()
COLL = ROOT / "docs/splunk-evidence-11f/collection.json"


def j(p):
    return json.loads((ROOT / p).read_text(encoding="utf-8"))


def bundle(lab, name):
    return j(f"learning/level_1/{lab}/splunk-evidence/{name}.json")


def packs():
    out = {}
    for p in sorted((ROOT / "learning/level_1").glob("*/specimens/**/*.jsonl")):
        out.setdefault(p.stem, []).append(p)
    return out


@pytest.mark.parametrize("lab", LABS)
def test_manifest_hashes_and_the_collection_are_intact(lab):
    m = bundle(lab, "manifest")
    assert sha(COLL.read_bytes()) == m["collection_sha256"]
    for name, h in m["files"].items():
        assert sha((ROOT / f"learning/level_1/{lab}/splunk-evidence/{name}").read_bytes()) == h, name
    assert m["splunk"] == bundle(lab, "searches")["splunk"] == {"build": "bcdcf0552e0c", "version": "10.2.6"}


@pytest.mark.parametrize("lab", LABS)
def test_every_search_is_the_shipped_spl_with_its_hash_and_complete_metadata(lab):
    s = bundle(lab, "searches")["searches"]
    assert len(s) == EXPECTED_SEARCHES[lab] == len(list((ROOT / f"learning/level_1/{lab}/searches").glob("*.spl")))
    for x in s:
        raw = (ROOT / x["spl_file"]).read_bytes()
        assert sha(raw) == x["spl_sha256"] and raw.decode() == x["spl_text"], x["id"]
        assert x["sid"] and x["dispatch_state"] == "DONE" and x["is_failed"] is False and x["submitted_at"], x["id"]
        assert x["row_count_check"]["equal"] and x["returned_rows"] == len(x["rows"]) == int(x["result_count"]), x["id"]
        assert "earliest=0" in x["spl_text"] and "agentsec_telemetry" in x["spl_text"]
        assert x["errors_or_warnings"] == [] and x["submit_error"] is None
        assert x["attribution"]["kind"] in ("per_run", "aggregate", "unattributed_sample")


@pytest.mark.parametrize("lab", LABS)
def test_rows_are_exactly_what_the_collection_recorded(lab):
    coll = json.loads(COLL.read_text(encoding="utf-8"))["labs"][lab]
    mine = bundle(lab, "searches")["searches"]
    assert [(c["id"], c["sid"], c["rows"], c["result_count"], c["scan_count"]) for c in coll] == [(m["id"], m["sid"], m["rows"], m["result_count"], m["scan_count"]) for m in mine]


def test_zero_row_tuned_search_is_a_successful_execution_not_missing_evidence():
    t = next(x for x in bundle(LABS[1], "searches")["searches"] if x["id"] == "Q-DET-TUNED")
    assert t["rows"] == [] and t["result_count"] == 0 and t["dispatch_state"] == "DONE" and int(t["scan_count"]) > 0
    assert t["attribution"]["zero_rows"] is True and t["attribution"]["executed_successfully"] is True
    broad = next(x for x in bundle(LABS[1], "searches")["searches"] if x["id"] == "Q-DET-BROAD")
    assert len(broad["rows"]) == 2
    m = bundle(LABS[1], "manifest")
    assert "does not interpret the zero rows as proof" in m["observed_summary"]


@pytest.mark.parametrize("lab", LABS)
def test_pack_matching_recomputed_from_the_committed_packs(lab):
    pm = bundle(lab, "pack-matching")
    allpacks = packs()
    for r in pm["runs"]:
        rid = r["run_id"]
        if rid not in allpacks:
            assert r["committed_pack"] is None and r["match"] is None, rid
            continue
        p = allpacks[rid][0]
        lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert r["committed_pack"]["sha256"] == sha(p.read_bytes()) and r["committed_pack"]["path"] == p.relative_to(ROOT).as_posix()
        pack_raw = {sha(l.encode()) for l in lines}
        splunk_raw = {e["raw_sha256"] for e in r["event_hashes"]}
        assert splunk_raw == pack_raw and len(lines) == r["match"]["pack_events"], rid     # every indexed event is a pack line, and every pack line is indexed
        assert r["match"]["different_content_count"] == 0 and r["match"]["pack_lines_not_in_splunk_exactly"] == 0
        for other in allpacks[rid][1:]:
            assert sha(other.read_bytes()) == r["committed_pack"]["sha256"], "copies of one run are identical"


def test_unmatched_runs_are_recorded_not_dropped():
    for lab in LABS:
        pm = bundle(lab, "pack-matching")
        iw = pm["index_wide"]
        assert iw["otel_runs_in_index"] == 104 and iw["runs_with_committed_pack"] == 53 and iw["runs_without_committed_pack"] == 51
        assert sum(iw["runs_without_committed_pack_by_mode"].values()) == 51 and "not all indexed runs are independently reproducible" in iw["statement"].lower()
    coll = json.loads(COLL.read_text(encoding="utf-8"))
    inv = coll["index_inventory"]
    assert len(inv["runs"]) == 104 and len(inv["runs_without_committed_pack"]) == 51
    assert sum(1 for r in inv["runs"] if r["packs"]) == 53 and set(inv["runs_without_committed_pack"]) == {r["run_id"] for r in inv["runs"] if not r["packs"]}
    bridge = bundle(LABS[0], "pack-matching")
    assert any(r["committed_pack"] is None for r in bridge["runs"]) and len(bridge["runs"]) == 14, "unmatched runs exposed by a search stay in the report"


def test_external_events_are_matched_byte_for_byte_or_reported_unmatched():
    ext = bundle(LABS[0], "pack-matching")["external_events"]
    scan = [e for e in ext if e["sourcetype"] == "agentsec:scanner:finding"]
    assert len(scan) == 3 and all(len(e["committed_match"]) == 1 for e in scan)
    for e in scan:
        path, line = e["committed_match"][0].split(":line ")
        ev = json.loads((ROOT / path).read_text(encoding="utf-8").splitlines()[int(line) - 1])["event"]
        assert sha(ev.encode()) == e["raw_sha256"] and ev == e["raw_text"]
    garak = [e for e in ext if e["sourcetype"] == "agentsec:external:evaluation"]
    assert len(garak) == 2 and {e["indexed_rows_with_this_raw"] for e in garak} == {2} and len({e["raw_sha256"] for e in garak}) == 1, "one distinct event indexed twice"
    norm = j("docs/p1a-evidence/garak-aeb05718-1364-4143-8248-71dd6f27b07b/normalized/evaluations.json")["records"][0]
    assert json.loads(garak[0]["raw_text"])["external"] == norm
    assert all(e["committed_match"] is None for e in ext if e["sourcetype"] in ("agentsec:canary", "otel:agentic:json"))


@pytest.mark.parametrize("lab", LABS)
def test_nothing_is_marked_verified_and_the_limits_are_stated(lab):
    m = bundle(lab, "manifest")
    v = m["verification"]
    assert v["status"] == "NOT_VERIFIED" and v["receipt"] is None and v["runs_in_this_bundle_with_a_valid_receipt"] == 0
    assert "SPLUNK-VERIFIED" in m["claims_not_made"] and "NOT_VERIFIED" in m["classification"]
    blob = json.dumps(m).lower()
    assert "splunk_verified" not in blob.replace("not_verified", "")
    assert len(m["limitations"]) >= 5 and any("mutable" in x for x in m["limitations"]) and any("aggregate" in x.lower() for x in m["limitations"])
    for x in m.get("documented_statements", []) + m.get("documented_expectations", []):
        assert EXP.clean(x["text"]) in EXP.source_text(ROOT / x["file"]), x["text"]


def test_no_receipt_belongs_to_a_run_the_bundle_depends_on():
    chk = bundle(LABS[0], "manifest")["verification"]["receipt_check"]
    receipts = set(chk["receipt_files_on_the_host"])
    assert chk["receipt_run_ids_that_are_indexed_runs"] and len(receipts) == 15
    in_bundle = {r["run_id"] for lab in LABS for r in bundle(lab, "pack-matching")["runs"]}
    assert not receipts & in_bundle, "no run this bundle shows has a verifier receipt"
    coll = json.loads(COLL.read_text(encoding="utf-8"))
    assert all("/api/v1/loan-desk/applications" in r["workflow_entry"] for r in coll["index_inventory"]["runs"] if r["run_id"] in receipts and r["run_id"] in chk["receipt_run_ids_that_are_indexed_runs"])


def test_identity_keeps_three_kinds_of_evidence_separate():
    m = bundle(LABS[2], "manifest")["three_kinds_of_evidence"]
    base, cur, hist = m["committed_specimen_evidence"], m["current_splunk_observations"], m["historical_documented_expectations"]
    assert base["lab"] == "LAB-AGENT-DELEGATION-001" and len(base["runs"]) == 3
    committed = sorted(p.stem for p in (ROOT / "learning/level_1/LAB-AGENT-DELEGATION-001/specimens").glob("*.jsonl"))
    assert sorted(r["run_id"] for r in base["runs"]) == committed
    for r in base["runs"]:
        lines = [json.loads(l) for l in (ROOT / r["pack"]).read_text(encoding="utf-8").splitlines() if l.strip()]
        assert sha((ROOT / r["pack"]).read_bytes()) == r["pack_sha256"] and len(lines) == r["events"]
        assert [(c["control_id"], c["decision"], c["reason"]) for c in r["control_decisions"]] == [(e["agentsec.control.id"], e["agentsec.control.decision"], e["agentsec.control.reason"]) for e in lines if e["event.name"] == "agentsec.control.decision"]
    assert set(committed) <= set(cur["identity_runs_in_index"]) and len(cur["identity_runs_in_index"]) == 6
    assert len(cur["identity_runs_without_committed_pack"]) == 3 and not set(cur["identity_runs_without_committed_pack"]) & set(committed)
    assert hist["kept_separate"] and hist["not_merged_with_the_above"]
    assert not set(hist["historical_run_ids"]) & (set(cur["identity_runs_in_index"]) | set(committed)), "historical ids are not merged with current or committed runs"
    assert hist["historical_run_ids_present_in_the_current_index"] == [] and hist["historical_run_ids_with_a_committed_pack"] == []
    for x in hist["statements"]:
        assert EXP.clean(x["text"]) in EXP.source_text(ROOT / x["file"]), x["text"]
    pm = bundle(LABS[2], "pack-matching")
    assert {r["run_id"] for r in pm["runs"]} == set(cur["identity_runs_in_index"])


def test_the_loader_can_read_each_bundle_as_a_study_source():
    # the existing exporter reads JSON sources by name and walks dotted paths; this proves the bundle fits it without a new loader
    for lab in LABS:
        packet = {n: bundle(lab, n) for n in ("manifest", "searches", "pack-matching")}
        assert EXP._walk(packet, "searches.searches[].id") and EXP._walk(packet, "manifest.verification.status") == ["NOT_VERIFIED"]
        assert EXP._walk(packet, "pack-matching.runs[].run_id") is not None
