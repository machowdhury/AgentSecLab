"""Increment 11G: the recorded-Splunk workbench for the Splunk Defender Bridge, Detection Engineering and Agent Identity labs.

Every question's options and answer are exported from the 11F evidence files. These tests recompute each answer from the raw 11F files with separate code, and check
that the embedded evidence is the 11F files unchanged and that the 429 KB collection is not in the learner bundle. Nothing here contacts Splunk.
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
DATA = json.loads((ROOT / "academy-ui/src/content/curriculum.json").read_text(encoding="utf-8"))
LABS = {l["id"]: l for l in DATA["labs"]}
FILES = ROOT / "academy-ui/src/content/recorded"
BR, DE, ID = "LAB-SPLUNK-DEFENDER-BRIDGE", "LAB-DETECTION-ENGINEERING", "LAB-AGENT-IDENTITY-NHI"
SPLUNK = [BR, DE, ID]
COLL = ROOT / "docs/splunk-evidence-11f/collection.json"
sha = lambda b: hashlib.sha256(b).hexdigest()
LABEL = "RECORDED SPLUNK OBSERVATION — NOT RE-RUN"


def cp(lab):
    return json.loads((FILES / LABS[lab]["explainer"]["recorded_ref"]["file"]).read_text(encoding="utf-8"))


def ev(lab, name):
    return json.loads((ROOT / f"learning/level_1/{lab}/splunk-evidence/{name}.json").read_text(encoding="utf-8"))


def ans(lab):
    s = cp(lab)["spec"]
    return {q["id"]: q for g in s["stages"] + [s["provenance"], s["conclusion"]] for q in g["questions"]}


def rows(lab, sid):
    return next(x for x in ev(lab, "searches")["searches"] if x["id"] == sid)["rows"]


def bucket(n):
    return "none" if n == 0 else "1" if n == 1 else "2–5" if n <= 5 else "6–10" if n <= 10 else "more than 10"


@pytest.mark.parametrize("lab", SPLUNK)
def test_the_embedded_evidence_is_the_11f_files_unchanged_and_hashed(lab):
    d = cp(lab)
    assert d["spec"]["kind"] == "splunk" and d["spec"]["label"] == LABEL
    for name in ("manifest", "searches", "matching"):
        assert d["packet"][name] == ev(lab, {"matching": "pack-matching"}.get(name, name)), name
    assert {f["name"] for f in d["files"]} == {"manifest", "searches", "matching"}
    for f in d["files"]:
        assert sha((ROOT / f["file"]).read_bytes()) == f["sha256"], f["file"]
    assert d["packet"]["manifest"]["collection_sha256"] == sha(COLL.read_bytes())


@pytest.mark.parametrize("lab", SPLUNK)
def test_rows_sids_times_and_spl_hashes_equal_the_raw_collection(lab):
    coll = json.loads(COLL.read_text(encoding="utf-8"))["labs"][lab]
    mine = cp(lab)["packet"]["searches"]["searches"]
    assert [(c["id"], c["sid"], c["submitted_at"], c["spl_sha256"], c["rows"]) for c in coll] == [(m["id"], m["sid"], m["submitted_at"], m["spl_sha256"], m["rows"]) for m in mine]
    for m in mine:
        assert sha((ROOT / m["spl_file"]).read_bytes()) == m["spl_sha256"]


@pytest.mark.parametrize("lab", SPLUNK)
def test_every_recorded_search_can_be_revealed_and_every_comparison_uses_revealable_searches(lab):
    s = cp(lab)["spec"]
    ids = {x["id"] for x in cp(lab)["packet"]["searches"]["searches"]}
    assert {st["search"] for st in s["stages"]} == ids
    for c in s["comparisons"]:
        for side in (c["left"], c["right"]):
            assert side.get("search") in ids or "path" in side


def test_the_collection_is_not_in_the_learner_bundle_and_evidence_loads_on_demand():
    for lab in SPLUNK:
        text = (FILES / f"{lab}.json").read_text(encoding="utf-8")
        assert '"index_inventory":' not in text and "event_hashes" in text   # the per-lab matching file, not the 429 KB collection
        assert (FILES / f"{lab}.json").stat().st_size < 200_000
    main = next((ROOT / "src/agentsec/static/learn/assets").glob("index-*.js")).read_text(encoding="utf-8")
    sid = cp(BR)["packet"]["searches"]["searches"][0]["sid"]
    run = next(r["run_id"] for r in cp(BR)["packet"]["matching"]["runs"] if r["committed_pack"] is None)   # a run no earlier lab embeds
    assert sid not in main and run not in main and "index_inventory" not in main


def test_bridge_answers_are_recomputed_from_the_recorded_rows():
    a = ans(BR); r = lambda sid: rows(BR, sid)
    d = r("Q-BRIDGE-DISCOVER")
    assert set(a["b1"]["answer"]) == {x["control_id"] for x in d if "control_id" in x} and a["b2"]["answer"] == [bucket(len(d))]
    assert a["b3"]["answer"] == [next(x["distinct_count"] for x in r("Q-BRIDGE-FIELDS") if x["field"] == "agentsec.security.profile")]
    n = r("Q-BRIDGE-NARROW")
    assert set(a["b4"]["answer"]) == {x["reasons"] for x in n} and a["b5"]["answer"] == sorted({x["mode"] for x in n}) and a["b6"]["answer"] == [bucket(len({x["run_id"] for x in n}))]
    sq = r("Q-BRIDGE-SEQUENCE")
    assert set(a["b7"]["answer"]) == {x["event_name"] for x in sq} and a["b8"]["answer"] == [str(len({x["run_id"] for x in sq}))]
    c = r("Q-BRIDGE-COMPARE")
    assert set(a["b9"]["answer"]) == {x["decision"] for x in c if x["mode"] == "ATTACK"} == {"ALLOW", "ERROR"} and a["b10"]["answer"] == [x["mode"] for x in c if x["decision"] == "DENY"] == ["RETEST"]
    assert a["b11"]["answer"] == [next(x["indexed_rows"] for x in r("Q-BRIDGE-COMPARE-EXECUTION") if x["mode"] == "RETEST" and x["event_name"] == "agentsec.mcp.started")]
    assert a["b12"]["answer"] == ["yes" if r("Q-BRIDGE-COMPARE") == r("Q-BRIDGE-STATS") else "no"]
    assert a["b13"]["answer"] == ["yes" if all(x["indexed_rows"] == x["distinct_raw"] for x in r("Q-BRIDGE-DUPLICATES")) else "no"]
    assert a["b14"]["answer"] == ["yes" if all(x["indexed_rows"] == x["distinct_raw"] for x in r("Q-BRIDGE-DUPLICATES-BY-MODE")) else "no"]
    ex = r("Q-BRIDGE-EXTERNAL")
    assert a["b15"]["answer"] == sorted({x["distinct_runtime_run_ids"] for x in ex}) == ["0"]
    assert a["b16"]["answer"] == [next(x["distinct_raw"] for x in ex if x["sourcetype"] == "agentsec:external:evaluation")] == ["1"]


def test_bridge_provenance_and_conclusion_are_recomputed_and_do_not_overclaim():
    a = ans(BR); runs = ev(BR, "pack-matching")["runs"]; iw = ev(BR, "pack-matching")["index_wide"]
    assert a["v1"]["answer"] == [str(sum(1 for x in runs if x["committed_pack"]))] == ["9"] and len(runs) == 14
    assert a["v2"]["answer"] == ["no"] and a["v3"]["answer"] == ["yes"] and iw["runs_without_committed_pack"] == 51
    claims = a["z1"]
    assert claims["answer"] == [claims["candidates"][0], claims["candidates"][2]]
    cmp_rows = rows(BR, "Q-BRIDGE-COMPARE")
    assert {x["mode"] for x in cmp_rows if x["decision"] == "DENY"} == {"RETEST"}                                   # candidate 0 is supported
    assert all(x["indexed_rows"] == x["distinct_raw"] for x in rows(BR, "Q-BRIDGE-DUPLICATES-BY-MODE"))               # candidate 4 is not
    assert all(x["distinct_runtime_run_ids"] == "0" for x in rows(BR, "Q-BRIDGE-EXTERNAL"))                           # candidate 2 is supported
    assert "SPLUNK-VERIFIED" in claims["candidates"][3] and claims["candidates"][3] not in claims["answer"]


def test_detection_answers_and_the_zero_row_tuned_search():
    a = ans(DE); r = lambda sid: rows(DE, sid)
    e = r("Q-DET-EVENTS")
    assert set(a["d1"]["answer"]) == {x["event_name"] for x in e if x["mode"] == "ATTACK"} and a["d2"]["answer"] == [x["mode"] for x in e if x["event_name"] == "agentsec.mcp.failed"]
    b, t = r("Q-DET-BROAD"), r("Q-DET-TUNED")
    assert a["d3"]["answer"] == [bucket(len({x["run_id"] for x in b}))] == ["2–5"] and a["d4"]["answer"] == ["yes" if all(x["deny_tools"] == x["start_tools"] for x in b) else "no"] == ["no"]
    assert t == [] and a["d5"]["answer"] == ["none"] and a["d6"]["answer"] == ["no"]
    srch = next(x for x in ev(DE, "searches")["searches"] if x["id"] == "Q-DET-TUNED")
    assert srch["dispatch_state"] == "DONE" and srch["result_count"] == 0 and int(srch["scan_count"]) > 0
    p = ev(DE, "pack-matching")["runs"]
    assert a["v1"]["answer"] == [str(sum(1 for x in p if x["committed_pack"]))] == ["2"] and a["v2"]["answer"] == ["no"]
    z = a["z1"]
    assert z["answer"] == [z["candidates"][0], z["candidates"][2], z["candidates"][3]]
    assert "validates the detection" in z["candidates"][1] and z["candidates"][1] not in z["answer"], "a zero-row search is never taken as validation"


def test_identity_answers_and_the_three_kinds_of_evidence_stay_apart():
    a = ans(ID); r = lambda sid: rows(ID, sid)
    assert a["i1"]["answer"] == sorted({x["runs"] for x in r("Q-ID-MODES")}) == ["2"]
    c = r("Q-ID-CONTROLS")
    assert a["i2"]["answer"] == sorted({x["decision"] for x in c if x["control_id"] == "CTRL-IDENTITY-001"}) == ["OBSERVE"]
    assert a["i3"]["answer"] == [x["decision"] for x in c if x["mode"] == "RETEST" and x["control_id"] == "CTRL-MCP-001"] == ["DENY"]
    assert a["i4"]["answer"] == [x["reason"] for x in c if x["mode"] == "ATTACK" and x["control_id"] == "CTRL-MCP-001"]
    assert set(a["i5"]["answer"]) == {x["mode"] for x in r("Q-ID-STARTS")} == {"ATTACK", "BASELINE"}
    runs = ev(ID, "pack-matching")["runs"]
    assert a["v1"]["answer"] == [str(sum(1 for x in runs if x["committed_pack"]))] == ["3"] and a["v2"]["answer"] == [str(sum(1 for x in runs if not x["committed_pack"]))] == ["3"]
    three = ev(ID, "manifest")["three_kinds_of_evidence"]
    assert a["v3"]["answer"] == [str(len(three["historical_documented_expectations"]["historical_run_ids_present_in_the_current_index"]))] == ["0"]
    committed = {x["run_id"] for x in three["committed_specimen_evidence"]["runs"]}
    assert committed == {x["run_id"] for x in runs if x["committed_pack"]} and not committed & set(three["historical_documented_expectations"]["historical_run_ids"])
    z = a["z1"]
    assert z["answer"] == [z["candidates"][0], z["candidates"][2]] and "authenticated" in z["candidates"][1] and "reproduce all six" in z["candidates"][3]




def test_the_workbench_never_queries_splunk_or_calls_the_backend():
    src = (ROOT / "academy-ui/src/workbench/SplunkWorkbench.tsx").read_text(encoding="utf-8")
    for bad in ("fetch(", "XMLHttpRequest", "/api/", "WebSocket"):
        assert bad not in src, bad
