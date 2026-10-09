"""P1.4: the Academy notebook states only what a run's own record shows.

Facts are recomputed here straight from the committed REPLAY packs, so a change
in the derivation cannot quietly drift from the evidence. LIVE behaviour is
exercised with records written to a temporary artifacts directory; nothing here
launches a run or talks to Splunk.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec import academy_evidence as ev

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "specimens"
ATTACK = "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49"
RETEST = "7a1d37b5-d589-4dfd-8322-25ebd0152dbc"
BASELINE = "163d11e2-e751-4282-9406-19b490542ed4"
LIVE_ID = "11111111-2222-4333-8444-555555555555"


def _raw(run_id: str) -> list[dict]:
    return [json.loads(line) for line in (PACKS / f"{run_id}.jsonl").read_text().splitlines() if line.strip()]


def _load(run_id, tmp_path=None, live=frozenset()):
    return ev.load_run(run_id, artifacts_dir=tmp_path or Path("/nonexistent"), live_run_ids=live)


def _write_live(tmp_path: Path, run_id: str, events: list[dict]) -> Path:
    directory = tmp_path / run_id
    directory.mkdir(parents=True)
    path = directory / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def _event(seq: int, name: str, run_id: str = LIVE_ID, **fields) -> dict:
    return {"timestamp": "2026-10-09T12:00:0%dZ" % seq, "agentsec.sequence": seq, "event.name": name, "agentsec.run.id": run_id, **fields}


# --- normal input: the committed packs ------------------------------------------------


@pytest.mark.parametrize("run_id", [ATTACK, RETEST, BASELINE])
def test_facts_match_the_raw_pack(run_id):
    raw = _raw(run_id)
    control = next(e for e in raw if e["event.name"] == "agentsec.control.decision")
    facts = ev.derive_facts(_load(run_id))
    assert facts["provenance"] == ev.REPLAY
    assert facts["role"] == ev.REPLAY_ROLES[run_id]
    assert facts["decision"]["value"] == control["agentsec.control.decision"]
    assert facts["reason"]["value"] == control["agentsec.control.reason"]
    assert facts["requested_tool"]["value"] == control["gen_ai.tool.name"]
    names = {e["event.name"] for e in raw}
    assert (facts["handler_started"]["value"] == ev.OBSERVED) == ("agentsec.mcp.started" in names)
    assert (facts["pipeline_stopped"]["value"] == ev.OBSERVED) == ("agentsec.pipeline.stopped" in names)
    assert facts["event_count"] == len(raw)
    assert facts["warnings"] == []


def test_attack_and_retest_packs_show_the_expected_lab_shapes():
    attack = ev.derive_facts(_load(ATTACK))
    retest = ev.derive_facts(_load(RETEST))
    assert (attack["decision"]["value"], attack["handler_started"]["value"]) == ("ALLOW", ev.OBSERVED)
    assert (retest["decision"]["value"], retest["handler_started"]["value"]) == ("DENY", ev.NOT_OBSERVED)
    assert retest["reason_code"] == "tool_not_granted"
    assert attack["security_profile"] == "vulnerable" and retest["security_profile"] == "defended"


@pytest.mark.parametrize("run_id", [ATTACK, RETEST, BASELINE])
def test_every_cited_event_exists_in_the_record(run_id):
    raw = _raw(run_id)
    pairs = {(e["agentsec.sequence"], e["event.name"], e["timestamp"]) for e in raw}
    facts = ev.derive_facts(_load(run_id))
    for key in ("decision", "reason", "requested_tool", "requested_scope", "allowed_scope", "handler_started", "handler_completed", "pipeline_stopped"):
        source = facts[key]["source"]
        if source is not None:
            assert (source["sequence"], source["event_name"], source["timestamp"]) in pairs


def test_no_llm_activity_is_invented():
    for run_id in (ATTACK, RETEST, BASELINE):
        raw_llm = [e for e in _raw(run_id) if "llm" in e["event.name"].lower()]
        assert ev.derive_facts(_load(run_id))["llm_event_count"] == len(raw_llm) == 0


def test_display_events_keep_only_allowlisted_fields():
    rows = ev.display_events(_load(ATTACK))
    assert rows and all(set(row) <= set(ev.DISPLAY_FIELDS) for row in rows)
    assert all("agentsec.content.preview" not in row for row in rows)


def test_replay_source_hash_is_the_committed_file_hash():
    import hashlib

    record = _load(ATTACK)
    assert record.sha256 == hashlib.sha256((PACKS / f"{ATTACK}.jsonl").read_bytes()).hexdigest()
    assert record.source == f"learning/level_1/LAB-MCP-001/specimens/{ATTACK}.jsonl"


# --- comparison ------------------------------------------------------------------------


def test_compare_reports_only_recorded_differences():
    doc = ev.compare_document(_load(ATTACK), _load(RETEST), splunk_web="http://h:8000")
    rows = {r["label"]: r for r in doc["rows"]}
    assert rows["Requested tool"]["relation"] == "SAME"
    assert rows["CTRL-MCP-001 decision"]["attack"] == "ALLOW"
    assert rows["CTRL-MCP-001 decision"]["retest"] == "DENY"
    assert rows["Tool handler started (mcp.started)"]["retest"] == ev.NOT_OBSERVED
    assert doc["warnings"] == []
    assert all("NOT" in o or "recorded" in o or "present" in o for o in doc["observations"])
    assert all("inference" in i.lower() or "not proof" in i.lower() for i in doc["inferences"])


def test_compare_rejects_the_same_run_twice():
    with pytest.raises(ev.EvidenceError) as raised:
        ev.compare_document(_load(ATTACK), _load(ATTACK), splunk_web="http://h:8000")
    assert raised.value.code == "same_run"


def test_compare_flags_swapped_roles():
    doc = ev.compare_document(_load(RETEST), _load(ATTACK), splunk_web="http://h:8000")
    assert any("ATTACK column recorded mode RETEST" in w for w in doc["warnings"])
    assert any("RETEST column recorded mode ATTACK" in w for w in doc["warnings"])


def test_compare_flags_mixed_live_and_replay(tmp_path):
    _write_live(tmp_path, LIVE_ID, [
        _event(1, "agentsec.control.decision", **{"agentsec.control.id": "CTRL-MCP-001", "agentsec.control.decision": "DENY", "agentsec.testbed.mode": "RETEST"}),
        _event(2, "agentsec.pipeline.stopped"),
    ])
    live = _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    doc = ev.compare_document(_load(ATTACK), live, splunk_web="http://h:8000")
    assert any("LIVE and the other is REPLAY" in w for w in doc["warnings"])


# --- LIVE records ------------------------------------------------------------------------


def test_live_record_is_labelled_live_with_its_source(tmp_path):
    _write_live(tmp_path, LIVE_ID, [
        _event(1, "agentsec.control.decision", **{"agentsec.control.id": "CTRL-MCP-001", "agentsec.control.decision": "ALLOW", "agentsec.control.reason": "x"}),
        _event(2, "agentsec.mcp.started"),
    ])
    record = _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    doc = ev.evidence_document(record, splunk_web="http://h:8000", launch_body={"mode": "ATTACK", "runtime": {"handler_invoke_count": 1}})
    assert doc["provenance"] == ev.LIVE
    assert doc["synthetic"] is False
    assert doc["evidence_state"] == "AVAILABLE"
    assert doc["runtime_schema_expected"] == "1.9.0"
    assert doc["external_evidence"]["contract_version"] == "1.0.0"
    assert doc["external_evidence"]["applicable"] is False
    assert doc["source"] == f"artifacts/{LIVE_ID}/events.jsonl"
    assert "does not prove Splunk has indexed it" in doc["provenance_text"]
    assert doc["launch_response"]["runtime_handler_count"] == 1
    assert "form.live_run_id=" + LIVE_ID in doc["splunk"]["studio_url"]


def test_launch_body_without_handler_count_is_not_measured(tmp_path):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.run.started")])
    record = _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    doc = ev.evidence_document(record, splunk_web="http://h:8000", launch_body={"runtime": {}})
    assert doc["launch_response"]["runtime_handler_count"] == ev.NOT_MEASURED


def test_deny_with_execution_is_never_reported_as_prevented(tmp_path):
    _write_live(tmp_path, LIVE_ID, [
        _event(1, "agentsec.control.decision", **{"agentsec.control.id": "CTRL-MCP-001", "agentsec.control.decision": "DENY"}),
        _event(2, "agentsec.mcp.started"),
    ])
    facts = ev.derive_facts(_load(LIVE_ID, tmp_path, frozenset({LIVE_ID})))
    assert facts["decision"]["value"] == "DENY"
    assert facts["handler_started"]["value"] == ev.OBSERVED
    assert any("Do not report this run as prevented" in w for w in facts["warnings"])


def test_missing_control_event_is_not_measured_not_allow(tmp_path):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.run.started"), _event(2, "agentsec.run.completed")])
    facts = ev.derive_facts(_load(LIVE_ID, tmp_path, frozenset({LIVE_ID})))
    assert facts["decision"]["value"] == ev.NOT_MEASURED
    assert facts["handler_started"]["value"] == ev.NOT_OBSERVED
    assert any("NOT MEASURED, not ALLOW" in w for w in facts["warnings"])


def test_a_different_control_does_not_count_as_ctrl_mcp_001(tmp_path):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.control.decision", **{"agentsec.control.id": "CTRL-OTHER", "agentsec.control.decision": "ALLOW"})])
    facts = ev.derive_facts(_load(LIVE_ID, tmp_path, frozenset({LIVE_ID})))
    assert facts["decision"]["value"] == ev.NOT_MEASURED


# --- malicious / malformed / boundary --------------------------------------------------


@pytest.mark.parametrize("bad", ["../etc/passwd", "5E8F55F3-EB46-47EE-B979-B72D9C9B1F49", "", None, 42, ATTACK + "x", ATTACK + "/../x"])
def test_malformed_run_ids_are_refused(bad):
    with pytest.raises(ev.EvidenceError) as raised:
        _load(bad)
    assert raised.value.code == "malformed_run_id"


def test_an_artifacts_run_not_launched_here_is_refused(tmp_path):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.run.started")])
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset())
    assert raised.value.code == "unknown_run"


def test_known_live_run_with_missing_record_is_missing_evidence(tmp_path):
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    assert raised.value.code == "live_record_missing"
    assert "missing evidence, not a missing run" in raised.value.detail


def test_a_record_carrying_another_run_id_is_refused(tmp_path):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.run.started", run_id=ATTACK)])
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    assert raised.value.code == "record_mismatch"


def test_non_json_record_is_refused(tmp_path):
    path = _write_live(tmp_path, LIVE_ID, [])
    path.write_text("{not json\n")
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    assert raised.value.code == "record_malformed"


def test_oversized_record_is_refused(tmp_path, monkeypatch):
    _write_live(tmp_path, LIVE_ID, [_event(1, "agentsec.run.started")])
    monkeypatch.setattr(ev, "MAX_RECORD_BYTES", 10)
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    assert raised.value.code == "record_too_large"


def test_too_many_events_is_refused(tmp_path, monkeypatch):
    _write_live(tmp_path, LIVE_ID, [_event(i, "agentsec.hop.started") for i in range(1, 6)])
    monkeypatch.setattr(ev, "MAX_EVENTS", 3)
    with pytest.raises(ev.EvidenceError) as raised:
        _load(LIVE_ID, tmp_path, frozenset({LIVE_ID}))
    assert raised.value.code == "record_too_large"


def test_missing_replay_pack_is_reported_not_invented(tmp_path):
    with pytest.raises(ev.EvidenceError) as raised:
        ev.load_run(ATTACK, artifacts_dir=tmp_path, live_run_ids=frozenset(), root=tmp_path)
    assert raised.value.code == "replay_pack_missing"


# --- Splunk links ------------------------------------------------------------------------


def test_replay_search_window_contains_the_recorded_run():
    facts = ev.derive_facts(_load(ATTACK))
    earliest, latest = ev.time_bounds(facts)
    assert earliest.isdigit() and latest.isdigit()
    links = ev.splunk_links(_load(ATTACK), facts, "http://lab.example:8000")
    assert "-1h" not in links["spl"]
    assert f'"agentsec.run.id"="{ATTACK}"' in links["spl"]
    assert links["search_url"].startswith("http://lab.example:8000/en-US/app/search/search?q=search%20index%3Dagentsec_telemetry")
    assert ATTACK in links["search_url"]
    assert links["studio_url"].endswith("form.run_id=" + ATTACK)


def test_pair_bounds_fall_back_to_all_time_without_timestamps():
    assert ev.pair_bounds({"first_timestamp": None, "last_timestamp": None}, ev.derive_facts(_load(ATTACK))) == ("0", "now")


def test_pack_inventory_reports_presence_and_hash(tmp_path):
    rows = ev.replay_pack_inventory()
    assert {r["role"] for r in rows} == {"BASELINE", "ATTACK", "RETEST"}
    assert all(r["present"] and len(r["sha256"]) == 64 for r in rows)
    missing = ev.replay_pack_inventory(root=tmp_path)
    assert all(not r["present"] and r["sha256"] is None for r in missing)
