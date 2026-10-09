"""P1.5 durable Academy LIVE index: UUID-gated recovery, no tree browsing."""
from __future__ import annotations

import json
from pathlib import Path

from agentsec.academy_live_index import (
    get_ref,
    is_authorized,
    launch_body_from_ref,
    list_refs,
    notebook_slots,
    persist_live_run,
)
from agentsec.attack_app import AcmeBankClient, create_app

LIVE_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
LIVE_B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
LIVE_C = "cccccccc-3333-4333-8333-cccccccccccc"
OTHER = "dddddddd-4444-4444-8444-dddddddddddd"


def _write_events(root: Path, run_id: str, n: int = 1) -> None:
    directory = root / run_id
    directory.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"agentsec.run.id": run_id, "event.name": "agentsec.run.started", "agentsec.sequence": i, "timestamp": f"2026-10-09T18:00:0{i}Z"})
        for i in range(1, n + 1)
    ]
    (directory / "events.jsonl").write_text("\n".join(lines) + "\n")


def test_persist_is_idempotent_and_does_not_duplicate(tmp_path):
    _write_events(tmp_path, LIVE_A)
    first = persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK", profile="vulnerable", specimen_id="spec-a")
    second = persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK", profile="vulnerable", specimen_id="spec-a")
    assert first is not None and second is not None
    refs = list_refs(tmp_path)
    assert [item.run_id for item in refs] == [LIVE_A]
    assert is_authorized(tmp_path, LIVE_A)


def test_missing_artifact_is_explicit_not_silently_complete(tmp_path):
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK")
    ref = get_ref(tmp_path, LIVE_A)
    assert ref is not None
    assert ref.status == "missing"
    slots = notebook_slots(tmp_path)
    assert slots["slots"]["ATTACK"] is None
    assert any("missing" in note for note in slots["notes"])


def test_notebook_slots_keep_latest_complete_per_scenario(tmp_path):
    _write_events(tmp_path, LIVE_A)
    _write_events(tmp_path, LIVE_B)
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK", recorded_at="2026-10-09T18:00:00Z")
    persist_live_run(tmp_path, run_id=LIVE_B, scenario="ATTACK", recorded_at="2026-10-09T18:05:00Z")
    persist_live_run(tmp_path, run_id=LIVE_C, scenario="RETEST", recorded_at="2026-10-09T18:06:00Z")
    _write_events(tmp_path, LIVE_C)
    persist_live_run(tmp_path, run_id=LIVE_C, scenario="RETEST", recorded_at="2026-10-09T18:06:00Z")
    slots = notebook_slots(tmp_path)
    assert slots["slots"]["ATTACK"]["run_id"] == LIVE_B
    assert slots["slots"]["RETEST"]["run_id"] == LIVE_C


def test_wrong_lab_or_unindexed_uuid_is_not_authorized(tmp_path):
    _write_events(tmp_path, OTHER)
    assert is_authorized(tmp_path, OTHER) is False
    assert persist_live_run(tmp_path, run_id="not-a-uuid", scenario="ATTACK") is None
    assert persist_live_run(tmp_path, run_id=LIVE_A, scenario="NOT_A_MODE") is None


def test_sidecar_recovers_when_index_is_gone(tmp_path):
    _write_events(tmp_path, LIVE_A)
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="RETEST", profile="defended")
    (tmp_path / "academy_live_index.json").unlink()
    assert is_authorized(tmp_path, LIVE_A)
    ref = get_ref(tmp_path, LIVE_A)
    assert ref is not None and ref.scenario == "RETEST"
    body = launch_body_from_ref(ref)
    assert body["recovered"] is True
    assert body["runtime"] == {}
    assert "HEC" not in json.dumps(body)
    assert "token" not in json.dumps(body).lower()


def test_index_never_stores_secrets(tmp_path):
    _write_events(tmp_path, LIVE_A)
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK", profile="vulnerable")
    text = (tmp_path / "academy_live_index.json").read_text() + (tmp_path / LIVE_A / "academy_ref.json").read_text()
    lowered = text.lower()
    for forbidden in ("password", "token", "secret", "authorization", "splunk_hec"):
        assert forbidden not in lowered


def _app(tmp_path):
    application = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda _p: (200, {"status": "healthy"})), launch_kwargs={"artifacts_dir": tmp_path})
    application.config["TESTING"] = True
    return application.test_client()


def test_evidence_endpoint_rehydrates_from_durable_index_without_launcher_memory(tmp_path):
    _write_events(tmp_path, LIVE_A)
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK", profile="vulnerable")
    client = _app(tmp_path)
    response = client.get(f"/api/academy/evidence/{LIVE_A}")
    assert response.status_code == 200
    body = response.get_json()
    assert body["provenance"] == "LIVE"
    assert body["run_id"] == LIVE_A
    assert body["launch_response"]["runtime_handler_count"] == "NOT MEASURED"


def test_evidence_endpoint_still_refuses_unindexed_artifacts(tmp_path):
    _write_events(tmp_path, OTHER)
    client = _app(tmp_path)
    response = client.get(f"/api/academy/evidence/{OTHER}")
    assert response.status_code == 404
    assert response.get_json()["error"] == "unknown_run"


def test_live_runs_endpoint_returns_slots_not_a_directory_listing(tmp_path):
    _write_events(tmp_path, LIVE_A)
    persist_live_run(tmp_path, run_id=LIVE_A, scenario="ATTACK")
    stray = tmp_path / "not-a-run"
    stray.mkdir()
    (stray / "events.jsonl").write_text("{}\n")
    client = _app(tmp_path)
    response = client.get("/api/academy/live-runs")
    assert response.status_code == 200
    body = response.get_json()
    assert body["slots"]["ATTACK"]["run_id"] == LIVE_A
    assert all(item["run_id"] != "not-a-run" for item in body["runs"])
    assert "not_authorization" in body
