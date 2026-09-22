"""Phase 15C: LAB-MEMORY-001 LIVE learning loop. Schema 1.9.0. No DET-MEMORY."""

from __future__ import annotations

import threading
from pathlib import Path

from agentsec.events import content_hash
from agentsec.experiment import SCHEMA_VERSION
from agentsec.experiment_context import (
    LAB_MEMORY,
    attack_retest_fingerprint_pair,
    bind_experiment_for_memory,
    lookup_experiment,
)
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION, assert_learning_not_policy
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.memory.fixtures import (
    MALICIOUS_MEMORY,
    MEMORY_ATTACK_ID,
    MEMORY_ID_MALICIOUS,
    MEMORY_ID_NORMAL,
    NORMAL_MEMORY,
    PROVENANCE,
)
from agentsec.memory.request_contract import parse_memory_write_body
from agentsec.memory.trust import MEMORY_FAIL_OPEN_REASON
from agentsec.memory.store import InProcessMemoryStore
from agentsec.memory.pipeline import run_memory_write

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "memory-live-learning-loop.md"
IMPL = ROOT / "docs" / "PHASE15C_MEMORY_LIVE_LEARNING_LOOP.md"
MALICIOUS_HASH = "sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9"


def test_phase15c_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert (ROOT / "docs" / "PHASE15C_MEMORY_ATTACK_SERVICE_LAUNCH_CONTRACT.md").is_file()
    assert (ROOT / "docs" / "PHASE15C_MEMORY_GUIDED_INVESTIGATIONS.md").is_file()
    assert (ROOT / "docs" / "PHASE15C_SECURITY_BOUNDARY_REVIEW.md").is_file()
    assert (ROOT / "docs" / "PHASE15C_LIVE_VS_REPLAY.md").is_file()


def test_schema_unchanged_and_no_det_memory():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-MEMORY" not in saved
    assert not list((ROOT / "learning").rglob("DET-MEMORY*"))
    hunts = {path.name for path in (ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches").glob("Q-*.spl")}
    assert hunts == {"Q-MEMORY-CONTEXT-AUTHORITY.spl"}


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    assert_learning_not_policy("LAB-MEMORY-001")
    manifest = validate_lab_manifest("LAB-MEMORY-001")
    assert manifest["not_authorization"] is True
    assert manifest["control_id"] == "CTRL-MEMORY-CONTEXT-001"
    assert manifest["enforcement_control_id"] == "CTRL-MCP-001"


def test_memory_attack_retest_fingerprint_is_memory_bytes():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_MEMORY)
    assert attack_fp == retest_fp == content_hash(MALICIOUS_MEMORY) == MALICIOUS_HASH
    attack = lookup_experiment("LAB-MEMORY-001:ATTACK")
    retest = lookup_experiment("LAB-MEMORY-001:RETEST")
    assert attack is not None and retest is not None
    assert attack.payload == retest.payload == MALICIOUS_MEMORY
    assert attack.memory_id == retest.memory_id == MEMORY_ID_MALICIOUS
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False
    baseline = lookup_experiment("LAB-MEMORY-001:BASELINE")
    assert baseline is not None
    assert baseline.memory_id == MEMORY_ID_NORMAL
    assert baseline.payload == NORMAL_MEMORY
    assert baseline.payload != MALICIOUS_MEMORY


def test_memory_launch_catalog_rows():
    attack = lookup_launch(
        lab_id="LAB-MEMORY-001",
        specimen_id=MEMORY_ATTACK_ID,
        mode="ATTACK",
        execution="live",
    )
    retest = lookup_launch(
        lab_id="LAB-MEMORY-001",
        specimen_id=MEMORY_ATTACK_ID,
        mode="RETEST",
        execution="live",
    )
    baseline = lookup_launch(
        lab_id="LAB-MEMORY-001",
        specimen_id="MEMORY-BASELINE",
        mode="BASELINE",
        execution="live",
    )
    assert attack is not None and retest is not None and baseline is not None
    assert attack.profile == "vulnerable"
    assert retest.profile == "defended"
    assert attack.runtime_route == "memory_lifecycle"


def test_memory_authority_fields_are_unknown_not_policy():
    parsed = parse_memory_write_body(
        {
            "memory_id": MEMORY_ID_MALICIOUS,
            "experiment_id": "LAB-MEMORY-001:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_customer_tier"],
            "trusted_memory": True,
            "memory_authorized": True,
            "content": MALICIOUS_MEMORY,
            "grant": True,
            "policy": "open",
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_memory_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_memory(
        experiment_id="LAB-MEMORY-001:ATTACK",
        memory_id=MEMORY_ID_NORMAL,
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_memory_mismatch"
    unknown, unknown_err = bind_experiment_for_memory(
        experiment_id="LAB-MEMORY-001:PWN",
        memory_id=MEMORY_ID_MALICIOUS,
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"
    user, user_err = bind_experiment_for_memory(
        experiment_id="LAB-MEMORY-001:ATTACK",
        memory_id=MEMORY_ID_MALICIOUS,
        user_id="attacker-lab",
    )
    assert user is None
    assert user_err == "experiment_user_mismatch"


def test_live_memory_attack_and_retest_via_attack_service(acme_client):
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MEMORY-001",
            "specimen_id": MEMORY_ATTACK_ID,
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MEMORY-001",
            "specimen_id": MEMORY_ATTACK_ID,
            "mode": "RETEST",
            "execution": "live",
        },
    )
    a = attack.get_json()
    r = retest.get_json()
    assert attack.status_code == 200, a
    assert retest.status_code == 200, r
    assert a["write_run_id"] != a["recall_run_id"]
    assert r["write_run_id"] != r["recall_run_id"]
    assert a["write_run_id"] != r["write_run_id"]
    assert a["recall_run_id"] != r["recall_run_id"]
    assert a["run_id"] == a["recall_run_id"]
    assert a["runtime"]["profile"] == "vulnerable"
    assert r["runtime"]["profile"] == "defended"
    assert a["runtime"]["memory_control_decision"] == "OBSERVE"
    assert r["runtime"]["memory_control_decision"] == "OBSERVE"
    assert a["runtime"]["follow_on_decision"] == "ALLOW"
    assert r["runtime"]["follow_on_decision"] == "DENY"
    assert a["runtime"]["follow_on_reason"] == MEMORY_FAIL_OPEN_REASON
    assert r["runtime"]["follow_on_reason"] == "tool_not_granted"
    assert a["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert r["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert a["runtime"]["handler_invoke_count"] == 1
    assert r["runtime"]["handler_invoke_count"] == 0
    assert a["input_fingerprint"] == r["input_fingerprint"] == MALICIOUS_HASH
    assert a["memory_id"] == r["memory_id"] == MEMORY_ID_MALICIOUS
    assert a["runtime"]["content_hash"] == r["runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["runtime"]["source_run_id"] == a["write_run_id"]
    assert r["runtime"]["source_run_id"] == r["write_run_id"]
    assert a["runtime"]["experiment_id"] == "LAB-MEMORY-001:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-MEMORY-001:RETEST"
    assert a["write_runtime"]["memory_id"] == MEMORY_ID_MALICIOUS
    assert a["write_runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert a["write_evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert a["recall_evidence_state"] == "WAITING_FOR_EVIDENCE"
    assert a["experiment_ready"] is False
    assert {path for path, _payload in calls} == {"/memory/write", "/memory/recall"}
    write_payloads = [payload for path, payload in calls if path == "/memory/write"]
    assert all(set(payload) <= {"memory_id", "user_id", "experiment_id"} for payload in write_payloads)
    assert all("profile" not in payload and "content" not in payload for _, payload in calls)
    assert "Q-MEMORY-CONTEXT-AUTHORITY" in a["search_handoff"]["reused_hunts"]
    assert a["search_handoff"]["copy_write_run_id"] == a["write_run_id"]
    coded = coded_policy()
    assert coded.allowed_tools == ALLOWED_TOOLS == frozenset({"lookup_policy"})


def test_memory_browser_cannot_send_authority_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    for extra in (
        {"profile": "vulnerable"},
        {"allowed_tools": ["lookup_customer_tier"]},
        {"memory_id": MEMORY_ID_MALICIOUS},
        {"trusted_memory": True},
        {"python": "print(1)"},
        {"spl": "index=*"},
        {"content": MALICIOUS_MEMORY},
        {"AGENTSEC_SECURITY_PROFILE": "vulnerable"},
    ):
        body = {
            "lab_id": "LAB-MEMORY-001",
            "specimen_id": MEMORY_ATTACK_ID,
            "mode": "ATTACK",
            "execution": "live",
            **extra,
        }
        response = client.post("/api/launch", json=body)
        assert response.status_code == 400, extra
        assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_memory_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-MEMORY-001").get_data(as_text=True)
    assert "Persistent Memory" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "Predict before ATTACK" in html
    assert "lab_id: \"LAB-MEMORY-001\"" in html
    assert MEMORY_ATTACK_ID in html
    assert "CTRL-MEMORY-CONTEXT-001" in html
    assert "Q-MEMORY-CONTEXT-AUTHORITY" in html
    assert "WRITE RUN" in html
    assert "RECALL RUN" in html
    assert "Copy ATTACK write run.id" in html
    assert "WHAT IS AGENT MEMORY?" in html
    assert "in-process memory" in html.lower()


def test_direct_memory_write_without_experiment_id_keeps_auto_mode_and_duplicate(acme_client):
    first = acme_client.post(
        "/memory/write",
        json={"memory_id": MEMORY_ID_NORMAL, "user_id": "applicant-web"},
    )
    body = first.get_json()
    assert first.status_code == 200
    assert body["testbed_mode"] == "BASELINE"
    assert body.get("experiment_id") in (None, "")
    second = acme_client.post(
        "/memory/write",
        json={"memory_id": MEMORY_ID_NORMAL, "user_id": "applicant-web"},
    )
    assert second.status_code == 400
    assert second.get_json()["block_reason"] == "duplicate_memory_id"


def test_direct_memory_experiment_mismatch_http_is_error(acme_client):
    response = acme_client.post(
        "/memory/write",
        json={
            "memory_id": MEMORY_ID_NORMAL,
            "user_id": "applicant-web",
            "experiment_id": "LAB-MEMORY-001:ATTACK",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "experiment_memory_mismatch"
    empty = acme_client.post(
        "/memory/write",
        json={
            "memory_id": MEMORY_ID_MALICIOUS,
            "user_id": "applicant-web",
            "experiment_id": "",
        },
    )
    assert empty.status_code == 400
    assert empty.get_json()["block_reason"] == "malformed_experiment"


def test_concurrent_memory_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-MEMORY-001",
                "specimen_id": MEMORY_ATTACK_ID,
                "mode": mode,
                "execution": "live",
            },
        )
        results[mode] = response.get_json()

    threads = [
        threading.Thread(target=fire, args=("ATTACK",)),
        threading.Thread(target=fire, args=("RETEST",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    attack = results["ATTACK"]
    retest = results["RETEST"]
    assert attack["write_run_id"] != retest["write_run_id"]
    assert attack["recall_run_id"] != retest["recall_run_id"]
    assert attack["input_fingerprint"] == retest["input_fingerprint"] == MALICIOUS_HASH
    assert attack["runtime"]["profile"] == "vulnerable"
    assert retest["runtime"]["profile"] == "defended"
    assert attack["runtime"]["follow_on_decision"] == "ALLOW"
    assert retest["runtime"]["follow_on_decision"] == "DENY"
    assert attack["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert retest["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_experiment_bound_write_replaces_same_fixture_bytes(settings, memory):
    store = InProcessMemoryStore()
    first = run_memory_write(
        memory_id=MEMORY_ID_MALICIOUS,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        allow_replace_same_fixture=True,
    )
    second = run_memory_write(
        memory_id=MEMORY_ID_MALICIOUS,
        store=store,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        allow_replace_same_fixture=True,
    )
    assert first.terminal == "completed_allowed"
    assert second.terminal == "completed_allowed"
    assert first.run_id != second.run_id
    assert first.content_hash == second.content_hash == MALICIOUS_HASH
    recalled, err = store.recall(MEMORY_ID_MALICIOUS)
    assert err is None
    assert recalled is not None
    assert recalled.source_run_id == second.run_id
    assert recalled.content == MALICIOUS_MEMORY
    assert recalled.provenance == PROVENANCE
    assert recalled.trust == "untrusted_data"


def test_pi_mcp_rag_still_launch(acme_client):
    client, _calls = _wired_app(acme_client)
    pi = client.post(
        "/api/launch",
        json={"lab_id": "LAB-PI-001", "specimen_id": "ATK-002", "mode": "ATTACK", "execution": "live"},
    )
    mcp = client.post(
        "/api/launch",
        json={"lab_id": "LAB-MCP-001", "specimen_id": "MCP-002", "mode": "ATTACK", "execution": "live"},
    )
    rag = client.post(
        "/api/launch",
        json={"lab_id": "LAB-RAG-CONTEXT", "specimen_id": "RAG-001", "mode": "ATTACK", "execution": "live"},
    )
    assert pi.status_code == 200
    assert mcp.status_code == 200
    assert rag.status_code == 200
    assert "write_run_id" not in pi.get_json()
    assert rag.get_json()["runtime"]["follow_on_decision"] == "ALLOW"
