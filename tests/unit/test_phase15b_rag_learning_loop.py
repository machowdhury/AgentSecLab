"""Phase 15B: LAB-RAG-CONTEXT LIVE learning loop. Schema 1.9.0. No DET-RAG."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from agentsec.events import content_hash
from agentsec.experiment import SCHEMA_VERSION
from agentsec.experiment_context import (
    LAB_RAG,
    attack_retest_fingerprint_pair,
    bind_experiment_for_rag,
    lookup_experiment,
)
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION, assert_learning_not_policy
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.rag.context_trust import RAG_FAIL_OPEN_REASON
from agentsec.rag.fixtures import DOCUMENT_ID_MALICIOUS, DOCUMENT_ID_NORMAL, MALICIOUS_DOCUMENT
from agentsec.rag.request_contract import parse_rag_retrieve_body

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "rag-live-learning-loop.md"
IMPL = ROOT / "docs" / "PHASE15B_RAG_LIVE_LEARNING_LOOP.md"
MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"


def test_phase15b_docs_exist():
    assert IMPL.is_file()
    assert NOTE.is_file()
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")
    assert (ROOT / "docs" / "PHASE15B_RAG_ATTACK_SERVICE_LAUNCH_CONTRACT.md").is_file()
    assert (ROOT / "docs" / "PHASE15B_RAG_GUIDED_INVESTIGATIONS.md").is_file()
    assert (ROOT / "docs" / "PHASE15B_SECURITY_BOUNDARY_REVIEW.md").is_file()


def test_schema_unchanged_and_no_det_rag():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-RAG" not in saved
    assert not list((ROOT / "learning").rglob("DET-RAG*"))
    hunts = {path.name for path in (ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches").glob("Q-*.spl")}
    assert hunts == {"Q-RAG-CONTEXT-AUTHORITY.spl"}


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    assert_learning_not_policy("LAB-RAG-CONTEXT")
    manifest = validate_lab_manifest("LAB-RAG-CONTEXT")
    assert manifest["not_authorization"] is True
    assert manifest["control_id"] == "CTRL-RAG-CONTEXT-001"
    assert manifest["enforcement_control_id"] == "CTRL-MCP-001"


def test_rag_attack_retest_fingerprint_is_document_bytes():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_RAG)
    assert attack_fp == retest_fp == content_hash(MALICIOUS_DOCUMENT) == MALICIOUS_HASH
    attack = lookup_experiment("LAB-RAG-CONTEXT:ATTACK")
    retest = lookup_experiment("LAB-RAG-CONTEXT:RETEST")
    assert attack is not None and retest is not None
    assert attack.payload == retest.payload == MALICIOUS_DOCUMENT
    assert attack.document_id == retest.document_id == DOCUMENT_ID_MALICIOUS
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False
    baseline = lookup_experiment("LAB-RAG-CONTEXT:BASELINE")
    assert baseline is not None
    assert baseline.document_id == DOCUMENT_ID_NORMAL
    assert baseline.payload != MALICIOUS_DOCUMENT


def test_rag_launch_is_allowlisted():
    row = lookup_launch(
        lab_id="LAB-RAG-CONTEXT",
        specimen_id="RAG-001",
        mode="ATTACK",
        execution="live",
    )
    assert row is not None
    assert row.runtime_route == "rag_retrieve"
    assert row.intentionally_vulnerable is True
    retest = lookup_launch(
        lab_id="LAB-RAG-CONTEXT",
        specimen_id="RAG-001",
        mode="RETEST",
        execution="live",
    )
    assert retest is not None
    assert retest.profile == "defended"
    baseline = lookup_launch(
        lab_id="LAB-RAG-CONTEXT",
        specimen_id="RAG-BASELINE",
        mode="BASELINE",
        execution="live",
    )
    assert baseline is not None
    assert baseline.profile == "defended"


def test_rag_retrieve_authority_fields_remain_unknown():
    parsed = parse_rag_retrieve_body(
        {
            "document_id": DOCUMENT_ID_MALICIOUS,
            "experiment_id": "LAB-RAG-CONTEXT:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_customer_tier"],
            "trusted_document": True,
            "trusted_context": True,
            "document_trust": "trusted",
            "content": MALICIOUS_DOCUMENT,
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_rag_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_rag(
        experiment_id="LAB-RAG-CONTEXT:ATTACK",
        document_id=DOCUMENT_ID_NORMAL,
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_document_mismatch"
    unknown, unknown_err = bind_experiment_for_rag(
        experiment_id="LAB-RAG-CONTEXT:PWN",
        document_id=DOCUMENT_ID_MALICIOUS,
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"
    user, user_err = bind_experiment_for_rag(
        experiment_id="LAB-RAG-CONTEXT:ATTACK",
        document_id=DOCUMENT_ID_MALICIOUS,
        user_id="attacker-lab",
    )
    assert user is None
    assert user_err == "experiment_user_mismatch"


def test_live_rag_attack_and_retest_via_attack_service(acme_client):
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-RAG-CONTEXT",
            "specimen_id": "RAG-001",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-RAG-CONTEXT",
            "specimen_id": "RAG-001",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    a = attack.get_json()
    r = retest.get_json()
    assert attack.status_code == 200
    assert retest.status_code == 200
    assert a["run_id"] != r["run_id"]
    assert a["runtime"]["profile"] == "vulnerable"
    assert r["runtime"]["profile"] == "defended"
    assert a["runtime"]["context_control_decision"] == "OBSERVE"
    assert r["runtime"]["context_control_decision"] == "OBSERVE"
    assert a["runtime"]["follow_on_decision"] == "ALLOW"
    assert r["runtime"]["follow_on_decision"] == "DENY"
    assert a["runtime"]["follow_on_reason"] == RAG_FAIL_OPEN_REASON
    assert r["runtime"]["follow_on_reason"] == "tool_not_granted"
    assert a["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert r["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert a["runtime"]["handler_invoke_count"] == 1
    assert r["runtime"]["handler_invoke_count"] == 0
    assert a["input_fingerprint"] == r["input_fingerprint"] == MALICIOUS_HASH
    assert a["runtime"]["document_id"] == r["runtime"]["document_id"] == DOCUMENT_ID_MALICIOUS
    assert a["runtime"]["content_hash"] == r["runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["runtime"]["experiment_id"] == "LAB-RAG-CONTEXT:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-RAG-CONTEXT:RETEST"
    assert a["runtime"].get("schema_version", "1.9.0") == "1.9.0"
    assert calls[0][0] == "/rag/retrieve"
    assert "profile" not in calls[0][1]
    assert "content" not in calls[0][1]
    assert set(calls[0][1]) <= {"document_id", "user_id", "experiment_id"}
    assert "Q-RAG-CONTEXT-AUTHORITY" in a["search_handoff"]["reused_hunts"]
    assert "document.id" in a["search_handoff"]["instructions"][3]
    coded = coded_policy()
    assert coded.allowed_tools == ALLOWED_TOOLS == frozenset({"lookup_policy"})


def test_rag_browser_cannot_send_authority_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    for extra in (
        {"profile": "vulnerable"},
        {"allowed_tools": ["lookup_customer_tier"]},
        {"document_id": DOCUMENT_ID_MALICIOUS},
        {"trusted_document": True},
        {"python": "print(1)"},
        {"spl": "index=*"},
        {"content": MALICIOUS_DOCUMENT},
        {"AGENTSEC_SECURITY_PROFILE": "vulnerable"},
    ):
        body = {
            "lab_id": "LAB-RAG-CONTEXT",
            "specimen_id": "RAG-001",
            "mode": "ATTACK",
            "execution": "live",
            **extra,
        }
        response = client.post("/api/launch", json=body)
        assert response.status_code == 400, extra
        assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_rag_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-RAG-CONTEXT").get_data(as_text=True)
    assert "RAG / Retrieved Context" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "Predict before ATTACK" in html
    assert "lab_id: \"LAB-RAG-CONTEXT\"" in html
    assert "RAG-001" in html
    assert "CTRL-RAG-CONTEXT-001" in html
    assert "Q-RAG-CONTEXT-AUTHORITY" in html
    assert "document trust" in html.lower() or "document body" in html.lower()


def test_direct_rag_retrieve_without_experiment_id_keeps_auto_mode(acme_client):
    response = acme_client.post(
        "/rag/retrieve",
        json={"document_id": DOCUMENT_ID_MALICIOUS, "user_id": "applicant-web"},
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["testbed_mode"] == "BASELINE"
    assert body.get("experiment_id") in (None, "")
    assert body["profile"] == "defended"
    assert body["follow_on_decision"] == "DENY"
    assert body["lookup_customer_tier_handler_count"] == 0
    assert body["context_control_decision"] == "OBSERVE"


def test_direct_rag_experiment_mismatch_http_is_error(acme_client):
    response = acme_client.post(
        "/rag/retrieve",
        json={
            "document_id": DOCUMENT_ID_NORMAL,
            "user_id": "applicant-web",
            "experiment_id": "LAB-RAG-CONTEXT:ATTACK",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "experiment_document_mismatch"
    assert body["lookup_customer_tier_handler_count"] == 0
    empty = acme_client.post(
        "/rag/retrieve",
        json={
            "document_id": DOCUMENT_ID_MALICIOUS,
            "user_id": "applicant-web",
            "experiment_id": "",
        },
    )
    assert empty.status_code == 400
    assert empty.get_json()["block_reason"] == "malformed_experiment"


def test_concurrent_rag_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-RAG-CONTEXT",
                "specimen_id": "RAG-001",
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
    assert attack["run_id"] != retest["run_id"]
    assert attack["runtime"]["profile"] == "vulnerable"
    assert retest["runtime"]["profile"] == "defended"
    assert attack["runtime"]["testbed_mode"] == "ATTACK"
    assert retest["runtime"]["testbed_mode"] == "RETEST"
    assert attack["input_fingerprint"] == retest["input_fingerprint"] == MALICIOUS_HASH
    assert attack["runtime"]["lookup_customer_tier_handler_count"] == 1
    assert retest["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert os.environ.get("AGENTSEC_SECURITY_PROFILE") in (None, "defended")
    assert coded_policy().allowed_tools == frozenset({"lookup_policy"})


def test_pi_and_mcp_launches_still_work(acme_client):
    client, _calls = _wired_app(acme_client)
    pi = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-PI-001",
            "specimen_id": "ATK-002",
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    mcp = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-MCP-001",
            "specimen_id": "MCP-002",
            "mode": "RETEST",
            "execution": "live",
        },
    )
    assert pi.status_code == 200
    assert mcp.status_code == 200
    assert pi.get_json()["runtime"]["profile"] == "vulnerable"
    assert mcp.get_json()["runtime"]["blocked"] is True
    assert mcp.get_json()["runtime"]["handler_invoke_count"] == 0
