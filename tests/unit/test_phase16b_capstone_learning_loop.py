"""Phase 16B: LAB-AGENTSEC-CAPSTONE-001 LIVE learning loop. Schema 1.9.0. No DET-CAPSTONE."""

from __future__ import annotations

import threading
from pathlib import Path

from agentsec.events import content_hash
from agentsec.experiment import SCHEMA_VERSION
from agentsec.experiment_context import (
    LAB_CAPSTONE,
    attack_retest_fingerprint_pair,
    bind_experiment_for_memory,
    bind_experiment_for_rag,
    lookup_experiment,
)
from agentsec.investigations import validate_investigations
from agentsec.lab_manifest import validate_lab_manifest
from agentsec.launch_catalog import known_lab_ids, lookup_launch
from agentsec.learning_contract import LEARNING_METADATA_NOT_AUTHORIZATION, assert_learning_not_policy
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.memory.fixtures import MEMORY_ID_CAPSTONE_MALICIOUS, MEMORY_ID_CAPSTONE_NORMAL
from agentsec.memory.store import FIXTURES
from agentsec.memory.trust import MEMORY_FAIL_OPEN_REASON, interpret_recalled_content
from agentsec.rag.fixtures import (
    DOCUMENT_ID_MALICIOUS,
    DOCUMENT_ID_NORMAL,
    MALICIOUS_DOCUMENT,
    NORMAL_DOCUMENT,
)
from agentsec.rag.request_contract import parse_rag_retrieve_body

from tests.unit.test_phase14b_attack_service import _wired_app

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
NOTE = ROOT / "docs" / "learning-notes" / "agentsec-capstone-live-investigation.md"
IMPL = ROOT / "docs" / "PHASE16B_CAPSTONE_RUNTIME_IMPLEMENTATION.md"
MALICIOUS_HASH = "sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef"
NORMAL_HASH = "sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e"
CAPSTONE_ATTACK_ID = "CAPSTONE-001"

PHASE16B_DOCS = (
    IMPL,
    ROOT / "docs" / "PHASE16B_CAPSTONE_LIVE_VALIDATION.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_ATTACK_RETEST_EQUIVALENCE.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_CROSS_RUN_CORRELATION.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_SECURITY_BOUNDARY_REVIEW.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_GUIDED_INVESTIGATIONS.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_SPLUNK_VALIDATION.md",
    ROOT / "docs" / "PHASE16B_CAPSTONE_PROOF_MODEL.md",
    NOTE,
)


def test_phase16b_docs_exist():
    for path in PHASE16B_DOCS:
        assert path.is_file(), path
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")


def test_schema_unchanged_and_no_det_capstone():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-CAPSTONE" not in saved
    assert not list((ROOT / "learning").rglob("DET-CAPSTONE*"))
    hunts = {
        path.name
        for path in (ROOT / "learning" / "level_1" / "LAB-AGENTSEC-CAPSTONE-001" / "searches").glob("Q-*.spl")
    }
    assert hunts == set()


def test_learning_metadata_is_not_authorization():
    assert LEARNING_METADATA_NOT_AUTHORIZATION is True
    assert_learning_not_policy("LAB-AGENTSEC-CAPSTONE-001")
    manifest = validate_lab_manifest("LAB-AGENTSEC-CAPSTONE-001")
    assert manifest["not_authorization"] is True
    assert manifest["enforcement_control_id"] == "CTRL-MCP-001"
    assert manifest["control_id"] == "CTRL-MCP-001"
    assert "Splunk does not" in " ".join(manifest["limitations"])
    rows = validate_investigations("LAB-AGENTSEC-CAPSTONE-001")
    ids = [row["investigation_id"] for row in rows]
    assert ids[0].startswith("CAP-I1")
    assert ids[-1].startswith("CAP-I16")
    assert len(ids) == 16
    hunts = {row["related_hunt"] for row in rows}
    assert "Q-CAPSTONE" not in hunts
    assert "DET-CAPSTONE" not in hunts
    assert "Q-RAG-CONTEXT-AUTHORITY" in hunts
    assert "Q-MEMORY-CONTEXT-AUTHORITY" in hunts
    assert "Q-MCP-AUTHZ" in hunts
    assert "Q-GOAL-INTEGRITY-AUTHORITY" in hunts
    assert "Q-AGENT-DELEGATION-AUTHORITY" in hunts
    by_id = {row["investigation_id"]: row for row in rows}
    assert by_id["CAP-I14-ATTACK-VS-RETEST"]["investigation_kind"] == "paired_run"
    assert by_id["CAP-I14-ATTACK-VS-RETEST"]["studio_tab"] == "EVIDENCE"
    assert by_id["CAP-I16-CLASSIFY-PROOF"]["studio_tab"] == "PATH B · ANSWERS"
    prove = by_id["CAP-I16-CLASSIFY-PROOF"]
    blob = prove["hint_2"] + prove["security_interpretation"]
    assert "INCORRECT" in blob
    assert "Splunk" in blob
    goal = by_id["CAP-I12-GOAL-INTEGRITY-REQUIRED"]
    ident = by_id["CAP-I13-IDENTITY-DELEGATION-REQUIRED"]
    assert "NOT PRESENT IN THIS PACKET" in goal["expected_result_shape"]
    assert "NOT PRESENT IN THIS PACKET" in ident["expected_result_shape"]
    assert "limits" in goal["hint_2"].lower() or "instrumented" in goal["security_interpretation"].lower()


def test_seven_live_labs_include_capstone():
    labs = known_lab_ids()
    assert len(labs) == 7
    assert LAB_CAPSTONE in labs
    for lab_id in (
        "LAB-PI-001",
        "LAB-MCP-001",
        "LAB-RAG-CONTEXT",
        "LAB-MEMORY-001",
        "LAB-AGENT-GOAL-INTEGRITY-001",
        "LAB-AGENT-DELEGATION-001",
        "LAB-AGENTSEC-CAPSTONE-001",
    ):
        assert lab_id in labs


def test_capstone_attack_retest_fingerprint_is_rag_bytes():
    attack_fp, retest_fp = attack_retest_fingerprint_pair(LAB_CAPSTONE)
    assert attack_fp == retest_fp == content_hash(MALICIOUS_DOCUMENT) == MALICIOUS_HASH
    attack = lookup_experiment("LAB-AGENTSEC-CAPSTONE-001:ATTACK")
    retest = lookup_experiment("LAB-AGENTSEC-CAPSTONE-001:RETEST")
    baseline = lookup_experiment("LAB-AGENTSEC-CAPSTONE-001:BASELINE")
    assert attack is not None and retest is not None and baseline is not None
    assert attack.payload == retest.payload == MALICIOUS_DOCUMENT
    assert attack.document_id == retest.document_id == DOCUMENT_ID_MALICIOUS
    assert attack.memory_id == retest.memory_id == MEMORY_ID_CAPSTONE_MALICIOUS
    assert FIXTURES[MEMORY_ID_CAPSTONE_MALICIOUS] == MALICIOUS_DOCUMENT
    assert content_hash(FIXTURES[MEMORY_ID_CAPSTONE_MALICIOUS]) == MALICIOUS_HASH
    assert attack.profile != retest.profile
    assert attack.intentionally_vulnerable is True
    assert retest.intentionally_vulnerable is False
    assert baseline.document_id == DOCUMENT_ID_NORMAL
    assert baseline.payload == NORMAL_DOCUMENT
    assert baseline.memory_id == MEMORY_ID_CAPSTONE_NORMAL
    assert content_hash(NORMAL_DOCUMENT) == NORMAL_HASH
    assert baseline.payload != MALICIOUS_DOCUMENT


def test_capstone_launch_catalog_rows():
    attack = lookup_launch(
        lab_id="LAB-AGENTSEC-CAPSTONE-001",
        specimen_id=CAPSTONE_ATTACK_ID,
        mode="ATTACK",
        execution="live",
    )
    retest = lookup_launch(
        lab_id="LAB-AGENTSEC-CAPSTONE-001",
        specimen_id=CAPSTONE_ATTACK_ID,
        mode="RETEST",
        execution="live",
    )
    baseline = lookup_launch(
        lab_id="LAB-AGENTSEC-CAPSTONE-001",
        specimen_id="CAPSTONE-BASELINE",
        mode="BASELINE",
        execution="live",
    )
    assert attack is not None and retest is not None and baseline is not None
    assert attack.profile == "vulnerable"
    assert retest.profile == "defended"
    assert attack.runtime_route == "capstone_lifecycle"


def test_capstone_authority_fields_are_unknown_not_policy():
    parsed = parse_rag_retrieve_body(
        {
            "document_id": DOCUMENT_ID_MALICIOUS,
            "experiment_id": "LAB-AGENTSEC-CAPSTONE-001:ATTACK",
            "profile": "vulnerable",
            "allowed_tools": ["lookup_customer_tier"],
            "grant": True,
            "policy": "open",
            "content": MALICIOUS_DOCUMENT,
        }
    )
    assert parsed.ok is False
    assert parsed.error_reason == "unknown_fields"


def test_capstone_experiment_mismatch_is_error_not_vulnerable():
    ctx, err = bind_experiment_for_rag(
        experiment_id="LAB-AGENTSEC-CAPSTONE-001:ATTACK",
        document_id=DOCUMENT_ID_NORMAL,
        user_id="applicant-web",
    )
    assert ctx is None
    assert err == "experiment_document_mismatch"
    unknown, unknown_err = bind_experiment_for_rag(
        experiment_id="LAB-AGENTSEC-CAPSTONE-001:PWN",
        document_id=DOCUMENT_ID_MALICIOUS,
        user_id="applicant-web",
    )
    assert unknown is None
    assert unknown_err == "unknown_experiment"
    mem, mem_err = bind_experiment_for_memory(
        experiment_id="LAB-AGENTSEC-CAPSTONE-001:ATTACK",
        memory_id=MEMORY_ID_CAPSTONE_NORMAL,
        user_id="applicant-web",
    )
    assert mem is None
    assert mem_err == "experiment_memory_mismatch"


def test_persisted_rag_bytes_are_recognized_as_closed_follow_on():
    intent = interpret_recalled_content(MALICIOUS_DOCUMENT, memory_id=MEMORY_ID_CAPSTONE_MALICIOUS)
    assert intent is not None
    assert intent.tool_name == "lookup_customer_tier"
    assert intent.marker_recognized is True
    benign = interpret_recalled_content(NORMAL_DOCUMENT, memory_id=MEMORY_ID_CAPSTONE_NORMAL)
    assert benign is None


def test_live_capstone_attack_and_retest_via_attack_service(acme_client):
    before = coded_policy()
    client, calls = _wired_app(acme_client)
    attack = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENTSEC-CAPSTONE-001",
            "specimen_id": CAPSTONE_ATTACK_ID,
            "mode": "ATTACK",
            "execution": "live",
        },
    )
    retest = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENTSEC-CAPSTONE-001",
            "specimen_id": CAPSTONE_ATTACK_ID,
            "mode": "RETEST",
            "execution": "live",
        },
    )
    a = attack.get_json()
    r = retest.get_json()
    assert attack.status_code == 200, a
    assert retest.status_code == 200, r
    assert len({a["retrieve_run_id"], a["write_run_id"], a["recall_run_id"]}) == 3
    assert len({r["retrieve_run_id"], r["write_run_id"], r["recall_run_id"]}) == 3
    assert a["retrieve_run_id"] != r["retrieve_run_id"]
    assert a["write_run_id"] != r["write_run_id"]
    assert a["recall_run_id"] != r["recall_run_id"]
    assert a["run_id"] == a["recall_run_id"]
    assert a["runtime"]["profile"] == "vulnerable"
    assert r["runtime"]["profile"] == "defended"
    assert a["retrieve_runtime"]["context_control_decision"] == "OBSERVE"
    assert r["retrieve_runtime"]["context_control_decision"] == "OBSERVE"
    assert a["retrieve_runtime"].get("lookup_customer_tier_handler_count", 0) == 0
    assert r["retrieve_runtime"].get("lookup_customer_tier_handler_count", 0) == 0
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
    assert a["retrieve_runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["write_runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["runtime"]["content_hash"] == MALICIOUS_HASH
    assert r["retrieve_runtime"]["content_hash"] == MALICIOUS_HASH
    assert a["runtime"]["source_run_id"] == a["write_run_id"]
    assert r["runtime"]["source_run_id"] == r["write_run_id"]
    assert a["document_id"] == DOCUMENT_ID_MALICIOUS
    assert a["memory_id"] == MEMORY_ID_CAPSTONE_MALICIOUS
    assert a["runtime"]["experiment_id"] == "LAB-AGENTSEC-CAPSTONE-001:ATTACK"
    assert r["runtime"]["experiment_id"] == "LAB-AGENTSEC-CAPSTONE-001:RETEST"
    assert a["runtime"].get("goal_control_decision") in (None, "")
    assert a["runtime"].get("identity_control_decision") in (None, "")
    assert {path for path, _payload in calls} == {"/rag/retrieve", "/memory/write", "/memory/recall"}
    for _path, payload in calls:
        assert set(payload) <= {"document_id", "memory_id", "user_id", "experiment_id"}
        assert "profile" not in payload
        assert "content" not in payload
        assert "allowed_tools" not in payload
    assert "Q-RAG-CONTEXT-AUTHORITY" in a["search_handoff"]["reused_hunts"]
    assert a["search_handoff"]["copy_retrieve_run_id"] == a["retrieve_run_id"]
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools == ALLOWED_TOOLS == frozenset({"lookup_policy"})
    assert "lookup_customer_tier" not in after.allowed_tools


def test_capstone_baseline_does_not_execute_privileged_tool(acme_client):
    client, _calls = _wired_app(acme_client)
    response = client.post(
        "/api/launch",
        json={
            "lab_id": "LAB-AGENTSEC-CAPSTONE-001",
            "specimen_id": "CAPSTONE-BASELINE",
            "mode": "BASELINE",
            "execution": "live",
        },
    )
    body = response.get_json()
    assert response.status_code == 200, body
    assert body["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert body["runtime"]["follow_on_decision"] in (None, "")
    assert body["retrieve_runtime"]["context_control_decision"] == "OBSERVE"
    assert body["runtime"]["memory_control_decision"] == "OBSERVE"
    assert body["input_fingerprint"] == NORMAL_HASH
    assert "SAFE" not in (body.get("note") or "")


def test_capstone_browser_cannot_send_authority_on_launch(acme_client):
    client, calls = _wired_app(acme_client)
    for extra in (
        {"profile": "vulnerable"},
        {"allowed_tools": ["lookup_customer_tier"]},
        {"document_id": DOCUMENT_ID_MALICIOUS},
        {"memory_id": MEMORY_ID_CAPSTONE_MALICIOUS},
        {"content": MALICIOUS_DOCUMENT},
        {"python": "print(1)"},
        {"spl": "index=*"},
        {"grant": True},
        {"AGENTSEC_SECURITY_PROFILE": "vulnerable"},
    ):
        body = {
            "lab_id": "LAB-AGENTSEC-CAPSTONE-001",
            "specimen_id": CAPSTONE_ATTACK_ID,
            "mode": "ATTACK",
            "execution": "live",
            **extra,
        }
        response = client.post("/api/launch", json=body)
        assert response.status_code == 400, extra
        assert response.get_json()["error"] == "unknown_fields"
    assert calls == []


def test_capstone_attack_page_is_closed_launcher():
    from agentsec.attack_app import AcmeBankClient, create_app

    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-AGENTSEC-CAPSTONE-001").get_data(as_text=True)
    assert "Lending Assistant Investigation" in html
    assert "RAG Memory MCP Authorization Failure" not in html
    assert "Launch ATTACK (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "Run ATTACK first" in html
    assert 'const labId = "LAB-AGENTSEC-CAPSTONE-001"' in html
    assert CAPSTONE_ATTACK_ID in html
    assert "CTRL-MCP-001" in html
    assert "Influence · intent · authority · invocation · completion · outcome" in html
    assert "RETRIEVE run · context entry" in html
    assert "WRITE run · fixture-equivalent persistence" in html
    assert "RECALL run · request / decision / runtime" in html
    assert "source_run_id · WRITE→RECALL link" in html
    assert "Copy Primary Run ID" in html
    assert "Copy Retrieve Run ID" in html
    assert "Copy Write Run ID" in html
    assert "Copy Recall Run ID" in html
    assert "Copy Source Run ID" in html
    assert "ToolRegistry count proves invocation began, not successful completion" in html
    assert "mcp.completed" in html
    assert "mcp.failed" in html
    assert "fixture-equivalent bytes · hash verified" in html
    assert "Goal Integrity and Identity/Delegation event families" in html
    assert "Cryptographic authentication, OAuth/OIDC" in html
    assert "ERROR · runtime or dependency failure" in html
    assert "body: JSON.stringify({lab_id: labId, specimen_id: specimenId, mode, execution: \"live\"})" in html
    bank = (ROOT / "src" / "agentsec" / "bank_app.py").read_text(encoding="utf-8")
    assert '@app.post("/capstone' not in bank
    assert '@app.post("/a2a' not in bank


def test_concurrent_capstone_attack_and_retest_do_not_leak_profile(acme_client):
    client, _calls = _wired_app(acme_client)
    results = {}

    def fire(mode):
        response = client.post(
            "/api/launch",
            json={
                "lab_id": "LAB-AGENTSEC-CAPSTONE-001",
                "specimen_id": CAPSTONE_ATTACK_ID,
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
    assert attack["retrieve_run_id"] != retest["retrieve_run_id"]
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


def test_no_capstone_http_route_or_schema_bump():
    bank = (ROOT / "src" / "agentsec" / "bank_app.py").read_text(encoding="utf-8")
    assert '@app.post("/capstone' not in bank
    assert '@app.post("/a2a' not in bank
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "1.10.0" not in schema
