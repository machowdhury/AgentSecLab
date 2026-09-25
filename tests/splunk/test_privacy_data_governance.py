"""Offline contracts for the L8 privacy workbench."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.policy import coded_policy

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-PRIVACY-DATA-GOVERNANCE-001"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_privacy_data_governance.xml"


def _json(name: str) -> dict:
    return json.loads((LAB / name).read_text(encoding="utf-8"))


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _markdown(layouts: tuple[str, ...] | None = None) -> str:
    definition = _definition()
    ids = definition["visualizations"] if layouts is None else [
        row["item"] for layout_id in layouts
        for row in definition["layout"]["layoutDefinitions"][layout_id]["structure"]
    ]
    return "\n".join(definition["visualizations"][viz_id]["options"]["markdown"] for viz_id in ids)


def test_l8_curriculum_navigation_and_artifacts():
    curriculum = json.loads((ROOT / "learning" / "academy" / "curriculum.json").read_text(encoding="utf-8"))
    assert [row["id"] for row in curriculum["levels"]][-3:] == ["L6", "L7", "L8"]
    assert next(row for row in curriculum["levels"] if row["id"] == "L7")["next"] == "L8"
    level = next(row for row in curriculum["levels"] if row["id"] == "L8")
    assert level["exit"] == "PRIVACY-AWARE SECURITY ARCHITECT"
    assert level["labs"][0]["lab_id"] == "LAB-PRIVACY-DATA-GOVERNANCE-001"
    assert curriculum["nav_collections"][-1] == {
        "label": "Privacy & Data Governance",
        "views": ["ws_lab_privacy_data_governance"],
    }
    for path in (
        DEFINITION, VIEW, LAB / "README.md", LAB / "incident.md",
        LAB / "data-map.json", LAB / "investigations.json",
        LAB / "privacy-evidence-ledger-template.md",
        LAB / "privacy-threat-model-template.md",
        LAB / "incident-report-template.md", LAB / "knowledge-check.md",
        LAB / "searches" / "Q-PRIVACY-CANDIDATES.spl",
        LAB / "searches" / "Q-PRIVACY-TRACE.spl",
        LAB / "searches" / "Q-PRIVACY-COMPARE.spl",
        ROOT / "scripts" / "build_lab_privacy_data_governance_dashboard.py",
    ):
        assert path.is_file(), path


def test_lifecycle_classification_minimization_and_trace():
    data = _json("data-map.json")
    assert data["synthetic_only"] is True
    assert [row["stage"] for row in data["lifecycle"]] == [
        "COLLECT", "INGEST", "CLASSIFY", "USE", "RETRIEVE", "INFER", "ACT",
        "STORE / REMEMBER", "LOG", "SHARE", "RETAIN", "DELETE",
    ]
    assert data["required_fields"] == ["customer_id", "preferred_channel"]
    assert set(data["full_record"]) - set(data["minimized_record"]) == {
        "account_balance_band", "email", "internal_case_note", "postal_address",
    }
    assert all(row["scenario_sensitivity"] for row in data["classification"])
    assert data["not_in_incident_trace"] == {
        "model_context": "NOT MODELED", "rag": "NOT MODELED",
        "memory": "NOT MODELED", "external_service": "NOT MODELED",
        "production_database": "NOT MODELED",
    }


def test_progressive_hints_answer_gating_and_failure_states():
    definition = _definition()
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]] == [
        "FOUNDATIONS", "DATA MAP", "TRACE", "INVESTIGATE", "MINIMIZE",
        "THREAT MODEL", "DESIGN", "PATH B · REVIEW",
    ]
    investigations = _json("investigations.json")
    assert [row["id"] for row in investigations["hints"]] == ["HINT_1", "HINT_2", "HINT_3", "HINT_4"]
    assert investigations["answer_gating"] == "PEDAGOGICAL"
    assert investigations["progress_persistence"] is False
    failures = " ".join(investigations["failure_states"].values())
    assert "NO EVIDENCE FOUND" in failures
    assert "not SAFE" in failures
    early = _markdown(("layout_foundations", "layout_map", "layout_trace", "layout_investigate", "layout_minimize", "layout_model", "layout_design"))
    review = _markdown(("layout_review",))
    for answer in ("The bounded task requires", "full specimen additionally supplied", "produced seven distinct correlated event payloads"):
        assert answer not in early
        assert answer in review


def test_rag_memory_tool_logging_and_privacy_threat_reasoning():
    md = _markdown()
    for needle in (
        "AUTHORIZED ACTION != AUTHORIZED DATA USE",
        "retrieval authorization is separate from tool authorization",
        "Privacy/retention failure is not identical to memory poisoning",
        "CTRL-MCP-001 authorizes the tool",
        "telemetry while increasing exposure",
        "ASSET → SOURCE → PROCESSOR → BOUNDARY → PURPOSE",
        "INPUT MINIMIZATION", "ARGUMENT FILTERING", "RETENTION", "DELETE",
        "ALLOW + MINIMIZED DATA + EXPECTED EXECUTION",
    ):
        assert needle.lower() in md.lower(), needle
    for spl in ("Q-PRIVACY-CANDIDATES.spl", "Q-PRIVACY-TRACE.spl", "Q-PRIVACY-COMPARE.spl"):
        text = (LAB / "searches" / spl).read_text(encoding="utf-8")
        assert "index=agentsec_telemetry" in text
        assert "sourcetype=otel:agentic:json" in text
        assert "index=*" not in text
        assert "transaction" not in text


def test_evidence_ledger_communications_and_framework_disclaimers():
    ledger = (LAB / "privacy-evidence-ledger-template.md").read_text(encoding="utf-8")
    report = (LAB / "incident-report-template.md").read_text(encoding="utf-8")
    model = (LAB / "privacy-threat-model-template.md").read_text(encoding="utf-8")
    for term in ("Claim", "Evidence", "Data involved", "Boundary", "Confidence", "Missing evidence"):
        assert term.lower() in ledger.lower()
    for term in ("Engineering", "Operations", "Leadership"):
        assert term in report
    for term in ("Asset", "Source", "Processor", "Purpose", "Exposure", "Persistence", "Residual risk"):
        assert term.lower() in model.lower()
    framework = (ROOT / "docs" / "PRIVACY_FRAMEWORK_VALIDATION.md").read_text(encoding="utf-8")
    md = _markdown()
    for term in (
        "EDUCATIONAL MAPPING", "not compliance validation", "not legal determination",
        "not certification", "not complete framework coverage", "NEEDS_EXTERNAL_VALIDATION",
        "NIST Privacy Framework 1.0", "NIST AI RMF 1.0", "OWASP",
    ):
        assert term.lower() in framework.lower()
        assert term.lower() in md.lower()


def test_security_semantics_schema_contract_and_secret_hygiene():
    assert SCHEMA_VERSION == "1.9.0"
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert coded_policy().allowed_tools == frozenset({"lookup_policy"})
    assert "external" not in inspect.signature(authorize_tool).parameters
    md = _markdown()
    for term in ("Authentication", "human approval", "cryptographic delegation"):
        assert term.lower() in md.lower()
    assert "NOT MODELED" in md
    content = "\n".join(path.read_text(encoding="utf-8") for path in LAB.rglob("*") if path.is_file())
    assert "BEGIN PRIVATE KEY" not in content
    assert "BEGIN CERTIFICATE" not in content
    assert "example.invalid" in content
    assert "sk_live_" not in content
