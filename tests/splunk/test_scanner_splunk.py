"""Scanner Splunk hunt contracts (Phase 9C).

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE9C_SCANNER_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH = ROOT / "learning" / "level_1" / "LAB-MCP-CATALOG" / "searches"
MCP001 = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
DOCS = ROOT / "docs"
APP = ROOT / "splunk_app" / "agentsec" / "default"

IDS = (
    "Q-SCANNER-WHO",
    "Q-SCANNER-ARTIFACT",
    "Q-SCANNER-FINDINGS",
    "Q-SCANNER-RUNTIME-CORRELATION",
)

DOC_HEADINGS = (
    "## Required fields (indexed names)",
    "## SPL",
    "## Line-by-line explanation",
    "## Expected result",
    "## Actual result",
    "## Validated run.id / test data",
    "## Performance notes",
    "## Known limitations",
    "## No-data semantics",
)

EXPENSIVE = ("| join ", "| transaction ", "| map ", "| append ")
REUSED = ("Q-MCP-WHO", "Q-MCP-AUTHZ", "Q-MCP-EXECUTED", "Q-MCP-CATALOG-AUTHORITY")


def _catalog() -> dict:
    return json.loads((SEARCH / "scanner_catalog.json").read_text(encoding="utf-8"))


def test_scanner_sourcetype_in_props_not_security_event():
    props = (APP / "props.conf").read_text(encoding="utf-8")
    assert "[agentsec:scanner:finding]" in props
    assert "INDEXED_EXTRACTIONS = json" in props
    assert "KV_MODE = none" in props
    schema = (ROOT / "schemas" / "security_event.schema.json").read_text(encoding="utf-8")
    assert '"const": "1.7.0"' in schema
    assert "agentsec.scanner" not in schema
    assert "agentsec:scanner:finding" not in schema


def test_published_scanner_searches_and_binds():
    catalog = _catalog()
    assert catalog["sourcetype"] == "agentsec:scanner:finding"
    assert catalog["scan_id_token"] == "__SCAN_ID__"
    assert catalog["description_sha256_token"] == "__DESCRIPTION_SHA256__"
    ids = [query["id"] for query in catalog["queries"]]
    assert ids == list(IDS)
    for query in catalog["queries"]:
        spl = (SEARCH / query["spl_file"]).read_text(encoding="utf-8")
        doc = (SEARCH / query["doc_file"]).read_text(encoding="utf-8")
        assert spl.startswith("index=agentsec_telemetry")
        assert "sourcetype=agentsec:scanner:finding" in spl or query["id"] == "Q-SCANNER-RUNTIME-CORRELATION"
        assert "schema.version" not in spl
        for heading in DOC_HEADINGS:
            assert heading in doc, heading
        for command in EXPENSIVE:
            assert command not in spl
        assert "VALIDATED" in doc
    who = (SEARCH / "Q-SCANNER-WHO.spl").read_text(encoding="utf-8")
    assert "__SCAN_ID__" in who
    corr = (SEARCH / "Q-SCANNER-RUNTIME-CORRELATION.spl").read_text(encoding="utf-8")
    assert "__DESCRIPTION_SHA256__" in corr
    assert "artifact.description_sha256" in corr
    assert "agentsec.content.hash" in corr
    assert "CTRL-MCP-METADATA-001" in corr


def test_no_runtime_authorization_dependency_in_scanner_spl():
    for name in IDS:
        spl = (SEARCH / f"{name}.spl").read_text(encoding="utf-8")
        assert "CTRL-MCP-001" not in spl or name == "Q-SCANNER-RUNTIME-CORRELATION"
        assert "coded_policy" not in spl
        assert "AllowTicket" not in spl
    corr = (SEARCH / "Q-SCANNER-RUNTIME-CORRELATION.spl").read_text(encoding="utf-8")
    assert "CTRL-MCP-001" not in corr


def test_existing_mcp_searches_unmodified_contract():
    authz = (MCP001 / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8")
    assert authz.startswith(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0"
    )
    assert "agentsec:scanner:finding" not in authz
    catalog = (SEARCH / "Q-MCP-CATALOG-AUTHORITY.spl").read_text(encoding="utf-8")
    assert catalog.startswith("index=agentsec_telemetry sourcetype=otel:agentic:json")
    assert "agentsec:scanner:finding" not in catalog
    det = (MCP001 / "DET-MCP-001.spl").read_text(encoding="utf-8")
    assert "scanner" not in det.lower()
    saved = (APP / "savedsearches.conf").read_text(encoding="utf-8")
    assert "DET-SCANNER" not in saved
    assert "Q-SCANNER" not in saved
    macro = (APP / "macros.conf").read_text(encoding="utf-8")
    assert "sourcetype=otel:agentic:json" in macro
    assert "agentsec:scanner:finding" not in macro


def test_no_detector_or_studio_for_scanner():
    assert not list(SEARCH.glob("DET-SCANNER*"))
    assert not list(MCP001.glob("DET-SCANNER*"))
    views = APP / "data" / "ui" / "views"
    scanner_views = {path.name for path in views.glob("*scanner*")}
    assert scanner_views <= {"ws_lab_scanner_runtime_evidence.xml"}
    catalog = json.loads((SEARCH / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["detection"]["id"] == "DET-MCP-001"
    rejected = {item["id"] for item in _catalog()["queries_not_created"]}
    assert "DET-SCANNER-HIGH" in rejected
    assert "Q-SCANNER-PASS-FAIL" in rejected


def test_phase9c_documentation_and_inventory():
    required = (
        DOCS / "PHASE9C_SCANNER_SPLUNK_VALIDATION.md",
        DOCS / "SCANNER_SPLUNK_FIELD_CONTRACT.md",
        DOCS / "SCANNER_SEARCH_CONTRACT.md",
        DOCS / "reviews" / "splunk-ko-review-scanner-evidence-2026-09-16.md",
        DOCS / "learning-notes" / "scanner-runtime-correlation.md",
        DOCS / "IMPLEMENTATION_STATUS.md",
        DOCS / "SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md",
    )
    for path in required:
        assert path.is_file(), path
    phase = (DOCS / "PHASE9C_SCANNER_SPLUNK_VALIDATION.md").read_text(encoding="utf-8")
    for needle in (
        "PASS — SCANNER EVIDENCE SPLUNK VALIDATED",
        "COMPLETE",
        "dc(_raw)",
        "agentsec:scanner:finding",
        "1.5.0",
        "scan_executed_zero_findings",
        "PROMPT INJECTION",
        "HIGH",
        "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1",
        "a0937bff-31a5-453a-99bf-47d7b5148ce4",
        "23c222ea-6a87-40b7-a3e9-f12a5b572fa1",
        "SCANNER FINDING != AUTHORIZATION DECISION",
        "NOT APPLICABLE",
        "Phase 9D not started",
        "No detector",
        "No Studio",
    ):
        assert needle in phase, needle
    notes = (DOCS / "learning-notes" / "scanner-runtime-correlation.md").read_text(
        encoding="utf-8"
    )
    assert "## What I should now be able to explain" in notes
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    assert "9C" in status
    assert "SCANNER EVIDENCE SPLUNK VALIDATED" in status
    inventory = (DOCS / "SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md").read_text(encoding="utf-8")
    assert "Q-SCANNER-WHO" in inventory
    assert "agentsec:scanner:finding" in inventory
