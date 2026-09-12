"""Contract tests for LAB-MCP-001 search files.

These tests do not execute SPL against Splunk. Live execution is recorded in
docs/PHASE3C_MCP_SPLUNK_VALIDATION.md.
"""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED_IDS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-SCOPE",
    "Q-MCP-PARAMS",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
    "Q-MCP-RESULT",
    "Q-MCP-RESULT-TRUST",
)

REQUIRED_METADATA = (
    "id",
    "spl_file",
    "doc_file",
    "security_question",
    "required_fields",
    "validation_status",
)

PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.profile",
    "agentsec.pipeline.outcome",
    "session.id",
    "mcp.session.id",
    "gen_ai.tool.call.arguments",
)

EXPENSIVE_COMMANDS = ("| join ", "| transaction ", "| map ", "| append ")

DOC_REQUIRED_HEADINGS = (
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

ROOT = Path(__file__).resolve().parents[2]
SEARCH_DIR = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
CATALOG_PATH = SEARCH_DIR / "catalog.json"


def _catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _all_spl_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(SEARCH_DIR.glob("*.spl")))


def test_expected_search_files_exist():
    catalog = _catalog()
    assert CATALOG_PATH.is_file()
    ids = [query["id"] for query in catalog["queries"]]
    assert ids == list(REQUIRED_IDS)
    for query in catalog["queries"]:
        assert (SEARCH_DIR / query["spl_file"]).is_file(), query["spl_file"]
        assert (SEARCH_DIR / query["doc_file"]).is_file(), query["doc_file"]


def test_query_metadata_complete():
    catalog = _catalog()
    for query in catalog["queries"]:
        missing = [key for key in REQUIRED_METADATA if key not in query]
        assert missing == [], f"{query.get('id')}: missing {missing}"
        assert query["validation_status"] in {"VALIDATED", "NOT VALIDATED", "FAILED"}
        assert query["required_fields"], query["id"]
        assert "event.name" in query["required_fields"]
        assert "agentsec.run.id" in query["required_fields"]


def test_search_documentation_complete():
    catalog = _catalog()
    docs = [SEARCH_DIR / query["doc_file"] for query in catalog["queries"]]
    docs.append(SEARCH_DIR / catalog["positive_control"]["doc_file"])
    for path in docs:
        text = path.read_text(encoding="utf-8")
        for heading in DOC_REQUIRED_HEADINGS:
            assert heading in text, f"{path.name} missing {heading}"


def test_required_field_references_appear_in_spl():
    catalog = _catalog()
    for query in catalog["queries"]:
        spl = (SEARCH_DIR / query["spl_file"]).read_text(encoding="utf-8")
        for field in query["required_fields"]:
            assert field in spl, f"{query['id']} SPL missing required field {field}"


def test_prohibited_conceptual_fields_are_absent_from_spl():
    spl = _all_spl_text()
    for field in PROHIBITED_FIELDS:
        assert field not in spl, f"SPL must not use conceptual field {field}"
    catalog = _catalog()
    assert catalog["prohibited_fields"] == list(PROHIBITED_FIELDS)
    for query in catalog["queries"]:
        for field in query["required_fields"]:
            assert field not in PROHIBITED_FIELDS


def test_does_not_use_agentsec_event_name():
    spl = _all_spl_text()
    assert "agentsec.event.name" not in spl
    assert "event.name" in spl
    for query in _catalog()["queries"]:
        assert "agentsec.event.name" not in query["required_fields"]


def test_query_ids_are_stable():
    catalog = _catalog()
    assert catalog["lab.id"] == "LAB-MCP-001"
    assert catalog["schema.version"] == "1.1.0"
    assert catalog["index"] == "agentsec_telemetry"
    assert catalog["sourcetype"] == "otel:agentic:json"
    assert catalog["run_id_token"] == "__RUN_ID__"
    for query in catalog["queries"]:
        spl = (SEARCH_DIR / query["spl_file"]).read_text(encoding="utf-8")
        assert "__RUN_ID__" in spl
        assert "$run_id$" not in spl
        assert query["id"] in query["spl_file"]
        assert spl.startswith("index=agentsec_telemetry")


def test_authz_distinguishes_allow_deny_error():
    spl = (SEARCH_DIR / "Q-MCP-AUTHZ.spl").read_text(encoding="utf-8")
    assert "agentsec.control.decision" in spl
    doc = (SEARCH_DIR / "Q-MCP-AUTHZ.md").read_text(encoding="utf-8")
    assert "ALLOW" in doc and "DENY" in doc and "ERROR" in doc
    assert "Do not collapse ERROR into DENY" in doc


def test_expensive_commands_are_absent():
    spl = _all_spl_text()
    for command in EXPENSIVE_COMMANDS:
        assert command not in spl, f"SPL must not use {command.strip()}"


def test_schema_field_names_match_emitters():
    events = (ROOT / "src" / "agentsec" / "events.py").read_text(encoding="utf-8")
    catalog = _catalog()
    emitter_fields = {
        "gen_ai.tool.name",
        "mcp.method.name",
        "agentsec.mcp.requested_scope",
        "agentsec.mcp.allowed_scope",
        "agentsec.mcp.result.trust",
        "agentsec.principal.id",
        "agentsec.control.decision",
    }
    for field in emitter_fields:
        assert field in events
        assert any(field in query["required_fields"] for query in catalog["queries"]), field


def _violation_core(spl: str) -> str:
    start = spl.index("| eval run_id=mvindex")
    end = spl.index("| table")
    return spl[start:end].strip()


def test_positive_control_is_simulated_makeresults():
    catalog = _catalog()
    control = catalog["positive_control"]
    assert control["evidence_class"] == "SIMULATED"
    assert control["generator"] == "makeresults"
    assert control["indexed"] is False
    assert control["expected_violation_rows"] == 1
    assert control["id"] not in REQUIRED_IDS
    spl_path = SEARCH_DIR / control["spl_file"]
    doc_path = SEARCH_DIR / control["doc_file"]
    assert spl_path.is_file()
    assert doc_path.is_file()
    spl = spl_path.read_text(encoding="utf-8")
    doc = doc_path.read_text(encoding="utf-8")
    assert spl.lstrip().startswith("| makeresults")
    assert "index=agentsec_telemetry" not in spl
    assert not any(line.lstrip().startswith("index=") for line in spl.splitlines())
    assert 'evidence_class="SIMULATED"' in spl
    assert "agentsec.control.decision" in spl and "DENY" in spl
    assert "agentsec.mcp.started" in spl
    assert "This is **not** OBSERVED runtime behavior" in doc
    live = (SEARCH_DIR / "Q-MCP-AFTER-DENY.spl").read_text(encoding="utf-8")
    assert _violation_core(spl) == _violation_core(live)
