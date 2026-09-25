"""garak evaluation adapter and ExternalEvidence 1.0.0 boundaries."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.contract import (
    EVIDENCE_CLASS_EVALUATION,
    EXTERNAL_CONTRACT_VERSION,
)
from agentsec.external_evidence.garak import (
    GARAK_CORRELATION_METHOD,
    GARAK_TOOL,
    GarakEvaluationAdapter,
)
from agentsec.external_evidence.garak_pack import (
    GARAK_EVENT_NAME,
    GARAK_SOURCETYPE,
    events_from_pack,
)
from agentsec.external_evidence.semantics import (
    FAILED_EVALUATION_NE_EXPLOIT,
    GARAK_NE_AGENTSEC,
    GARAK_NE_PDP,
    GARAK_NE_SPLUNK,
    MODEL_RESPONSE_NE_RUNTIME_EXECUTION,
    PASSED_EVALUATION_NE_SAFE,
)

ROOT = Path(__file__).resolve().parents[2]
PACK = (
    ROOT
    / "docs"
    / "p1a-evidence"
    / "garak-aeb05718-1364-4143-8248-71dd6f27b07b"
)
RAW = PACK / "raw" / "garak-report.jsonl"
NORMALIZED = PACK / "normalized" / "evaluations.json"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"


def test_garak_adapter_emits_evaluation_and_preserves_native_result():
    records = GarakEvaluationAdapter(
        report_path=RAW,
        raw_evidence_ref="raw/garak-report.jsonl",
        ingest_timestamp="2026-09-24T23:15:00Z",
    ).records()
    assert len(records) == 1
    record = records[0]
    payload = record.to_dict()
    assert record.evidence_class == EVIDENCE_CLASS_EVALUATION == "evaluation"
    assert record.tool == GARAK_TOOL == "garak"
    assert record.tool_version == "0.17.0"
    assert payload["subject"]["id"] == "llama3.2:1b"
    assert payload["native"]["probe"] == "dan.Dan_11_0"
    assert payload["native"]["detector"] == "dan.DAN"
    assert payload["native"]["passed"] == 1
    assert payload["native"]["fails"] == 0
    assert payload["native"]["total_evaluated"] == 1
    assert payload["correlation"]["method"] == GARAK_CORRELATION_METHOD
    assert payload["correlation"]["method"] != "hash_join"


def test_raw_evidence_link_and_hash_are_exact():
    manifest = json.loads((PACK / "manifest.json").read_text(encoding="utf-8"))
    normalized = json.loads(NORMALIZED.read_text(encoding="utf-8"))
    digest = "sha256:" + hashlib.sha256(RAW.read_bytes()).hexdigest()
    record = normalized["records"][0]
    assert manifest["provenance"]["raw_evidence_ref"] == "raw/garak-report.jsonl"
    assert manifest["provenance"]["raw_evidence_sha256"] == digest
    assert record["raw_evidence_ref"] == "raw/garak-report.jsonl"
    assert record["raw_evidence_sha256"] == digest
    assert "/Users/" not in RAW.read_text(encoding="utf-8")
    assert "/Users/" not in json.dumps(manifest)


def test_unknown_optional_fields_stay_absent(tmp_path):
    rows = [
        {
            "entry_type": "start_run setup",
            "_config.version": "0.17.0",
            "plugins.target_type": "ollama.OllamaGeneratorChat",
        },
        {
            "entry_type": "init",
            "garak_version": "0.17.0",
            "start_time": "2026-09-24T00:00:00",
            "run": "native-evaluation-id",
        },
        {
            "entry_type": "eval",
            "probe": "example.Probe",
            "detector": "example.Detector",
            "passed": 0,
            "fails": 1,
            "nones": 0,
            "total_evaluated": 1,
            "total_processed": 1,
        },
    ]
    report = tmp_path / "minimal.jsonl"
    report.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    payload = GarakEvaluationAdapter(
        report_path=report,
        raw_evidence_ref="raw/minimal.jsonl",
    ).records()[0].to_dict()
    assert "id" not in payload["subject"]
    assert "name" not in payload["subject"]
    assert "framework_mappings" not in payload
    assert "ingest_timestamp" not in payload
    assert "severity" not in payload


def test_garak_hec_event_has_distinct_sourcetype_and_no_runtime_fields():
    events = events_from_pack(PACK)
    assert len(events) == 1
    payload = events[0]
    body = payload["event"]
    assert payload["sourcetype"] == GARAK_SOURCETYPE
    assert payload["sourcetype"] != "agentsec:scanner:finding"
    assert payload["sourcetype"] != "otel:agentic:json"
    assert body["event.name"] == GARAK_EVENT_NAME
    assert body["external"]["evidence_class"] == "evaluation"
    assert body["evaluation"]["native_result"] == "PASS"
    assert body["correlation"]["method"] == "identity_tuple"
    dumped = json.dumps(payload)
    assert "agentsec.run.id" not in dumped
    assert "agentsec.schema.version" not in dumped
    assert "CTRL-MCP-001" not in dumped
    props = (
        ROOT / "splunk_app" / "agentsec" / "default" / "props.conf"
    ).read_text(encoding="utf-8")
    assert "[agentsec:external:evaluation]" in props
    assert "[agentsec:scanner:finding]" in props


def test_external_contract_and_runtime_schema_versions_unchanged():
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "external.evaluation" not in schema
    assert "garak" not in schema.lower()


def test_evaluation_semantics_are_explicit():
    assert PASSED_EVALUATION_NE_SAFE == "PASSED EVALUATION != SAFE"
    assert FAILED_EVALUATION_NE_EXPLOIT == "FAILED EVALUATION != EXPLOIT CONFIRMED"
    assert MODEL_RESPONSE_NE_RUNTIME_EXECUTION.endswith("RUNTIME TOOL EXECUTION")
    assert GARAK_NE_PDP == "GARAK != PDP"
    assert GARAK_NE_SPLUNK == "GARAK != SPLUNK"
    assert GARAK_NE_AGENTSEC == "GARAK != AGENTSEC"


def test_garak_adapter_has_no_pdp_dependency():
    module_path = Path(inspect.getsourcefile(GarakEvaluationAdapter) or "")
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    assert not any(name.startswith("agentsec.mcp") for name in imports)
    text = module_path.read_text(encoding="utf-8")
    assert "authorize_tool" not in text
    assert "CTRL-MCP-001" not in text


def test_mcp_runtime_does_not_import_garak_or_external_evidence():
    for path in (ROOT / "src" / "agentsec" / "mcp").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "GarakEvaluationAdapter" not in text, path
        assert "agentsec.external_evidence" not in text, path
        assert "garak" not in text.lower(), path


def test_attribution_metadata_is_complete():
    pin = json.loads((ROOT / "tools" / "garak" / "pin.json").read_text(encoding="utf-8"))
    attribution = (ROOT / "docs" / "EXTERNAL_TOOL_ATTRIBUTIONS.md").read_text(
        encoding="utf-8"
    )
    assert pin["version"] == "0.17.0"
    assert pin["official_repository"] == "https://github.com/NVIDIA/garak"
    assert pin["license"] == "Apache-2.0"
    for label in (
        "TOOL",
        "PROJECT",
        "OFFICIAL REPOSITORY",
        "VERSION TESTED",
        "LICENSE",
        "PURPOSE",
        "HOW AGENTSEC USES IT",
        "INTEGRATION CLASS",
        "LIMITATIONS",
        "BUILT BY AGENTSEC",
        "INTEGRATED BY AGENTSEC",
        "REFERENCED / TAUGHT BY AGENTSEC",
    ):
        assert label in attribution
