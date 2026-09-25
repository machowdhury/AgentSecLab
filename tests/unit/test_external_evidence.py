"""Vendor-neutral external evidence contract. Not a PDP. Not schema 1.9.0."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from agentsec.experiment import SCHEMA_VERSION
from agentsec.external_evidence.cisco import cisco_normalized_to_external
from agentsec.external_evidence.contract import (
    CORRELATION_KEY_DESCRIPTION_CONTENT_HASH,
    CORRELATION_METHOD_HASH_JOIN,
    EVIDENCE_CLASS_FINDING,
    EXTERNAL_CONTRACT_VERSION,
    ExternalEvidence,
)
from agentsec.external_evidence.semantics import (
    HASH_MATCH_NE_CAUSALITY,
    SCANNER_HIGH_NE_DENY,
    ZERO_FINDINGS_NE_SAFE,
)
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.fixtures import MCP_POLICY_SCOPE
from agentsec.mcp.policy import coded_policy
from agentsec.scanners.hec_events import SOURCETYPE, events_from_pack
from agentsec.scanners.models import (
    ADAPTER_VERSION,
    ARTIFACT_TYPE_MCP_CATALOG,
    EVIDENCE_CLASS,
    ArtifactIdentity,
    NativeFinding,
    NormalizedScan,
    ScannerIdentity,
)

ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = ROOT / "src" / "agentsec" / "mcp"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
NORMAL_PACK = ROOT / "docs" / "phase9b-evidence" / "normal-b3061c4e-7a81-445c-8fd8-3108dd14c419"
MALICIOUS_PACK = ROOT / "docs" / "phase9b-evidence" / "malicious-7ae3ea64-4e7a-40fe-943f-3e582bce5ee8"


def _scanner() -> ScannerIdentity:
    return ScannerIdentity(
        name="cisco-ai-mcp-scanner",
        version="4.8.4",
        repository="https://github.com/cisco-ai-defense/mcp-scanner",
        commit="be87b90d88bca2527a6e2075769a7608decd8f27",
        license="Apache-2.0",
        package="cisco-ai-mcp-scanner",
        cli="mcp-scanner",
        wheel_sha256="cd25f68d4f22c6e40b74578a8c28e2dfc350f69ebf4122801d9d05f804e769cd",
    )


def _artifact(*, fixture: str, description_sha256: str, created_at: str) -> ArtifactIdentity:
    return ArtifactIdentity(
        path="input/tools.json",
        sha256="sha256:deadbeef",
        bytes_len=1,
        fixture=fixture,
        created_at=created_at,
        description_sha256=description_sha256,
        tool_count=2,
    )


def _scan(*, findings: tuple[NativeFinding, ...], fixture: str, desc: str) -> NormalizedScan:
    return NormalizedScan(
        scan_id="scan-test",
        evidence_class=EVIDENCE_CLASS,
        scanner=_scanner(),
        artifact=_artifact(fixture=fixture, description_sha256=desc, created_at="2026-09-16T05:36:55Z"),
        findings=findings,
        classification="DETECTED_BY_SCANNER" if findings else None,
        static_scan=True,
        target_executed=False,
        network_required=False,
        llm_used=False,
        exit_code=0,
        timed_out=False,
        parse_error=None,
        raw_output_sha256="sha256:" + "ab" * 32,
        adapter_version=ADAPTER_VERSION,
        stdout_sha256="sha256:" + "ab" * 32,
        stderr_sha256="sha256:" + "00" * 32,
        finding_count=len(findings),
        limitations=(),
    )


def test_schema_19_unchanged_and_external_contract_separate():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    assert "external.evidence_class" not in schema
    assert EXTERNAL_CONTRACT_VERSION == "1.0.0"


def test_unknown_evidence_class_rejected():
    with pytest.raises(ValueError, match="unknown external evidence_class"):
        ExternalEvidence(evidence_class="authorization", evidence_id="x")


def test_optional_fields_omitted_when_unknown():
    record = ExternalEvidence(evidence_class=EVIDENCE_CLASS_FINDING, evidence_id="only-id")
    payload = record.to_dict()
    assert payload == {
        "contract.version": EXTERNAL_CONTRACT_VERSION,
        "evidence_class": "finding",
        "evidence_id": "only-id",
    }
    assert "severity" not in payload
    assert "provider" not in payload
    assert "correlation" not in payload


def test_cisco_adapter_maps_finding_and_preserves_native_fields():
    row = NativeFinding(
        native_rule_id="PROMPT INJECTION",
        native_category="PROMPT INJECTION",
        native_severity="HIGH",
        native_confidence=None,
        title="PROMPT INJECTION",
        summary="Detected 1 threat: prompt injection",
        tool_name="lookup_policy",
        analyzer="yara_analyzer",
    )
    desc = "sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1"
    records = cisco_normalized_to_external(_scan(findings=(row,), fixture="MALICIOUS", desc=desc))
    assert len(records) == 1
    payload = records[0].to_dict()
    assert payload["evidence_class"] == "finding"
    assert payload["producer_class"] == "OBSERVED_SCANNER"
    assert payload["severity"] == "HIGH"
    assert payload["correlation"]["method"] == CORRELATION_METHOD_HASH_JOIN
    assert payload["correlation"]["key"] == CORRELATION_KEY_DESCRIPTION_CONTENT_HASH
    assert payload["correlation"]["value"] == desc
    assert payload["native"]["native_rule_id"] == "PROMPT INJECTION"
    assert payload["native"]["analyzer"] == "yara_analyzer"
    assert "native_confidence" not in payload["native"]
    assert payload["raw_evidence_ref"] == "raw/scanner-output.json"


def test_zero_findings_is_finding_class_not_safe():
    records = cisco_normalized_to_external(
        _scan(
            findings=(),
            fixture="NORMAL",
            desc="sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3",
        )
    )
    assert len(records) == 1
    payload = records[0].to_dict()
    assert payload["evidence_class"] == "finding"
    assert payload["native"]["finding_count"] == 0
    assert "severity" not in payload
    assert ZERO_FINDINGS_NE_SAFE.startswith("ZERO FINDINGS")


def test_canonical_raw_hash_matches_file():
    for pack in (NORMAL_PACK, MALICIOUS_PACK):
        raw = (pack / "raw" / "scanner-output.json").read_bytes()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["provenance"]["raw_output_sha256"] == digest
        assert manifest["artifact"]["path"] == "input/tools.json"
        assert "/Users/" not in json.dumps(manifest)
        events = events_from_pack(pack)
        for payload in events:
            assert payload["sourcetype"] == SOURCETYPE
            assert payload["event"]["external"]["evidence_class"] == "finding"
            assert payload["event"]["correlation"]["method"] == "hash_join"
            assert "agentsec.run.id" not in payload["event"]
            assert payload["event"]["external"]["raw_evidence_sha256"] == digest


def test_scanner_high_does_not_change_authorization():
    policy = coded_policy()
    finding = ExternalEvidence(
        evidence_class="finding",
        evidence_id="ignored",
        severity="HIGH",
    )
    granted = authorize_tool(
        tool_name="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        profile="defended",
        policy=policy,
        tool_registered=True,
    )
    denied = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="defended",
        policy=policy,
        tool_registered=True,
    )
    assert granted.decision == "ALLOW"
    assert granted.reason == "tool_granted"
    assert denied.decision == "DENY"
    assert denied.reason == "tool_not_granted"
    params = inspect.signature(authorize_tool).parameters
    assert "finding" not in params
    assert "external" not in params
    assert SCANNER_HIGH_NE_DENY == "SCANNER HIGH != DENY"
    source = inspect.getsource(authorize_tool)
    assert "ExternalEvidence" not in source
    assert finding.severity == "HIGH"


def test_zero_findings_do_not_grant_or_trust():
    empty = cisco_normalized_to_external(
        _scan(findings=(), fixture="NORMAL", desc="sha256:aa")
    )
    assert empty[0].to_dict()["native"]["finding_count"] == 0
    policy = coded_policy()
    denied = authorize_tool(
        tool_name="lookup_customer_tier",
        requested_scope="customer:read",
        profile="defended",
        policy=policy,
        tool_registered=True,
    )
    assert denied.decision == "DENY"
    params = inspect.signature(authorize_tool).parameters
    assert "findings" not in params


def test_mcp_modules_do_not_import_external_evidence():
    for path in MCP_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
        assert not any(n.startswith("agentsec.external_evidence") for n in names), path
        text = path.read_text(encoding="utf-8")
        assert "ExternalEvidence" not in text


def test_hash_match_semantics_documented():
    assert "same process" in HASH_MATCH_NE_CAUSALITY
    assert ARTIFACT_TYPE_MCP_CATALOG == "mcp.catalog.snapshot"
