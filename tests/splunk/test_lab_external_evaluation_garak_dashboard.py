"""Repository contracts for the External Security Toolbox Studio workshop.

These tests prove packaging and teaching semantics, not browser rendering or
live Splunk execution.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "learning" / "level_1" / "LAB-EXTERNAL-EVALUATION-GARAK"
DEFINITION = LAB / "dashboard.definition.json"
VIEW = (
    ROOT
    / "splunk_app"
    / "agentsec"
    / "default"
    / "data"
    / "ui"
    / "views"
    / "ws_lab_external_evaluation_garak.xml"
)
BUILDER = ROOT / "scripts" / "build_lab_external_evaluation_garak_dashboard.py"
NAV = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "nav" / "default.xml"


def _definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def _xml_definition() -> dict:
    text = VIEW.read_text(encoding="utf-8")
    return json.loads(text.split("<![CDATA[", 1)[1].split("]]>", 1)[0])


def _markdown() -> str:
    return "\n".join(
        viz["options"]["markdown"]
        for viz in _definition()["visualizations"].values()
        if viz["type"] == "splunk.markdown"
    )


def test_packaged_view_matches_generated_definition_and_nav():
    assert BUILDER.is_file()
    assert DEFINITION.is_file()
    assert VIEW.is_file()
    assert _definition() == _xml_definition()
    assert "ws_lab_external_evaluation_garak" in NAV.read_text(encoding="utf-8")
    assert "<label>External Security Toolbox</label>" in VIEW.read_text(encoding="utf-8")


def test_progressive_tabs_and_validated_searches():
    definition = _definition()
    assert [row["label"] for row in definition["layout"]["tabs"]["items"]] == [
        "TOOLBOX",
        "GUIDED",
        "INVESTIGATE",
        "CHALLENGE",
    ]
    assert set(definition["dataSources"]) == {
        "ds_cisco_who",
        "ds_cisco_finding",
        "ds_garak",
        "ds_planes",
    }
    assert (
        definition["dataSources"]["ds_garak"]["options"]["query"]
        == (LAB / "searches" / "Q-GARAK-EVALUATION.spl").read_text(encoding="utf-8").strip()
    )
    assert (
        definition["dataSources"]["ds_planes"]["options"]["query"]
        == (LAB / "searches" / "Q-EXTERNAL-EVIDENCE-PLANES.spl")
        .read_text(encoding="utf-8")
        .strip()
    )
    for layout in definition["layout"]["layoutDefinitions"].values():
        assert layout["options"]["width"] == 1440


def test_toolbox_attribution_and_evidence_reasoning():
    text = _markdown()
    for required in (
        "BUILT BY AGENTSEC",
        "INTEGRATED BY AGENTSEC",
        "TAUGHT / REFERENCED BY AGENTSEC",
        "STATIC / CATALOG SECURITY FINDING",
        "ADVERSARIAL MODEL EVALUATION",
        "HIGH != DENY",
        "ZERO FINDINGS != SAFE",
        "PASS != SAFE",
        "FAIL != EXPLOIT CONFIRMED",
        "ALLOW does not prove execution",
        "execution.started does not prove successful completion",
        "CORRELATION != CAUSATION",
        "No `agentsec.run.id`",
    ):
        assert required.lower() in text.lower(), required


def test_learning_grammar_threat_bridge_and_framework_honesty():
    text = _markdown()
    flat = " ".join(text.split())
    for stage in (
        "WHY",
        "WHAT",
        "WHERE IT FITS",
        "PREDICT",
        "RUN / REPLAY",
        "READ NATIVE",
        "NORMALIZE",
        "INGEST",
        "INVESTIGATE",
        "CORRELATE",
        "CHALLENGE THE EVIDENCE",
        "THREAT-MODELING BRIDGE",
        "EXPLAIN",
    ):
        assert stage in text
    for question in (
        "ASSET",
        "ACTOR",
        "ENTRY POINT",
        "TRUST BOUNDARY",
        "CONTROL",
        "OBSERVABILITY",
        "RESIDUAL RISK",
    ):
        assert question in text
    assert "EDUCATIONAL MAPPING" in text
    assert "NEEDS_EXTERNAL_VALIDATION" in text
    assert "compliance, certification, complete coverage" in flat


def test_no_data_and_causal_claims_fail_honestly():
    definition = _definition()
    for viz in definition["visualizations"].values():
        if viz["type"] != "splunk.table":
            continue
        message = viz["options"]["noDataMessage"]
        assert message.startswith("NO EVIDENCE FOUND")
        assert "not SAFE" in message
        assert viz["hideWhenNoData"] is False
    dumped = json.dumps(definition)
    assert "agentsec.run.id=" not in dumped
    assert "finding → authorization" not in dumped
    assert "evaluation → runtime execution" not in dumped
    assert "ds.savedsearch" not in dumped
