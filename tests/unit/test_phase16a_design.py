"""Phase 16A is curriculum integration / design only.

Does not implement the capstone, launchers, detectors, schema, or authorization.
Pytest proves repository consistency — not LIVE Splunk or runtime validation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.experiment import SCHEMA_VERSION
from agentsec.launch_catalog import known_lab_ids

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
LEARNING = ROOT / "learning" / "level_1"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
SAVED = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
ATTACK_APP = ROOT / "src" / "agentsec" / "attack_app.py"
BANK_APP = ROOT / "src" / "agentsec" / "bank_app.py"
LAUNCH = ROOT / "src" / "agentsec" / "launch_catalog.py"
EXPERIMENT = ROOT / "src" / "agentsec" / "experiment_context.py"

LIVE_LABS = (
    "LAB-PI-001",
    "LAB-MCP-001",
    "LAB-RAG-CONTEXT",
    "LAB-MEMORY-001",
    "LAB-AGENT-GOAL-INTEGRITY-001",
    "LAB-AGENT-DELEGATION-001",
)

PHASE16A_DOCS = (
    DOCS / "PHASE16A_CURRICULUM_INTEGRATION.md",
    DOCS / "AGENTSEC_SECURITY_REASONING_MODEL.md",
    DOCS / "AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md",
    DOCS / "AGENTSEC_CONCEPT_COVERAGE.md",
    DOCS / "AGENTSEC_CURRICULUM_GAP_ANALYSIS.md",
    DOCS / "AGENTSEC_LEARNING_LEVELS.md",
    DOCS / "AGENTSEC_CAPSTONE_ARCHITECTURE.md",
    DOCS / "AGENTSEC_CAPSTONE_ATTACK_STORY.md",
    DOCS / "AGENTSEC_CAPSTONE_INVESTIGATION_DESIGN.md",
    DOCS / "AGENTSEC_CAPSTONE_EVIDENCE_MODEL.md",
    DOCS / "AGENTSEC_SPLUNK_SKILL_PROGRESSION.md",
    DOCS / "AGENTSEC_DETECTION_ENGINEERING_CURRICULUM.md",
    DOCS / "AGENTSEC_FINAL_COMPETENCY_MODEL.md",
    DOCS / "learning-notes" / "agentsec-end-to-end-security-reasoning.md",
)

KNOWN_BANK_ROUTES = (
    '@app.post("/process")',
    '@app.post("/mcp/invoke")',
    '@app.post("/rag/retrieve")',
    '@app.post("/memory/write")',
    '@app.post("/memory/recall")',
    '@app.post("/goal/evaluate")',
    '@app.post("/identity/delegate")',
)

def _blob() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in PHASE16A_DOCS)


def _manifest(lab_id: str) -> dict:
    path = LEARNING / lab_id / "lab-manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _investigations(lab_id: str) -> dict:
    path = LEARNING / lab_id / "investigations.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_phase16a_design_docs_exist():
    for path in PHASE16A_DOCS:
        assert path.is_file(), path
    note = DOCS / "learning-notes" / "agentsec-end-to-end-security-reasoning.md"
    assert "## What I should now be able to explain" in note.read_text(encoding="utf-8")


def test_phase16a_is_design_only_and_forbids_16b():
    blob = _blob()
    for needle in (
        "DESIGN",
        "Do not start Phase 16B",
        "LAB-AGENTSEC-CAPSTONE-001",
        "REQUEST ≠ GRANT",
        "SPLUNK ≠ ENFORCEMENT",
        "Path A",
        "Path B",
        "CTRL-MCP-001",
        "CTRL-RAG-CONTEXT-001",
        "CTRL-MEMORY-CONTEXT-001",
        "DET-MCP-001",
        "NONE JUSTIFIED",
        "PROVENANCE ≠ TRUST",
        "OBSERVE ≠ ALLOW",
    ):
        assert needle in blob, needle
    hub = (DOCS / "PHASE16A_CURRICULUM_INTEGRATION.md").read_text(encoding="utf-8")
    assert "1.9.0" in hub
    assert "Do not start Phase 16B from this file." in hub


def test_six_live_domains_represented():
    assert frozenset(LIVE_LABS).issubset(known_lab_ids())
    assert "LAB-AGENTSEC-CAPSTONE-001" in known_lab_ids()
    coverage = (DOCS / "AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md").read_text(
        encoding="utf-8"
    )
    hub = (DOCS / "PHASE16A_CURRICULUM_INTEGRATION.md").read_text(encoding="utf-8")
    for lab_id in LIVE_LABS:
        assert lab_id in coverage, lab_id
        assert lab_id in hub, lab_id
        assert (LEARNING / lab_id / "lab-manifest.json").is_file(), lab_id
        assert (LEARNING / lab_id / "investigations.json").is_file(), lab_id


def test_every_live_lab_has_security_question_and_enforcement_honesty():
    for lab_id in LIVE_LABS:
        manifest = _manifest(lab_id)
        assert manifest.get("security_question"), lab_id
        text = json.dumps(manifest)
        assert "Splunk does not" in text, lab_id
        live = manifest["execution_modes"]["LIVE"]
        assert "ATTACK" in live, lab_id
        assert "RETEST" in live, lab_id
        pdp = manifest.get("enforcement_control_id") or manifest.get("control_id")
        if lab_id == "LAB-PI-001":
            assert pdp == "CTRL-INPUT-001"
        else:
            assert pdp == "CTRL-MCP-001", lab_id


def test_every_live_lab_identifies_trust_boundary_in_coverage_matrix():
    coverage = (DOCS / "AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md").read_text(
        encoding="utf-8"
    )
    for lab_id in LIVE_LABS:
        section = coverage.split(lab_id, 1)[1].split("### ", 1)[0]
        assert "Trust boundary" in section, lab_id


def test_path_a_path_b_on_every_live_lab():
    for lab_id in LIVE_LABS:
        inv = _investigations(lab_id)
        assert "path_a" in inv and inv["path_a"], lab_id
        assert "path_b" in inv and inv["path_b"], lab_id
        assert inv.get("not_authorization") is True, lab_id
        questions = [item.get("security_question") for item in inv["investigations"]]
        assert all(questions), lab_id


def test_capstone_design_reuses_existing_controls_and_hunts():
    architecture = (DOCS / "AGENTSEC_CAPSTONE_ARCHITECTURE.md").read_text(
        encoding="utf-8"
    )
    investigations = (DOCS / "AGENTSEC_CAPSTONE_INVESTIGATION_DESIGN.md").read_text(
        encoding="utf-8"
    )
    assert "CTRL-MCP-001" in architecture
    assert "CTRL-RAG-CONTEXT-001" in architecture
    assert "CTRL-MEMORY-CONTEXT-001" in architecture
    assert "Sole tool PDP" in architecture or "sole tool PDP" in architecture
    assert "CTRL-CAPSTONE" not in architecture
    assert "No DET-CAPSTONE" in architecture
    assert "Do not build this runtime" in architecture
    ids = re.findall(r"CAP-I\d+", investigations)
    assert 12 <= len(set(ids)) <= 20, ids
    spl_names = {path.stem for path in LEARNING.rglob("Q-*.spl")}
    mentioned = set(re.findall(r"\bQ-[A-Z0-9]+(?:-[A-Z0-9]+)+\b", investigations))
    missing = {name for name in mentioned if name not in spl_names}
    assert not missing, missing


def test_no_invented_detector_schema_bump_or_runtime_endpoint():
    assert SCHEMA_VERSION == "1.9.0"
    schema = SCHEMA.read_text(encoding="utf-8")
    assert '"const": "1.9.0"' in schema
    operational = {p.stem for p in LEARNING.rglob("DET-*.spl")}
    assert "DET-CAPSTONE" not in operational
    assert "DET-RAG" not in operational
    assert "DET-MEMORY" not in operational
    assert "DET-GOAL" not in operational
    assert "DET-A2A" not in operational
    saved = SAVED.read_text(encoding="utf-8")
    assert "DET-CAPSTONE" not in saved
    attack = ATTACK_APP.read_text(encoding="utf-8")
    bank = BANK_APP.read_text(encoding="utf-8")
    launch = LAUNCH.read_text(encoding="utf-8")
    experiment = EXPERIMENT.read_text(encoding="utf-8")
    assert "LAB-AGENTSEC-CAPSTONE-001" in attack
    assert "LAB-AGENTSEC-CAPSTONE-001" in experiment
    assert "@app.post(\"/capstone" not in bank
    assert "@app.post(\"/a2a" not in bank
    assert "LAB-MCP-003" not in attack
    assert "LAB-MCP-003" not in launch
    for route in KNOWN_BANK_ROUTES:
        assert route in bank, route


def test_status_and_roadmap_record_16a_design_only():
    status = (DOCS / "IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
    roadmap = (DOCS / "AGENTSEC_ROADMAP_2026.md").read_text(encoding="utf-8")
    learning = (DOCS / "AGENTSEC_LEARNING_ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "16A" in status
    assert "DESIGN" in status
    assert "Phase 16A" in roadmap
    assert "Do not start Phase 16B" in roadmap
    assert "PHASE16A_CURRICULUM_INTEGRATION.md" in learning
    assert "AGENTSEC_CURRICULUM_LEVELS.md" in learning
