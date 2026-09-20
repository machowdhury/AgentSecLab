"""Phase 13A goal-integrity design documents. Runtime is 13B."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
NOTE = DOCS / "learning-notes" / "agent-goal-integrity-101.md"
SCHEMA = ROOT / "schemas" / "security_event.schema.json"
DET = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / "DET-MCP-001.spl"
STATUS = DOCS / "IMPLEMENTATION_STATUS.md"
ROADMAP = DOCS / "AGENTSEC_ROADMAP_2026.md"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"

PHASE13A_DOCS = (
    DOCS / "GOAL_INTEGRITY_PREDECESSOR_ANALYSIS.md",
    DOCS / "GOAL_INTEGRITY_SECURITY_MODEL.md",
    DOCS / "GOAL_INTEGRITY_THREAT_MODEL.md",
    DOCS / "GOAL_INTEGRITY_LAB_SPECIFICATION.md",
    DOCS / "GOAL_INTEGRITY_EVENT_MODEL_REVIEW.md",
    DOCS / "GOAL_INTEGRITY_DETECTION_MODEL.md",
    DOCS / "GOAL_INTEGRITY_EXTERNAL_TOOL_RESEARCH.md",
    NOTE,
)


def test_phase13a_design_docs_exist():
    for path in PHASE13A_DOCS:
        assert path.is_file(), path


def test_phase13a_locks_authorized_tool_wrong_goal():
    blob = "\n".join(path.read_text(encoding="utf-8") for path in PHASE13A_DOCS)
    assert "LAB-AGENT-GOAL-INTEGRITY-001" in blob
    assert "GOAL-001" in blob
    assert "INV-002" in blob
    assert "No INV-009" in blob
    assert "CTRL-GOAL-INTEGRITY-001" in blob
    assert "CTRL-MCP-001" in blob
    assert "AUTHORIZED TOOL + UNAUTHORIZED GOAL" in blob
    assert "vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority" in blob
    assert "SCHEMA BUMP JUSTIFIED" in blob
    assert "1.9.0" in blob
    assert "REQUIRES NEW TELEMETRY" in blob
    assert "UNMAPPED / REQUIRES REVALIDATION" in blob
    spec = (DOCS / "GOAL_INTEGRITY_LAB_SPECIFICATION.md").read_text(encoding="utf-8")
    assert "SAME AUTHORITATIVE TASK" in spec
    assert "SAME MALICIOUS INPUT" in spec
    det = (DOCS / "GOAL_INTEGRITY_DETECTION_MODEL.md").read_text(encoding="utf-8")
    assert "DET-MCP-001" in det
    assert "NO DETECTOR JUSTIFIED" in det
    assert "No DET-GOAL" in det
    assert "## What I should now be able to explain" in NOTE.read_text(encoding="utf-8")


def test_phase13a_did_not_create_spl_or_studio():
    assert list((ROOT / "learning").rglob("DET-GOAL*")) == []
    allowed_q_goal = {
        ROOT
        / "learning"
        / "level_1"
        / "LAB-AGENT-GOAL-INTEGRITY-001"
        / "searches"
        / "Q-GOAL-INTEGRITY-AUTHORITY.spl",
        ROOT
        / "learning"
        / "level_1"
        / "LAB-AGENT-GOAL-INTEGRITY-001"
        / "searches"
        / "Q-GOAL-INTEGRITY-AUTHORITY.md",
    }
    found_q_goal = set((ROOT / "learning").rglob("Q-GOAL*"))
    assert found_q_goal <= allowed_q_goal
    if VIEWS.is_dir():
        goal_views = {path.name for path in VIEWS.glob("*goal*")}
        assert goal_views <= {"ws_lab_agent_goal_integrity.xml"}
    det = DET.read_text(encoding="utf-8")
    assert "CTRL-GOAL" not in det
    assert "GOAL-001" not in det
    assert STATUS.is_file()
    assert ROADMAP.is_file()
    schema = SCHEMA.read_text(encoding="utf-8")
    assert "goal_integrity" in schema
    assert '"const": "1.9.0"' in schema
