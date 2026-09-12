"""Workshop logic contracts for LAB-PI-001.

These tests do not execute SPL and do not prove runtime prevention.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_IDS = (
    "Q-RUN-EVENTS",
    "Q-CONTROL-DECISION",
    "Q-LLM-EXECUTED",
    "Q-LLM-AFTER-DENY",
)

WORKSHOP_STEPS = (
    "LEARN",
    "BASELINE",
    "ATTACK",
    "OBSERVE",
    "HUNT",
    "DETECT",
    "DEFEND",
    "RETEST",
    "COMPARE",
    "PROVE",
)

PROHIBITED_FIELDS = (
    "agentsec.event.name",
    "agentsec.profile",
    "agentsec.pipeline.outcome",
)

ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "learning" / "level_1" / "LAB-PI-001"
REQUIRED_FILES = (
    LAB_DIR / "README.md",
    LAB_DIR / "workshop.md",
    LAB_DIR / "evidence-requirements.md",
    LAB_DIR / "knowledge-check.md",
    LAB_DIR / "dashboard.md",
)


def _lab_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in REQUIRED_FILES)


def test_workshop_files_exist():
    for path in REQUIRED_FILES:
        assert path.is_file(), path
    assert (LAB_DIR / "searches" / "catalog.json").is_file()
    assert (LAB_DIR / "dashboard.definition.json").is_file()
    assert (LAB_DIR / "dashboard.md").is_file()


def test_workshop_flow_headings_in_order():
    text = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    positions = [text.index(f"## {step}") for step in WORKSHOP_STEPS]
    assert positions == sorted(positions)


def test_validated_searches_named_per_step():
    workshop = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    for query_id in REQUIRED_IDS:
        assert query_id in workshop
    assert "Q-RUN-EVENTS" in workshop.split("## OBSERVE", 1)[1].split("## HUNT", 1)[0]
    hunt = workshop.split("## HUNT", 1)[1].split("## DETECT", 1)[0]
    assert "Q-CONTROL-DECISION" in hunt and "Q-LLM-EXECUTED" in hunt
    detect = workshop.split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "Q-LLM-AFTER-DENY" in detect
    assert "Q-LLM-AFTER-DENY-POSITIVE-CONTROL" in detect
    assert "SIMULATED" in detect


def test_prohibited_conceptual_fields_absent_from_workshop_docs():
    blob = _lab_text()
    for field in PROHIBITED_FIELDS:
        assert field not in blob, field
    assert "event.name" in blob
    assert "agentsec.security.profile" in blob
    assert "agentsec.outcome" in blob


def test_evidence_gates_and_hierarchy():
    evidence = (LAB_DIR / "evidence-requirements.md").read_text(encoding="utf-8")
    for marker in ("G1", "G2", "G3", "G4", "G5", "G6", "events.jsonl", "export.json"):
        assert marker in evidence
    assert "Runtime" in evidence
    assert "corroborat" in evidence.lower()
    assert "splunk.verified" in evidence


def test_validated_run_ids_and_attack_mode_honesty():
    blob = _lab_text()
    assert "b3611d56-0d3f-4b2e-9a51-75ae36628155" in blob
    assert "78f05d1b-728e-4e70-8993-f5e365871f87" in blob
    assert "f39fed12-de89-45ba-b684-5b6077942580" in blob
    assert "bbe75cb8-0190-47d6-86be-5feba58ad5c0" in blob
    workshop = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    retest = workshop.split("## RETEST", 1)[1].split("## COMPARE", 1)[0]
    assert "bbe75cb8-0190-47d6-86be-5feba58ad5c0" in retest
    assert "`testbed.mode=ATTACK`" in retest or "**`testbed.mode=ATTACK`**" in retest
    assert "must not be described as RETEST" in retest
    compare = workshop.split("## COMPARE", 1)[1].split("## PROVE", 1)[0]
    assert "BASELINE" in compare and "VULNERABLE ATTACK" in compare and "DEFENDED RETEST" in compare
    assert "b3611d56" in compare and "f39fed12" in compare and "bbe75cb8" in compare
    assert "78f05d1b" in compare
    assert "Do not relabel" in compare
    assert "benign request" in compare
    assert "fail-open" in compare
    assert "DENY before invocation" in compare
    assert "0 LLM executions" in compare
    assert "ws_lab_pi_001" in blob
    assert "dashboard.definition.json" in (LAB_DIR / "dashboard.md").read_text(encoding="utf-8")
    assert "3367455f" in blob
    assert "never exported" in blob.lower() or "were never exported" in blob


def test_does_not_claim_forbidden_lessons():
    workshop = (LAB_DIR / "workshop.md").read_text(encoding="utf-8")
    blob = _lab_text().lower()
    assert "dashboard studio" in workshop.lower()
    assert "not a shipped detection" in workshop.lower()
    assert "allow is not execution" in blob
    assert "independent prevention proof" in blob or "not independently prove" in blob
    assert "makeresults" in blob and "simulated" in blob


def test_simulated_fixture_not_called_observed_runtime():
    blob = _lab_text()
    assert "SIMULATED" in blob
    assert "makeresults" in blob
    detect = (LAB_DIR / "workshop.md").read_text(encoding="utf-8").split("## DETECT", 1)[1].split("## DEFEND", 1)[0]
    assert "OBSERVED runtime" not in detect or "not OBSERVED" in detect
    assert "**SIMULATED**" in detect
    evidence = (LAB_DIR / "evidence-requirements.md").read_text(encoding="utf-8")
    assert "must not appear in a PROVE block as runtime behavior" in evidence


def test_knowledge_checks_cover_core_misunderstandings():
    checks = (LAB_DIR / "knowledge-check.md").read_text(encoding="utf-8")
    for needle in (
        "ALLOW",
        "executed",
        "missing `llm.*`",
        "Q-LLM-AFTER-DENY",
        "SIMULATED",
        "RETEST",
        "66",
        "CTRL-INPUT-001",
    ):
        assert needle in checks


def test_no_new_spl_in_lab_root():
    lab_spl = list(LAB_DIR.glob("*.spl"))
    assert lab_spl == []
    search_ids = {path.name for path in (LAB_DIR / "searches").glob("*.spl")}
    assert search_ids == {
        "Q-RUN-EVENTS.spl",
        "Q-CONTROL-DECISION.spl",
        "Q-LLM-EXECUTED.spl",
        "Q-LLM-AFTER-DENY.spl",
        "Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl",
    }
