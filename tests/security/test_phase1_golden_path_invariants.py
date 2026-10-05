"""Phase 1 golden-path invariants for the LAB-MCP-001 reference journey.

These cover the gaps the existing suite did not already assert. CTRL-MCP-001
semantics, schema 1.9.0 and the ExternalEvidence contract are covered widely
elsewhere and are not duplicated here.

The journey under test is:

    AcmeBank -> Behind the AI -> workshop -> predict -> ATTACK -> run.id ->
    Splunk evidence -> RETEST -> second run.id -> compare -> conclude
"""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import pytest

from agentsec.mcp.fixtures import MCP_CUSTOMER_SCOPE, MCP_LOOKUP_TIER_ARGS
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry

ROOT = Path(__file__).resolve().parents[2]
CURRICULUM = json.loads(
    (ROOT / "learning/academy/curriculum.json").read_text(encoding="utf-8")
)
TEMPLATES = ROOT / "src/agentsec/templates"
STATIC = ROOT / "src/agentsec/static"
WORKBENCH = (TEMPLATES / "attack_mcp.html").read_text(encoding="utf-8")
ACMEBANK = (TEMPLATES / "acmebank.html").read_text(encoding="utf-8")
WORKSHOP = json.loads(
    (ROOT / "learning/level_1/LAB-MCP-001/dashboard.definition.json").read_text(
        encoding="utf-8"
    )
)

# Phase 2. Named here so an accidental Phase 1 implementation fails loudly.
PHASE_2_LABS = ("LAB-GOV-004", "LAB-DATA-003", "LAB-A2A-005")
PHASE_2_CONTROLS = ("CTRL-RUNTIME-004", "CTRL-DATA-003", "CTRL-A2A-005")


def _curriculum_lab_ids() -> list[str]:
    return [lab["lab_id"] for level in CURRICULUM["levels"] for lab in level["labs"]]


# --- curriculum is derived, never typed in ---------------------------------


def test_curriculum_lab_ids_are_unique():
    lab_ids = _curriculum_lab_ids()
    assert len(lab_ids) == len(set(lab_ids)), "a lab is registered twice"


def test_learner_path_catalog_is_derived_from_the_curriculum():
    """Your Path may show more entries than the curriculum has labs (it also
    lists checkpoints and non-lab steps), but every curriculum lab must appear.
    A lab that exists only in the hand-maintained catalog is drift."""
    path_js = (
        ROOT / "splunk_app/agentsec/appserver/static/agentsec_learner_path.js"
    ).read_text(encoding="utf-8")
    for lab_id in _curriculum_lab_ids():
        view = next(
            lab["view"]
            for level in CURRICULUM["levels"]
            for lab in level["labs"]
            if lab["lab_id"] == lab_id
        )
        assert view in path_js, f"{lab_id} ({view}) is missing from Your Path"


# --- Phase 2 boundary ------------------------------------------------------


@pytest.mark.parametrize("lab_id", PHASE_2_LABS)
def test_phase_2_labs_are_not_registered(lab_id):
    assert lab_id not in _curriculum_lab_ids()
    from agentsec.launch_catalog import known_lab_ids

    assert lab_id not in known_lab_ids(), (
        f"{lab_id} is launchable but belongs to Phase 2"
    )


@pytest.mark.parametrize("control_id", PHASE_2_CONTROLS)
def test_phase_2_controls_do_not_exist(control_id):
    hits = [
        path
        for path in (ROOT / "src").rglob("*.py")
        if control_id in path.read_text(encoding="utf-8")
    ]
    assert not hits, f"{control_id} is implemented but belongs to Phase 2: {hits}"


# --- ATTACK and RETEST are two separate runs -------------------------------


def _invoke(settings, memory, *, profile: str, mode: str):
    return run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=dataclasses.replace(settings, security_profile=profile),
        testbed_mode=mode,
        attack_id="MCP-002",
        registry=default_registry(),
        write_evidence=False,
    )


def test_attack_and_retest_mint_distinct_run_ids(settings, memory):
    attack = _invoke(settings, memory, profile="vulnerable", mode="ATTACK")
    retest = _invoke(settings, memory, profile="defended", mode="RETEST")
    assert attack.run_id and retest.run_id
    assert attack.run_id != retest.run_id, "the comparison needs two real runs"


def test_control_decision_is_not_execution_evidence(settings, memory):
    """The ATTACK fails open: CTRL-MCP-001 says ALLOW and the handler runs.
    The RETEST denies and the handler never starts. The two facts are read
    from two different places, which is the point of the whole lab."""
    attack = _invoke(settings, memory, profile="vulnerable", mode="ATTACK")
    retest = _invoke(settings, memory, profile="defended", mode="RETEST")

    attack_decision = attack.hops[0].control_decision
    retest_decision = retest.hops[0].control_decision
    assert attack_decision == "ALLOW"
    assert retest_decision == "DENY"

    # Execution comes from the handler count, never from the decision token.
    assert attack.handler_invoke_count > 0, "ALLOW on the vulnerable profile executed"
    assert retest.handler_invoke_count == 0, "DENY means the handler never began"


def test_requested_scope_differs_from_allowed_scope_on_both_runs(settings, memory):
    """Question 3 of the evidence notebook has to have an answer on both runs:
    the authority gap is recorded even when the control fails open."""
    for profile, mode in (("vulnerable", "ATTACK"), ("defended", "RETEST")):
        result = _invoke(settings, memory, profile=profile, mode=mode)
        decision_events = [
            event
            for event in result.events
            if event.get("event.name") == "agentsec.control.decision"
        ]
        assert decision_events, f"{mode} emitted no control decision"
        event = decision_events[0]
        assert event["agentsec.mcp.requested_scope"] == "customer:read"
        assert event["agentsec.mcp.allowed_scope"] == "policy:read"


def test_lab_emits_no_llm_events_so_no_surface_may_claim_a_call_count(settings, memory):
    """The Figma prototype showed "LLM calls: 4" for this lab. LAB-MCP-001 runs
    no model call, so that number has no evidence behind it and must not appear."""
    attack = _invoke(settings, memory, profile="vulnerable", mode="ATTACK")
    names = {event.get("event.name") for event in attack.events}
    assert not {name for name in names if str(name).startswith("agentsec.llm.")}

    notebook = " ".join(
        viz["options"]["markdown"]
        for viz_id, viz in WORKSHOP["visualizations"].items()
        if viz_id.startswith("viz_nb_")
    )
    assert "llm" not in notebook.lower(), "a notebook cell asks about model calls"


# --- presentation cannot collapse independent facts ------------------------


def test_workbench_reports_each_state_dimension_separately():
    for element_id in (
        "fact-decision",  # control decision
        "fact-execution",  # execution evidence
        "fact-terminal",  # launcher terminal state
        "fact-evidence",  # Splunk evidence readiness
        "fact-learning",  # browser-local prediction
    ):
        assert f'id="{element_id}"' in WORKBENCH, element_id
    assert "fact-pair__not-equal" in WORKBENCH, "decision and execution lost the != pair"


def test_status_pill_does_not_restate_a_control_decision():
    """The pill used to show DENIED or EVIDENCE READY, so one summary word
    stood in for four independent facts."""
    assert 'controlDecision === "DENY" ? "DENIED"' not in WORKBENCH
    assert '"RUN COMPLETE"' in WORKBENCH


def test_prediction_is_browser_local_and_absent_from_the_launch_payload():
    body = WORKBENCH.split("body: JSON.stringify({", 1)[1].split("})", 1)[0]
    for field in ("predict-control", "predict-execution", "prediction"):
        assert field not in body, f"{field} leaked into the runtime launch payload"
    assert "savePrediction" in WORKBENCH


def test_behind_the_ai_is_labelled_documented_not_measured():
    assert "DOCUMENTED architecture" in ACMEBANK
    assert "not measured evidence from your run" in ACMEBANK


def test_evidence_notebook_states_what_each_answer_does_not_prove():
    cells = [
        viz["options"]["markdown"]
        for viz_id, viz in WORKSHOP["visualizations"].items()
        if viz_id.startswith("viz_nb_q")
    ]
    assert len(cells) == 5, "expected five notebook questions"
    for cell in cells:
        assert "WHAT THE ANSWER SHOWS" in cell
        assert "WHAT IT DOES NOT PROVE" in cell


# --- remote safety ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        TEMPLATES / "attack_mcp.html",
        TEMPLATES / "acmebank.html",
        STATIC / "agentsec-workbench.css",
    ],
)
def test_no_environment_specific_host_is_hard_coded(path):
    text = path.read_text(encoding="utf-8")
    for host in ("localhost", "127.0.0.1", "3.17.29.24"):
        assert host not in text, f"{path.name} hard-codes {host}"


def test_cross_port_navigation_follows_the_requesting_host():
    """AcmeBank links to the Attack Service on another port. It must build that
    URL from window.location so a remote deployment is not sent to loopback."""
    assert "page.hostname" in ACMEBANK
    assert re.search(r'page\.protocol \+ "//" \+ page\.hostname \+ ":5001"', ACMEBANK)
