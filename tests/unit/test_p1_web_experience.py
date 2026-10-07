"""P1 learner experience: the LAB-MCP-001 guided web wizard.

These are deterministic, offline assertions about rendered markup, the REPLAY baseline
constant, and the step-gating rules. They do not call a model, AcmeBank or Splunk, and
they make no claim about live runtime behavior (that is qualified on the deployed lab).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.attack_app import (
    MCP_BASELINE_REPLAY_FACTS,
    MCP_BASELINE_REPLAY_RUN_ID,
    AcmeBankClient,
    create_app,
)

ROOT = Path(__file__).resolve().parents[2]
SPECIMEN = ROOT / "learning/level_1/LAB-MCP-001/specimens" / f"{MCP_BASELINE_REPLAY_RUN_ID}.jsonl"
TEMPLATE = ROOT / "src/agentsec/templates/attack_mcp.html"
ACADEMY_CSS = ROOT / "src/agentsec/static/agentsec-academy.css"


@pytest.fixture(scope="module")
def html() -> str:
    app = create_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    return app.test_client().get("/labs/LAB-MCP-001").get_data(as_text=True)


def _static(html: str) -> str:
    return re.sub(r"<script.*?</script>", "", html, flags=re.S)


# --- baseline: REPLAY facts are pinned to the committed specimen pack -------------------


def test_baseline_facts_equal_the_committed_specimen_pack():
    """The attack-service container does not mount the specimens, so the facts are a code
    constant. This test is what stops the constant drifting from the recorded evidence."""
    rows = [json.loads(line) for line in SPECIMEN.read_text(encoding="utf-8").splitlines() if line.strip()]
    names = [r["event.name"] for r in rows]
    decision = next(r for r in rows if r["event.name"] == "agentsec.control.decision")
    facts = MCP_BASELINE_REPLAY_FACTS
    assert facts["run_id"] == MCP_BASELINE_REPLAY_RUN_ID
    assert facts["decision"] == decision["agentsec.control.decision"]
    assert facts["reason"] == decision["agentsec.control.reason"]
    assert facts["tool"] == decision["gen_ai.tool.name"]
    assert facts["handler_started"] is ("agentsec.mcp.started" in names)
    assert facts["handler_completed"] is ("agentsec.mcp.completed" in names)
    assert facts["event_count"] == len(rows)


def test_baseline_is_labelled_replay_and_is_not_launchable(html):
    baseline = _static(html).split('id="baseline-evidence"')[1].split("</section>")[0]
    assert "REPLAY" in baseline
    assert "recorded" in baseline.lower()
    assert "granted" in baseline
    assert re.findall(r'data-mode="([A-Z]+)"', html) == ["ATTACK", "RETEST"]
    assert 'data-mode="BASELINE"' not in html
    assert f"form.run_id={MCP_BASELINE_REPLAY_RUN_ID}" in html, "advanced path to the canonical REPLAY run"


def test_baseline_primary_action_is_explore_baseline(html):
    assert re.search(r'id="explore-baseline"[^>]*>\s*Explore baseline →', html)
    # the evidence stays hidden until the learner chooses to explore it
    assert re.search(r'id="baseline-evidence"[^>]*\bhidden\b', html)


# --- information architecture ----------------------------------------------------------


def test_five_phases_eight_steps_and_no_observe_destination(html):
    steps = re.findall(r'<(?:section|div)[^>]*\bdata-step="([a-z]+)"', html)
    assert steps == ["start", "baseline", "predict", "attack", "investigate", "defend", "retest", "compare", "explain"]
    rail = html.split('id="phase-rail"')[1].split("</ol>")[0]
    assert len(re.findall(r"<li\b", rail)) == 5
    assert "observe" not in rail.lower()
    assert 'data-step="observe"' not in html


def test_attack_complete_is_a_state_not_a_ninth_destination(html):
    assert 'data-step="attack-complete"' not in html
    assert 'id="attack-complete"' in html
    block = html.split('id="attack-complete"')[1]
    assert " hidden" in block.split(">")[0]


def test_step_gating_rules_are_pinned_in_the_template():
    source = TEMPLATE.read_text(encoding="utf-8")
    gate = source.split("function canEnter", 1)[1].split("function fallbackStep", 1)[0]
    assert 'step === "attack") return predictionLocked' in gate
    assert re.search(r'"investigate" \|\| step === "defend" \|\| step === "retest"\) return hasRun\("ATTACK"\)', gate)
    assert re.search(r'"compare" \|\| step === "explain"\) return hasRun\("ATTACK"\) && hasRun\("RETEST"\)', gate)


# --- one dominant next action per screen ------------------------------------------------


@pytest.mark.parametrize(
    ("step", "cta"),
    [
        ("start", "Start: see normal behavior →"),
        ("baseline", "Continue: make your prediction →"),
        ("predict", "Lock prediction &amp; continue →"),
        ("attack", "Run ATTACK experiment →"),
        ("defend", "Retest the same attack →"),
        ("compare", "Continue: explain what you found →"),
        ("explain", "Finish this lab →"),
    ],
)
def test_each_step_has_exactly_one_dominant_cta(html, step, cta):
    start = html.index(f'data-step="{step}"')
    nxt = re.search(r'<(?:section|div)[^>]*\bdata-step="', html[start + 10:])
    block = html[start: start + 10 + nxt.start()] if nxt else html[start:]
    # tolerate the "&" being written raw in the template
    ctas = re.findall(r'class="cta"[^>]*>([^<]*)<', block)
    ctas = [c.replace("&amp;", "&") for c in ctas]
    ctas = [c for c in ctas if c.strip()]
    wanted = cta.replace("&amp;", "&")
    assert wanted in ctas, (step, ctas)
    if step == "baseline":
        # "Explore baseline" is the only visible CTA; "Continue" lives inside the hidden evidence
        assert ctas == ["Explore baseline →", wanted]
        reveal = block.split('id="baseline-evidence"')[1]
        assert wanted in re.findall(r'class="cta"[^>]*>([^<]*)<', reveal)
    elif step == "attack":
        # the attack step also owns the (hidden) completion CTA; both are single and distinct
        assert set(ctas) == {wanted, "Investigate evidence →"}
    else:
        assert len(ctas) == 1, (step, ctas)


def test_prediction_is_two_independent_questions_and_the_cta_is_gated(html):
    control = re.findall(r'name="predict-control" value="([A-Z]+)"', html)
    execution = re.findall(r'name="predict-execution" value="([A-Z]+)"', html)
    assert control == ["ALLOW", "DENY", "ERROR", "UNKNOWN"]
    assert execution == ["YES", "NO", "UNKNOWN"]
    assert re.search(r'id="record-prediction"[^>]*aria-disabled="true"', html)


def test_notebook_primary_link_is_the_normal_path_without_run_id_entry(html):
    link = re.search(r'<a[^>]*id="open-notebook-primary"[^>]*>', html).group(0)
    assert "layout_investigate" in link
    assert 'target="_blank"' in link and "noopener" in link
    assert "You do not need the run.id" in html


# --- the attack screen is short; the detail is disclosed, not deleted -------------------


def test_attack_screen_is_short_and_detail_lives_in_closed_disclosures(html):
    static = _static(html)
    attack = static.split('data-step="attack"')[1].split("</section>")[0]
    for internal in ("allowlist", "SPL", "environment variable", "trust label", "requested_scope", "AGENTSEC_"):
        assert internal not in attack, internal
    for disclosure in ("understand-attack", "lab-safety", "technical-details"):
        tag = re.search(rf'<details[^>]*id="{disclosure}"[^>]*>', html)
        assert tag is not None, disclosure
        assert " open" not in tag.group(0), f"{disclosure} must start closed"
    # the removed-from-view detail still exists somewhere on the page
    assert "CTRL-MCP-001" in html and "run.id" in html and "Evidence / Advanced" in html


def test_launch_body_stays_closed_and_never_carries_the_prediction(html):
    assert 'body: JSON.stringify({lab_id: "LAB-MCP-001", specimen_id: specimenId, mode: mode, execution: "live"})' in html
    launch = html.split("JSON.stringify({", 1)[1].split("})", 1)[0]
    assert "predict" not in launch


# --- wording and evidence integrity ----------------------------------------------------


def test_no_safe_secure_fixed_claims_and_no_fake_defense_control(html):
    visible = _static(html)
    for banned in ("system is secure now", "now secure", "problem fixed", "is now safe", "SAFE ✓", "FIXED", "fully secure"):
        assert banned not in visible
    assert "does not show the system is secure" in visible
    defend = visible.split('id="defend-step"')[1].split("<!-- STEP 6")[0]
    assert "<input" not in defend and "<form" not in defend
    assert len(re.findall(r"<button", defend)) == 1
    assert not re.search(r"apply defen[cs]e\s*</button>", visible, re.I)


def test_no_llm_claims_for_a_deterministic_lab(html):
    visible = _static(html)
    assert not re.search(r"token count|model trace|LLM reasoning", visible, re.I)


def test_decision_chips_use_shape_and_text_not_colour_alone():
    css = ACADEMY_CSS.read_text(encoding="utf-8")
    source = TEMPLATE.read_text(encoding="utf-8")
    assert '"■ "' in source and '"▶ "' in source
    assert "ALLOW" not in css or "safe" not in css.lower().split("allow", 1)[1][:40]


def test_academy_css_has_no_text_below_14px_and_reflows():
    css = ACADEMY_CSS.read_text(encoding="utf-8")
    sizes = [float(s) for s in re.findall(r"font-size:\s*([0-9.]+)px", css)]
    assert sizes and min(sizes) >= 14
    assert "@media (max-width:900px)" in css or "@media (max-width: 900px)" in css
    assert "prefers-reduced-motion" in css or "transition" not in css
    assert "[hidden]{display:none !important}" in css


def test_academy_main_overrides_the_legacy_760px_reading_width():
    """REGRESSION (found on the deployed app at 1920px): agentsec.css sets `main{max-width:var(--max-width)}`
    (760px). The academy shell sets `main{width:min(1320px,...)}` but not `max-width`, so the card rendered
    728px wide, wrapped the three story cards into tall columns, and pushed the primary CTA to y=1138 on a
    1080px-high window. The approved design is a 1320px content column."""
    css = ACADEMY_CSS.read_text(encoding="utf-8")
    rule = re.search(r"body\.academy main\s*\{([^}]*)\}", css)
    assert rule, "academy main rule missing"
    assert "max-width:none" in rule.group(1).replace(" ", "")
    assert "--content:min(1320px" in css.replace(" ", "")
