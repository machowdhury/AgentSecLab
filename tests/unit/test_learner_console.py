"""Browser-only learner console contracts. These tests do not launch a lab."""

from pathlib import Path

from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app

ROOT = Path(__file__).resolve().parents[2]


def test_prediction_stays_out_of_the_launch_body():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    html = app.test_client().get("/").get_data(as_text=True)
    assert 'name="predict-control"' in html
    assert 'name="predict-execution"' in html
    assert "session-history" in html
    assert "Copy SPL" in html
    assert "Return to Academy" in html
    assert "investigation handle, not a verdict" in html
    assert 'execution: "live"' in html
    assert "predict-control" not in html.split('body: JSON.stringify({', 1)[1].split("})", 1)[0]
    assert "3.17.29.24" not in html
    assert "Host publish remains 127.0.0.1" not in html
    assert "input_pattern_matched" not in html
    assert "expected_evidence_vulnerable" not in html


def test_session_helpers_do_not_post_predictions():
    script = (ROOT / "src/agentsec/static/agentsec-ui.js").read_text(encoding="utf-8")
    assert "sessionStorage" in script
    assert "savePrediction" in script
    assert "recordLaunch" in script
    assert "fetch(" not in script


def test_brand_assets_describe_the_gate_without_a_new_component():
    architecture = (ROOT / "docs/brand/agentsec-architecture.svg").read_text(encoding="utf-8")
    sequence = (ROOT / "docs/brand/agentsec-evidence-sequence.svg").read_text(encoding="utf-8")
    mark = (ROOT / "src/agentsec/static/agentsec-mark.svg").read_text(encoding="utf-8")
    assert "CTRL-MCP-001" in architecture
    assert "Splunk HEC and Search" in architecture
    assert "not proof" in sequence or "not proven" in sequence
    assert "claim" in sequence
    assert "shield" not in mark.lower()


def test_selected_workshops_do_not_announce_the_mode_pair_first():
    a2a = (ROOT / "learning/level_1/LAB-A2A-AUTH-DELEGATION/dashboard.definition.json").read_text(
        encoding="utf-8"
    )
    hitl = (ROOT / "learning/level_1/LAB-HITL-APPROVAL/dashboard.definition.json").read_text(
        encoding="utf-8"
    )
    cred = (ROOT / "learning/level_1/LAB-CREDENTIAL-LIFETIME/dashboard.definition.json").read_text(
        encoding="utf-8"
    )
    provenance = (
        ROOT / "learning/level_1/LAB-COMPONENT-PROVENANCE/dashboard.definition.json"
    ).read_text(encoding="utf-8")
    assert "Card Cedar" in a2a
    assert "must be judged as the same request" not in a2a
    assert "Packet North" in hitl
    assert "ATTACK and RETEST submit the same action" not in hitl
    assert "Story Elm" in cred
    assert "classroom-ledger" in provenance
    assert "SIMULATED" in provenance
    assert "ollama/ollama:latest" in provenance


def test_access_script_does_not_claim_stale_loopback_links():
    text = (ROOT / "scripts/agentsec-access.sh").read_text(encoding="utf-8")
    assert "Academy pages still contain http://127.0.0.1:5001" not in text
    assert "browser address bar" in text
