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
    assert "LAST KNOWN CLIENT STATE" in script
    assert "pairSessionRuns" in script
    assert "/api/launches/" in script
    assert "predict-control" not in script
    assert "method: \"POST\"" not in script


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


def test_studio_focus_stylesheet_is_packaged_on_dashboards():
    css = (
        ROOT / "splunk_app/agentsec/appserver/static/agentsec_studio_focus.css"
    ).read_text(encoding="utf-8")
    assert ':focus-visible' in css
    assert 'role="tab"' in css
    views = ROOT / "splunk_app/agentsec/default/data/ui/views"
    studio = list(views.glob("ws_*.xml"))
    assert studio
    for path in studio:
        text = path.read_text(encoding="utf-8")
        assert 'stylesheet="agentsec_studio_focus.css"' in text


def test_brand_assets_are_packaged_without_a_deployment_address():
    home = (
        ROOT / "splunk_app/agentsec/default/data/ui/views/ws_agentsec_home.xml"
    ).read_text(encoding="utf-8")
    assert "agentsec-mark.svg" in home
    assert '"type": "splunk.image"' in home
    assert '"preserveAspectRatio": true' in home
    assert '"w": 64' in home
    assert '"h": 64' in home
    assert "![AgentSec mark" not in home
    assert (ROOT / "splunk_app/agentsec/appserver/static/agentsec-mark.svg").is_file()
    assert (ROOT / "splunk_app/agentsec/static/appIcon.png").is_file()
    assert (ROOT / "splunk_app/agentsec/static/appIcon_2x.png").is_file()
    assert (ROOT / "src/agentsec/static/agentsec-favicon.svg").is_file()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Ollama is the local LLM runtime" in readme
    memory = (
        ROOT / "learning/level_1/LAB-MEMORY-001/dashboard.md"
    ).read_text(encoding="utf-8")
    assert "browser address bar" in memory
    blob = readme + home + memory
    assert "3.17.29.24" not in blob
