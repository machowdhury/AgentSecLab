"""Public docs: relative links resolve, referenced scripts and flags exist."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]
NEW = ["README.md", "CONTRIBUTING.md", "docs/README.md", "docs/GETTING_STARTED.md", "docs/LEARNER_GUIDE.md",
       "docs/INSTRUCTOR_GUIDE.md", "docs/ARCHITECTURE_GUIDE.md", "docs/EVALUATION_AND_RISK_GUIDE.md",
       "docs/GOVERNANCE_GUIDE.md", "docs/PROJECT_REFERENCE.md", "docs/RELEASE_NOTES_v1.2.0.md"]


def test_new_docs_links_resolve():
    for rel in NEW:
        f = ROOT / rel
        for t in re.findall(r"\]\(([^)]+)\)", f.read_text(encoding="utf-8")):
            if t.startswith(("http", "#", "mailto:")):
                continue
            assert (f.parent / t.split("#")[0]).resolve().exists(), (rel, t)


def test_documented_scripts_and_flags_exist():
    text = (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")
    for s in set(re.findall(r"\./scripts/([\w.-]+\.sh)", text)):
        assert (ROOT / "scripts" / s).exists(), s
    up = (ROOT / "scripts/lab-up.sh").read_text(encoding="utf-8")
    for flag in ("--build", "--no-wait", "--remote"):
        assert flag in up, flag
    down = (ROOT / "scripts/lab-down.sh").read_text(encoding="utf-8")
    for flag in ("--remove-containers", "--purge", "--yes-delete-all-lab-data"):
        assert flag in down, flag
    assert (ROOT / "scripts/build_academy_ui.sh").exists()


def test_documented_routes_exist():
    router = (ROOT / "academy-ui/src/router.tsx").read_text(encoding="utf-8")
    for r in ("governance", "risk", "evals"):
        assert f'"{r}"' in router


def test_first_lab_has_the_documented_predict_reveal_prove_experience():
    import json
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    lab = "LAB-HITL-APPROVAL"
    assert lab in readme and lab in (ROOT / "docs/LEARNER_GUIDE.md").read_text(encoding="utf-8")
    rec = json.loads((ROOT / f"academy-ui/src/content/recorded/{lab}.json").read_text(encoding="utf-8"))
    assert rec["kind"] == "checkpoint" and rec["spec"]["predictions"] and rec["sha256"]   # Practice (predict, reveal) and Prove data exist
    assert "LAB-MCP-003" not in readme


def test_journey_docs_name_both_the_six_steps_and_the_seven_mission_stages():
    notes = (ROOT / "docs/RELEASE_NOTES_v1.2.0.md").read_text(encoding="utf-8")
    for text in ((ROOT / "README.md").read_text(encoding="utf-8"), notes):
        assert re.search(r"Learn.*Attack.*Investigate.*EVAL.*Risk.*Governance", text, re.S)
        assert re.search(r"Learn, (Prepare, )?Attack, Investigate, Defend, Retest, Explain", text)
    assert "not verified" in notes.lower() and "not tagged" in notes.lower()


def test_learner_entry_point_is_the_react_academy_not_the_legacy_splunk_dashboard():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = "http://127.0.0.1:5001/learn"
    assert start in readme
    # the first place the README names a URL for learners is the Academy, and Splunk Academy Home is labelled legacy
    legacy = "ws_agentsec_home"
    assert readme.index(start) < readme.index(legacy)
    assert re.search(r"Legacy Splunk dashboards.*ws_agentsec_home", readme)
    assert "start here" in readme.lower()
    quick = (ROOT / "docs/QUICKSTART.md").read_text(encoding="utf-8")
    assert quick.index("5001/learn") < quick.index(legacy)
    assert "React Academy" in (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")
    for guide in ("docs/LEARNER_GUIDE.md", "docs/INSTRUCTOR_GUIDE.md"):
        assert "5001/learn" in (ROOT / guide).read_text(encoding="utf-8"), guide


def test_documented_ports_and_routes_match_the_code():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for port in ("5000:5000", "5001:5001", "8000:8000"):
        assert f":{port}\"" in compose                      # learner ports exist ...
    assert "${AGENTSEC_BIND_ADDRESS:-127.0.0.1}:5001:5001" in compose   # ... and default to loopback
    assert "127.0.0.1:8088:8088" in compose                  # HEC stays private
    assert "register_learn(app" in (ROOT / "src/agentsec/attack_app.py").read_text(encoding="utf-8")   # /learn is served by the Attack Service app (port 5001)
    assert '"/learn' in (ROOT / "src/agentsec/learn_web.py").read_text(encoding="utf-8")
    assert 'BASE = "/learn"' in (ROOT / "academy-ui/src/router.tsx").read_text(encoding="utf-8")


def test_docs_keep_the_no_auth_no_tls_warning_and_explain_both_access_modes():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"No authentication, no TLS", readme)
    assert "launches attacks" in readme and "Never expose" in readme
    assert "127.0.0.1" in readme and "SSM" in readme and "REMOTE_ACCESS.md" in readme
    remote = (ROOT / "docs/REMOTE_ACCESS.md").read_text(encoding="utf-8")
    assert "AWS-StartPortForwardingSession" in remote and "no authentication or TLS" in remote
    assert "i-0" not in remote and "<instance-id>" in remote          # no real instance id in public docs


def test_platform_release_version_is_distinct_from_the_embedded_splunk_app_version():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"platform release is \*\*v1\.2\.0\*\*", readme) and "1.1.0" in readme
    notes = (ROOT / "docs/RELEASE_NOTES_v1.2.0.md").read_text(encoding="utf-8")
    assert "1.1.0" in notes and "Splunk app" in notes
    assert 'version = "1.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")   # Option A: metadata intentionally not bumped
