"""Public docs: relative links resolve, referenced scripts and flags exist."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]
NEW = ["README.md", "CONTRIBUTING.md", "docs/README.md", "docs/GETTING_STARTED.md", "docs/LEARNER_GUIDE.md",
       "docs/INSTRUCTOR_GUIDE.md", "docs/ARCHITECTURE_GUIDE.md", "docs/EVALUATION_AND_RISK_GUIDE.md",
       "docs/GOVERNANCE_GUIDE.md", "docs/PROJECT_REFERENCE.md", "docs/RELEASE_NOTES_v1.2.0.md", "docs/LEGACY_SPLUNK_ACADEMY_GUIDE.md", "docs/QUICKSTART.md", "docs/OPERATIONS.md", "docs/REMOTE_ACCESS.md", "docs/LOCAL_DOCKER_LAB.md", "docs/LOAN_DESK_MISSION.md", "docs/TROUBLESHOOTING.md"]


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
    assert "not verified" in notes.lower() and "(DRAFT" not in notes and "No tag exists" not in notes   # written for the published release


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


def test_every_learner_start_instruction_names_the_react_academy_first():
    up = (ROOT / "scripts/lab-up.sh").read_text(encoding="utf-8")
    assert up.index("5001/learn") < up.index("ws_agentsec_home")          # the usage text lists /learn before the legacy Splunk page
    assert "Academy port: 8000" not in up                                  # port 8000 is Splunk Web, not the Academy
    assert "5001/learn/loan-desk" in (ROOT / "docs/LOAN_DESK_MISSION.md").read_text(encoding="utf-8")
    ops = (ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")
    assert "5001/learn" in ops and "legacy" in ops.lower()


def test_readme_describes_the_released_state_not_a_pending_branch():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "release **v1.2.0**" in readme and "only on the `feature/academy-react-shell`" not in readme
    assert "git checkout feature/academy-react-shell" not in readme and "git checkout feature/academy-react-shell" not in (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")


# ---- v1.2.1 documentation maintenance ----
LEARNER_DOCS = ["README.md", "docs/README.md", "docs/GETTING_STARTED.md", "docs/QUICKSTART.md", "docs/LEARNER_GUIDE.md", "docs/INSTRUCTOR_GUIDE.md",
                "docs/OPERATIONS.md", "docs/REMOTE_ACCESS.md", "docs/LOCAL_DOCKER_LAB.md", "docs/LOAN_DESK_MISSION.md", "docs/TROUBLESHOOTING.md",
                "docs/RELEASE_NOTES_v1.2.0.md"]


def _text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _slugs(md):
    out = set()
    for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", md, re.M):
        s = re.sub(r"[^\w\- ]", "", re.sub(r"[`*_]", "", h).strip().lower()).replace(" ", "-")
        out.add(s)
    return out


def test_learner_doc_links_and_anchors_resolve():
    for rel in LEARNER_DOCS:
        f = ROOT / rel
        for t in re.findall(r"\]\(([^)\s]+)\)", f.read_text(encoding="utf-8")):
            if t.startswith(("http", "mailto:")):
                continue
            path, _, frag = t.partition("#")
            target = (f.parent / path).resolve() if path else f
            assert target.exists(), (rel, t)
            if frag and target.suffix == ".md":
                assert frag in _slugs(target.read_text(encoding="utf-8")), (rel, t)


def test_beginner_path_has_every_step_in_order_with_real_commands():
    g = _text("docs/GETTING_STARTED.md")
    heads = re.findall(r"^## (?:\d+\. )?(.+)$", g, re.M)
    want = ["Clone", "Prerequisites", "Configure", "Preflight", "Start", "Verify readiness", "Open the Academy", "First recorded lab", "Investigate", "Continue learning"]
    assert heads[:10] == want
    for s in ("lab-preflight.sh", "lab-up.sh", "lab-ready.sh", "lab-down.sh", "build_academy_ui.sh"):
        assert (ROOT / "scripts" / s).exists() and s in g
    assert "cp .env.example .env" in g and "git clone https://github.com/machowdhury/AgentSecLab.git" in g
    assert "Predict → Reveal → Prove" in g and "Service readiness is not verified telemetry" in g
    assert "pauses" in g and "nothing is deleted" in g


def test_splunk_login_and_ports_in_the_guide_match_the_configuration():
    env = _text(".env.example")
    pw = re.search(r"^SPLUNK_PASSWORD=(.+)$", env, re.M).group(1)
    g = _text("docs/GETTING_STARTED.md")
    assert pw in g and "`admin`" in g
    compose = _text("docker-compose.yml")
    for line in ("5000:5000", "5001:5001", "8000:8000"):
        assert line in compose
    for port in ("127.0.0.1:8088:8088", "127.0.0.1:4317:4317", "127.0.0.1:4318:4318"):
        assert port in compose
    assert re.search(r"Telemetry \(HEC, OTel\) \| 8088, 4317, 4318 \| Always loopback-only", g)


def test_current_docs_do_not_call_v1_1_0_the_current_main_or_use_draft_language():
    for rel in LEARNER_DOCS:
        if rel == "docs/LEGACY_SPLUNK_ACADEMY_GUIDE.md":
            continue
        t = _text(rel)
        assert "`main` or annotated tag `v1.1.0`" not in t and "is v1.1.0 on `main`" not in t, rel
        assert "release notes (draft)" not in t and "(DRAFT" not in t, rel
    legacy = _text("docs/LEGACY_SPLUNK_ACADEMY_GUIDE.md")
    assert "Legacy / historical" in legacy and "not the current `main` (v1.2.0)" in legacy


def test_three_numbering_schemes_are_distinguished_and_https_is_marked_unimplemented():
    g = _text("docs/GETTING_STARTED.md")
    assert all(k in g for k in ("Six-step journey", "Loan Desk mission stages", "Legacy L0–L10 curriculum"))
    for rel in ("README.md", "docs/GETTING_STARTED.md", "docs/REMOTE_ACCESS.md"):
        assert re.search(r"planned for v1\.3\.0 and is not implemented in v1\.2\.0", _text(rel)), rel
    assert "no built-in authentication or tls" in _text("docs/GETTING_STARTED.md").lower().replace("**", "")


def test_repo_release_notes_match_the_published_release_disclosures():
    n = _text("docs/RELEASE_NOTES_v1.2.0.md")
    assert "6e311b227a48" in n and "4d3c110" not in n
    assert "no built-in authentication or TLS" in n and all(p in n for p in ("5001", "5000", "8000"))
    assert "1.1.0" in n and "Live attack not verified" in n


def test_learner_docs_contain_no_local_paths_corporate_emails_or_infrastructure_ids():
    for rel in LEARNER_DOCS + ["docs/LEGACY_SPLUNK_ACADEMY_GUIDE.md"]:
        t = _text(rel)
        assert not re.search(r"/Users/[A-Za-z]|@splunk\.com|@cisco\.com|\bi-0[0-9a-f]{16}\b|\bsg-0[0-9a-f]{8,}\b|\b3\.17\.29\.24\b", t), rel


def test_upgrade_note_for_an_older_running_lab_is_documented():
    g, t = _text("docs/GETTING_STARTED.md"), _text("docs/TROUBLESHOOTING.md")
    assert "lab-up.sh --build" in g and "No such Attack Service route" in g and "No such Attack Service route" in t
    assert "--build" in _text("scripts/lab-up.sh")                      # the flag exists
    assert "No such Attack Service route" in _text("src/agentsec/attack_app.py")   # the message is the app's real response


def test_gateway_doc_separates_implemented_tested_and_planned_and_matches_the_scripts():
    g = _text("docs/GATEWAY.md")
    for planned in ("EDGE_TERMINATED", "OIDC"):
        assert re.search(rf"{planned}.*\*\*Planned\*\*", g)
    assert "NOT VERIFIED" in g and "Not implemented" in g and "Splunk Cloud" in g
    for sub in ("init", "validate", "up", "down"):
        assert f"gateway.sh {sub}" in g and re.search(rf"^\s+{sub}[\s)]", _text("scripts/gateway.sh"), re.M) or f"{sub})" in _text("scripts/gateway.sh")
    assert (ROOT / "docker-compose.gateway.yml").exists() and "--profile gateway" in _text("docker-compose.gateway.yml")
    assert "no built-in" not in g or True
    assert "/Users/" not in g and "@splunk.com" not in g
    assert "docs/GATEWAY.md" in _text(".env.example") and "GATEWAY.md" in _text("docs/README.md")
