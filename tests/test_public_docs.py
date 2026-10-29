"""Public docs: relative links resolve, referenced scripts and flags exist."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def _readme():
    """The README plus the legacy multi-port section that moved out of it."""
    return (ROOT / "README.md").read_text(encoding="utf-8") + "\n" + (ROOT / "docs/LEGACY_MULTI_PORT_FLOW.md").read_text(encoding="utf-8")


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
    readme = _readme()
    lab = "LAB-HITL-APPROVAL"
    assert lab in readme and lab in (ROOT / "docs/LEARNER_GUIDE.md").read_text(encoding="utf-8")
    rec = json.loads((ROOT / f"academy-ui/src/content/recorded/{lab}.json").read_text(encoding="utf-8"))
    assert rec["kind"] == "checkpoint" and rec["spec"]["predictions"] and rec["sha256"]   # Practice (predict, reveal) and Prove data exist
    assert "LAB-MCP-003" not in readme


def test_journey_docs_name_both_the_six_steps_and_the_seven_mission_stages():
    notes = (ROOT / "docs/RELEASE_NOTES_v1.2.0.md").read_text(encoding="utf-8")
    for text in (_readme(), notes):
        assert re.search(r"Learn.*Attack.*Investigate.*EVAL.*Risk.*Governance", text, re.S)
        assert re.search(r"Learn, (Prepare, )?Attack, Investigate, Defend, Retest, Explain", text)
    assert "not verified" in notes.lower() and "(DRAFT" not in notes and "No tag exists" not in notes   # written for the published release


def test_learner_entry_point_is_the_react_academy_not_the_legacy_splunk_dashboard():
    readme = _readme()
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
    readme = _readme()
    assert re.search(r"No authentication, no TLS", readme)
    assert "launches attacks" in readme and "Never expose" in readme
    assert "127.0.0.1" in readme and "SSM" in readme and "REMOTE_ACCESS.md" in readme
    remote = (ROOT / "docs/REMOTE_ACCESS.md").read_text(encoding="utf-8")
    assert "AWS-StartPortForwardingSession" in remote and "no authentication or TLS" in remote
    assert "i-0" not in remote and "<instance-id>" in remote          # no real instance id in public docs


def test_platform_release_version_is_distinct_from_the_embedded_splunk_app_version():
    readme = _readme()
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
    readme = _readme()
    assert "release **v1.2.0**" in readme and "only on the `feature/academy-react-shell`" not in readme
    assert "git checkout feature/academy-react-shell" not in readme and "git checkout feature/academy-react-shell" not in (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")


# ---- v1.2.1 documentation maintenance ----
LEARNER_DOCS = ["README.md", "docs/README.md", "docs/GETTING_STARTED.md", "docs/QUICKSTART.md", "docs/LEARNER_GUIDE.md", "docs/INSTRUCTOR_GUIDE.md",
                "docs/OPERATIONS.md", "docs/REMOTE_ACCESS.md", "docs/LOCAL_DOCKER_LAB.md", "docs/LOAN_DESK_MISSION.md", "docs/TROUBLESHOOTING.md",
                "docs/RELEASE_NOTES_v1.2.0.md", "docs/GATEWAY.md", "docs/SPLUNK_INTEGRATION.md"]


def _text(rel):
    return _readme() if rel == "README.md" else (ROOT / rel).read_text(encoding="utf-8")


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
        t = _text(rel)
        assert re.search(r"opt-in HTTPS gateway", t) and "unreleased" in t.lower() and "GATEWAY.md" in t, rel       # v1.3.0 gateway: implemented, but labelled unreleased
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
    assert "NOT VERIFIED" in g and "mock-tested" in g and "Splunk Cloud" in g and "Not runtime-tested" in g
    sh = _text("scripts/gateway.sh")
    for sub in ("init", "validate", "up", "down"):
        assert f"gateway.sh {sub}" in g and f"{sub})" in sh
    assert (ROOT / "docker-compose.gateway.yml").exists() and "--profile gateway" in _text("docker-compose.gateway.yml")
    assert (ROOT / "scripts/gateway-ready.sh").exists() and "gateway-ready.sh" in g
    assert "/Users/" not in g and "@splunk.com" not in g
    assert "docs/GATEWAY.md" in _text(".env.example") and "GATEWAY.md" in _text("docs/README.md")


def test_gateway_doc_states_the_single_port_contract_and_does_not_overclaim_platforms():
    g = _text("docs/GATEWAY.md")
    assert "443 (default) or 8000" in g and "AGENTSEC_PUBLIC_PORT" in g and "AGENTSEC_SPLUNK_LOCAL_PORT" in g
    assert "real bind of 8000 NOT VERIFIED" in g
    for platform in ("Linux with Docker Engine", "Generic VM, AWS, Azure, GCP VMs running Docker"):
        row = [l for l in g.splitlines() if platform in l][0]
        assert "**Runtime-tested**" not in row and re.search(r"not (runtime-)?tested", row.lower()), row
    assert "TELEMETRY NOT VERIFIED" in g and "LIVE WORKFLOW NOT VERIFIED" in g
    env = _text(".env.example")
    assert "AGENTSEC_PUBLIC_PORT=443" in env and "AGENTSEC_HTTPS_PORT" not in env


def test_splunk_integration_doc_separates_real_from_mock_and_matches_the_code():
    d = _text("docs/SPLUNK_INTEGRATION.md")
    assert "Mock only" in d and "NOT VERIFIED" in d and "Real Splunk" in d
    for name in ("AGENTSEC_SPLUNK_MODE", "AGENTSEC_SPLUNK_REST_URL", "AGENTSEC_SPLUNK_CA_BUNDLE_FILE", "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE", "AGENTSEC_SPLUNK_INDEX", "AGENTSEC_SPLUNK_TIMEOUT_SEC"):
        assert name in d and name in _text("src/agentsec/splunk_client.py")
    for stage in ("CONNECTIVITY", "AUTHENTICATION", "AUTHORIZATION", "SEARCH", "TELEMETRY"):
        assert stage in d
    assert "docs/SPLUNK_INTEGRATION.md" in _text(".env.example") and "SPLUNK_INTEGRATION.md" in _text("docs/README.md") and "SPLUNK_INTEGRATION.md" in _text("docs/GATEWAY.md")
    assert not re.search(r"Splunk Cloud (is|are) (fully )?(supported|compatible)", d, re.I) and "/Users/" not in d


def test_splunk_real_verification_record_is_honest_about_what_was_blocked():
    d = _text("docs/SPLUNK_INTEGRATION.md")
    assert "partially verified" in d and "BLOCKED" in d and "SplunkServerDefaultCert" in d and "no subject alternative name" in d
    assert "Do not trust `SplunkCommonCA`" in d and "3545" in d and "3986" in d
    assert not re.search(r"authenticated stages[^.]*(PASS|verified against real)", d)


DOCS_6 = ["README.md", "docs/GETTING_STARTED.md", "docs/QUICKSTART.md", "docs/LOCAL_DOCKER_LAB.md", "docs/GATEWAY.md", "docs/SPLUNK_INTEGRATION.md"]


def test_every_aligned_doc_labels_v1_2_0_published_and_v1_3_0_unreleased_and_links_the_canonical_table():
    for rel in DOCS_6:
        t = _text(rel)
        assert "unreleased" in t.lower() and ("GATEWAY.md" in t or rel == "docs/GATEWAY.md"), rel
    for rel in ("README.md", "docs/GETTING_STARTED.md", "docs/SPLUNK_INTEGRATION.md"):
        assert "GATEWAY.md#deployment-modes-at-a-glance" in _text(rel), rel
    for rel in ("README.md", "docs/GETTING_STARTED.md", "docs/QUICKSTART.md", "docs/LOCAL_DOCKER_LAB.md"):
        assert re.search(r"published v1\.2\.0", _text(rel), re.I), rel


def test_gateway_doc_has_the_deployment_mode_table_and_the_single_port_contract():
    g = _text("docs/GATEWAY.md")
    assert "## Deployment modes at a glance" in g
    for cell in ("Published v1.2.0", "v1.3.0 opt-in HTTPS gateway", "**Exactly one: 443 (default) or 8000**", "mock-tested only", "BLOCKED", "NOT VERIFIED"):
        assert cell in g, cell
    assert re.search(r"Not reachable through the gateway \(NOT VERIFIED, not routed\)", g, re.I)
    assert re.search(r"Classic Attack Service page .*\*\*Not routed\*\* \(known v1.3.0 limitation\)", g) and "302 to `/learn`" in g
    assert "`lab-up.sh --remote` is not the gateway" in g


def test_no_doc_claims_splunk_web_is_reachable_through_the_gateway():
    bad = re.compile(r"splunk web[^.\n]{0,60}(is|are)?\s*(available|reachable|accessible|proxied|served)[^.\n]{0,40}(through|via|behind|on) the gateway", re.I)
    for rel in DOCS_6 + ["docs/REMOTE_ACCESS.md"]:
        for line in _text(rel).splitlines():
            if bad.search(line):
                assert re.search(r"\bnot\b|NOT VERIFIED|never", line, re.I), (rel, line)
    for rel in ("docs/GATEWAY.md", "docs/SPLUNK_INTEGRATION.md"):
        assert "NOT VERIFIED" in _text(rel) and "Splunk Web" in _text(rel)


def test_real_splunk_stays_not_verified_or_blocked_in_every_doc_that_mentions_external_splunk():
    for rel in ("README.md", "docs/GETTING_STARTED.md", "docs/LOCAL_DOCKER_LAB.md", "docs/GATEWAY.md", "docs/SPLUNK_INTEGRATION.md"):
        t = _text(rel)
        if re.search(r"external Splunk|Splunk Cloud|EXTERNAL_ENTERPRISE", t):
            assert "mock-tested" in t or "mock only" in t.lower(), rel
            assert not re.search(r"(external Splunk|Splunk Cloud)[^.\n]{0,40}(is|are) (fully )?(supported|compatible|verified)", t, re.I), rel
    assert "BLOCKED" in _text("docs/SPLUNK_INTEGRATION.md") and "BLOCKED" in _text("docs/GATEWAY.md")
