"""Batch 1 contracts: lab registry, framework references, evidence state, timeline, workshop schema.

Deterministic and offline. Counts come from the data files, not from literals, except the
two preserved baselines the product owner named (31 curriculum entries, 36 Splunk views).
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agentsec import evidence_contract as c1
from agentsec import evidence_readiness as er
from agentsec import framework_refs
from agentsec.experiment import technique_id_for
from agentsec.lab_registry import coverage, load_registry
from agentsec.timeline import build_timeline

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "splunk_app/agentsec/default/data/ui/views"
SPECIMENS = ROOT / "learning/level_1/LAB-MCP-001/specimens"
ATTACK_RUN = "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49"
RETEST_RUN = "7a1d37b5-d589-4dfd-8322-25ebd0152dbc"


def _json(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _validator(schema: str) -> Draft202012Validator:
    return Draft202012Validator(_json(f"schemas/{schema}.schema.json"))


def _events(run_id: str) -> list[dict]:
    return [json.loads(x) for x in (SPECIMENS / f"{run_id}.jsonl").read_text().splitlines() if x.strip()]


# --- lab registry ------------------------------------------------------------

def test_registry_preserves_every_curriculum_entry_and_view():
    reg = load_registry()
    cur = _json("learning/academy/curriculum.json")
    want = {l["lab_id"] for lv in cur["levels"] for l in lv["labs"]} | {k["lab_id"] for k in cur["checkpoints"]}
    assert {e["lab_id"] for e in reg["entries"]} == want
    assert len(reg["entries"]) == len(want) == 31
    assert len(list(VIEWS.glob("*.xml"))) >= 36  # existing Studio views are never removed
    _validator("lab_registry").validate(reg)


def test_registry_covers_all_taxonomy_domains_except_the_documented_gap():
    cov = coverage(load_registry())
    assert len(load_registry()["domains"]) == 12 and len(load_registry()["pillars"]) == 6
    # AI foundations (D01) has no curriculum entry today. Pinned so closing it is a deliberate change.
    assert cov["domains_without_primary_entry"] == ["D01"]


def test_pillars_are_not_claimed_as_implemented_beyond_the_evidence():
    status = coverage(load_registry())["pillar_status"]
    assert status["P3"]["implemented"] > 0  # LIVE labs exercise a real control decision
    for pillar in ("P1", "P2", "P4", "P5", "P6"):
        assert status[pillar]["implemented"] == 0, pillar


def test_tiers_match_capability():
    reg = load_registry()
    for e in reg["entries"]:
        has_workshop = (ROOT / "learning/level_1" / e["lab_id"] / "workshop.json").is_file()
        assert (e["tier"] == "GUIDED MISSION") == has_workshop, e["lab_id"]
        assert (e["tier"] in ("GUIDED MISSION", "WORKBENCH")) == (e["mode"] == "LIVE"), e["lab_id"]
        text = (VIEWS / f"{e['view']}.xml").read_text(encoding="utf-8")
        refs = len(re.findall(r"agentsec\.run\.id|\$run_id|\$replay_run|name=\"run", text))
        if e["tier"] == "REPLAY":
            assert refs >= 4, (e["lab_id"], refs)  # REPLAY promises specimen evidence in its view
        if e["tier"] == "CONTENT-ONLY":
            assert refs <= 1, (e["lab_id"], refs)


def test_domain_evidence_quotes_exist_verbatim():
    norm = lambda s: " ".join(s.split())  # noqa: E731
    for entry in _json("learning/academy/lab_registry_data.json")["entries"]:
        assert entry["evidence"], entry["lab_id"]
        for ev in entry["evidence"]:
            assert norm(ev["quote"]) in norm((ROOT / ev["file"]).read_text(encoding="utf-8")), (entry["lab_id"], ev["file"])


# --- framework references ----------------------------------------------------

def test_telemetry_no_longer_emits_technique_ids():
    for attack_id in ("ATK-001", "ATK-002", "MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005"):
        assert technique_id_for(attack_id) is None


def test_committed_specimens_only_carry_the_declared_legacy_ids():
    legacy = set(framework_refs.load()["legacy_specimen_ids"])
    seen = set()
    for pack in (ROOT / "learning").rglob("*.jsonl"):
        seen |= set(re.findall(r'"agentsec\.technique\.id":"([^"]+)"', pack.read_text(encoding="utf-8")))
    assert seen <= legacy, seen - legacy


def test_learner_surfaces_hold_no_unverified_framework_id():
    allowed = framework_refs.verified_ids() | {r["id"] for r in framework_refs.retired_labels()}
    for path in [*(ROOT / "src/agentsec/templates").rglob("*.html"), *(ROOT / "src/agentsec/static").glob("*.js")]:
        for found in re.findall(r"AML\.T\d{4}(?:\.\d{3})?", path.read_text(encoding="utf-8")):
            assert found in allowed, (path.name, found)


def test_references_only_expose_verified_ids_and_scope_retirements():
    for scope in ("ATK-002", "MCP-002", "MCP-003", "MCP-004"):
        refs = framework_refs.references_for(scope)
        assert refs and all(r["id"] in framework_refs.verified_ids() for r in refs)
    assert [r["id"] for r in framework_refs.retired_labels("ATK-002")] == ["AML.T0054"]
    assert [r["id"] for r in framework_refs.retired_labels("MCP-002")] == ["AML.T0050"]
    assert all(r["relationship"] in ("PROPOSED", "RELATED") for r in framework_refs.load()["lab_references"])


# --- C1 evidence state -------------------------------------------------------

def test_c1_schema_enums_match_the_module():
    props = _json("schemas/evidence_state.schema.json")["properties"]
    assert tuple(props["source"]["enum"]) == c1.SOURCES
    assert tuple(props["readiness"]["enum"]) == c1.READINESS
    assert set(props["reason"]["enum"]) == set(c1.REASONS) | {None}


def test_c1_unavailable_probe_is_never_zero_rows():
    doc = c1.evidence_state("LIVE", {"evidence_state": "EVIDENCE_CHECK_UNAVAILABLE", "probe_error": "docker_not_available",
                                     "splunk_count": None, "local_event_count": 7})
    assert doc["readiness"] == "EVIDENCE_CHECK_UNAVAILABLE" and doc["splunk_count"] is None and not doc["reconciled"]
    _validator("evidence_state").validate(doc)
    with pytest.raises(c1.ContractError):
        c1.validate({**doc, "splunk_count": 0})


def test_c1_ready_requires_matching_counts_to_be_reconciled():
    ready = {"evidence_state": "EVIDENCE_READY", "splunk_count": 7, "local_event_count": 7, "completeness_ok": True}
    assert c1.evidence_state("LIVE", ready)["reconciled"] is True
    short = {**ready, "splunk_count": 5, "completeness_ok": False}
    doc = c1.evidence_state("LIVE", short)
    assert doc["readiness"] == "EVIDENCE_READY" and doc["reason"] == "count_mismatch" and not doc["reconciled"]


def test_c1_simulated_evidence_cannot_claim_a_splunk_reconciliation():
    with pytest.raises(c1.ContractError):
        c1.validate({"source": "SIMULATED", "readiness": "EVIDENCE_READY", "reason": None,
                     "local_event_count": 2, "splunk_count": 2, "reconciled": True})


# --- REST probe: disabled, fail-closed, no verification bypass ---------------

def test_rest_probe_is_disabled_by_default_and_selection_keeps_the_docker_probe():
    assert er.probe_splunk_count_rest("r", env={})["error"] == "probe_disabled"
    assert er.select_probe(env={}) is er.probe_splunk_count


@pytest.mark.parametrize("env", [
    {er.REST_PROBE_FLAG: "true"},
    {er.REST_PROBE_FLAG: "true", "AGENTSEC_SPLUNK_PROBE_URL": "http://splunk:8089", "AGENTSEC_SPLUNK_PROBE_TOKEN": "t",
     "AGENTSEC_SPLUNK_PROBE_CA_FILE": __file__},
    {er.REST_PROBE_FLAG: "true", "AGENTSEC_SPLUNK_PROBE_URL": "https://splunk:8089", "AGENTSEC_SPLUNK_PROBE_TOKEN": "",
     "AGENTSEC_SPLUNK_PROBE_CA_FILE": __file__},
])
def test_rest_probe_fails_closed_when_misconfigured(env):
    assert er.probe_splunk_count_rest("r", env=env)["error"] == "probe_misconfigured"


def _enabled_env(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    return {er.REST_PROBE_FLAG: "true", "AGENTSEC_SPLUNK_PROBE_URL": "https://splunk:8089",
            "AGENTSEC_SPLUNK_PROBE_TOKEN": "t", "AGENTSEC_SPLUNK_PROBE_CA_FILE": str(ca)}


def test_rest_probe_classifies_tls_and_auth_failures_without_inventing_counts(tmp_path, monkeypatch):
    env = _enabled_env(tmp_path)
    monkeypatch.setattr(ssl, "create_default_context", lambda **_kw: object())

    def opener_raising(exc):
        def _open(*_a, **_k):
            raise exc
        return _open

    tls = er.probe_splunk_count_rest("r", env=env, opener=opener_raising(ssl.SSLCertVerificationError("bad")))
    assert tls["error"] == "tls_verification_failed" and tls["splunk_count"] is None
    auth = er.probe_splunk_count_rest("r", env=env, opener=opener_raising(urllib.error.HTTPError("u", 401, "no", {}, None)))
    assert auth["error"] == "probe_auth_failed" and auth["splunk_ok"] is False


def test_rest_probe_parses_a_count(tmp_path, monkeypatch):
    env = _enabled_env(tmp_path)
    monkeypatch.setattr(ssl, "create_default_context", lambda **_kw: object())

    class Resp:
        def read(self):
            return b"n\n7\n"

    result = er.probe_splunk_count_rest("r", env=env, opener=lambda *_a, **_k: Resp())
    assert result["splunk_ok"] and result["splunk_count"] == 7


def test_evidence_probe_source_never_disables_tls_verification():
    src = (ROOT / "src/agentsec/evidence_readiness.py").read_text(encoding="utf-8")
    for bad in ("CERT_NONE", "check_hostname = False", "check_hostname=False", "verify=False", "_create_unverified_context"):
        assert bad not in src, bad


# --- C2 timeline -------------------------------------------------------------

def test_timeline_attack_is_executed_and_retest_is_not():
    attack = build_timeline(_events(ATTACK_RUN), run_id=ATTACK_RUN, source="REPLAY")
    retest = build_timeline(_events(RETEST_RUN), run_id=RETEST_RUN, source="REPLAY")
    _validator("run_timeline").validate(attack)
    _validator("run_timeline").validate(retest)
    a, = attack["tool_calls"]
    r, = retest["tool_calls"]
    assert (a["decision"], a["executed"]) == ("ALLOW", True)
    assert (r["decision"], r["executed"]) == ("DENY", False)
    assert a["proposed"] is None and a["proposal_source"] == "server_payload"  # no model proposed it
    assert a["indexed"] is None  # indexing is C1's fact, never inferred here


def test_timeline_never_infers_execution_from_allow():
    events = [e for e in _events(ATTACK_RUN) if e["event.name"] not in ("agentsec.mcp.started", "agentsec.mcp.completed")]
    call, = build_timeline(events, run_id=ATTACK_RUN, source="LIVE")["tool_calls"]
    assert call["decision"] == "ALLOW" and call["executed"] is False


def test_timeline_ignores_other_runs_and_rejects_unknown_sources():
    assert build_timeline(_events(ATTACK_RUN), run_id="other", source="LIVE")["event_count"] == 0
    with pytest.raises(c1.ContractError):
        build_timeline([], run_id="x", source="MEASURED")


# --- workshop schema ---------------------------------------------------------

def test_workshop_content_validates_and_matches_the_registry():
    reg = {e["lab_id"]: e for e in load_registry()["entries"]}
    found = sorted((ROOT / "learning/level_1").glob("*/workshop.json"))
    assert found, "at least the MCP-001 workshop must exist"
    for path in found:
        doc = json.loads(path.read_text(encoding="utf-8"))
        _validator("workshop").validate(doc)
        assert doc["lab_id"] == path.parent.name and doc["tier"] == reg[doc["lab_id"]]["tier"]
        assert len({s["id"] for s in doc["steps"]}) == len(doc["steps"])
        assert len({c["id"] for c in doc["checks"]}) == len(doc["checks"])
        assert doc["duration_minutes"]["min"] <= doc["duration_minutes"]["max"]


def test_mcp001_workshop_matches_the_existing_nine_step_flow_and_checks():
    doc = _json("learning/level_1/LAB-MCP-001/workshop.json")
    assert [s["id"] for s in doc["steps"]] == ["start", "baseline", "predict", "attack", "investigate", "defend", "retest", "compare", "explain"]
    template = (ROOT / "src/agentsec/templates/academy/workshop_mcp.html").read_text(encoding="utf-8")
    assert all(f'data-step="{s["id"]}"' in template for s in doc["steps"])
    md = (ROOT / "learning/level_1/LAB-MCP-001/knowledge-check.md").read_text(encoding="utf-8")
    questions = re.findall(r"^\d+\.\s+", md.split("## Answers")[0].split("## Questions")[1], re.M)
    assert len(doc["checks"]) == len(questions)
