"""Increment 11D checkpoints: every fact, answer and comparison shown for the nine simulated or documented packets comes from the committed packet.

The packet is embedded unchanged in academy-ui/src/content/recorded/<LAB>.json (loaded on demand). These tests re-read the packet and the lab documents
and recompute every answer with code that is separate from the UI. A simulated or documented packet is never presented as a live or measured run.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
DATA = json.loads((ROOT / "academy-ui" / "src" / "content" / "curriculum.json").read_text(encoding="utf-8"))
LABS = {l["id"]: l for l in DATA["labs"]}
FILES = ROOT / "academy-ui" / "src" / "content" / "recorded"
MODES = ("A2A-AUTH-DELEGATION", "HITL-APPROVAL", "CREDENTIAL-LIFETIME", "CODE-AGENT-BOUNDS", "CHANGE-BOUNDS", "RAG-PURPOSE", "RECALL-ISOLATION", "COMPONENT-PROVENANCE")
INVENTORY = "LAB-ASSET-INVENTORY"
ALL = [f"LAB-{m}" for m in MODES] + [INVENTORY]
D = lambda b, a, r: {"BASELINE": b, "ATTACK": a, "RETEST": r}
EXPECTED = {   # what each lab's own "Path B" review states, per case
    "LAB-A2A-AUTH-DELEGATION": {"evaluation": D("MATCH", "MISMATCH", "MISMATCH"), "decision": D("ALLOW", "ALLOW", "DENY"), "execution": D("YES", "YES", "NO")},
    "LAB-HITL-APPROVAL": {"window": D("inside the window", "inside the window", "inside the window"), "binding": D("MATCH", "MISMATCH", "MISMATCH"), "decision": D("ALLOW", "ALLOW", "DENY"), "execution": D("YES", "YES", "NO")},
    "LAB-CREDENTIAL-LIFETIME": {"lifetime": D("inside its lifetime", "outside its lifetime", "outside its lifetime"), "decision": D("ALLOW", "ALLOW", "DENY"), "execution": D("YES", "YES", "NO")},
    "LAB-CODE-AGENT-BOUNDS": {"binding": D("MATCH", "MISMATCH", "MISMATCH"), "decision": D("ALLOW", "ALLOW", "DENY"), "execution": D("YES", "YES", "NO")},
    "LAB-CHANGE-BOUNDS": {"binding": D("MATCH", "MISMATCH", "MISMATCH"), "decision": D("ALLOW", "ALLOW", "DENY"), "execution": D("YES", "YES", "NO")},
    "LAB-COMPONENT-PROVENANCE": {"decision": D("ALLOW", "ALLOW", "DENY")},
    "LAB-RAG-PURPOSE": {"purpose": D("yes", "no", "no"), "decision": D("ALLOW", "FAIL_OPEN", "DENY"), "use": D("USED FOR THE ALLOWED PURPOSE", "USED", "NOT USED")},
    "LAB-RECALL-ISOLATION": {"owner": D("yes", "no", "no"), "recall": D("RETURNED", "RETURNED", "ISOLATED"), "isolation": D("OWNER", "CROSSED", "HELD")},
}
REASONS = {   # the reason codes in each lab's Path B review (ATTACK is the labelled vulnerable teaching reason)
    "LAB-A2A-AUTH-DELEGATION": D("tool_granted", "vulnerable_profile_fail_open:caller_identity_derived_authority", "tool_not_granted"),
    "LAB-HITL-APPROVAL": D("tool_granted", "vulnerable_profile_fail_open:stale_approval_accepted", "approval_binding_mismatch"),
    "LAB-CREDENTIAL-LIFETIME": D("tool_granted", "vulnerable_profile_fail_open:expired_credential_accepted", "expired_credential"),
    "LAB-CODE-AGENT-BOUNDS": D("tool_granted", "vulnerable_profile_fail_open:code_agent_scope_not_checked", "operation_not_granted"),
    "LAB-CHANGE-BOUNDS": D("tool_granted", "vulnerable_profile_fail_open:change_scope_not_checked", "change_not_granted"),
    "LAB-COMPONENT-PROVENANCE": D("tool_granted", "vulnerable_profile_fail_open:known_component_treated_as_grant", "provenance_is_not_a_grant"),
}
DIFFS = {   # request details that differ BASELINE -> ATTACK, and ATTACK -> RETEST (never any)
    "LAB-A2A-AUTH-DELEGATION": ["requested_tool", "requested_scope", "requested_resource"], "LAB-HITL-APPROVAL": ["submitted_resource", "submitted_action_reference"],
    "LAB-CREDENTIAL-LIFETIME": ["credential_reference", "requested_tool", "requested_resource"], "LAB-CODE-AGENT-BOUNDS": ["submitted_operation", "request_id"],
    "LAB-CHANGE-BOUNDS": ["submitted_operation", "request_id"], "LAB-COMPONENT-PROVENANCE": ["component", "provenance", "requested_tool"],
    "LAB-RAG-PURPOSE": ["requested_purpose", "request_id"], "LAB-RECALL-ISOLATION": ["reader", "request_id"],
}
INVENTORY_ANSWERS = {
    "i1": {"llama3.2:1b", "ollama/ollama", "acme-agent-fulfillment-006", "lookup_policy", "in-process teaching MCP", "agentsec"},
    "i2": {"acme-agent-fulfillment-006"}, "i3": {"lookup_policy", "cisco mcp-scanner", "garak"}, "i4": {"ollama/ollama"},
}


def cp(lab):
    return json.loads((FILES / LABS[lab]["explainer"]["recorded_ref"]["file"]).read_text(encoding="utf-8"))


def source(lab):
    d = cp(lab)
    return json.loads((ROOT / d["packet_file"]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("lab", ALL)
def test_packet_is_embedded_unchanged_loaded_on_demand_and_the_tier_is_untouched(lab):
    ex = LABS[lab]["explainer"]
    d = cp(lab)
    assert ex["recorded_ref"] == {"kind": "checkpoint", "file": f"{lab}.json"} and "packet_id" not in json.dumps(ex)
    assert d["kind"] == "checkpoint" and d["packet"] == source(lab)
    assert hashlib.sha256((ROOT / d["packet_file"]).read_bytes()).hexdigest() == d["sha256"]
    assert (ROOT / d["packet_file"]).parent == ROOT / "learning/level_1" / lab
    assert LABS[lab]["availability"] in ("content_only", "replay") and LABS[lab]["integrated"] is False and LABS[lab]["launchable"] is False and LABS[lab]["native"] is None
    assert ex["status"] == "full"


@pytest.mark.parametrize("lab", ALL)
def test_classification_is_the_packets_own_and_never_live_or_measured(lab):
    d = cp(lab)
    cls = d["packet"]["evidence_classification"]
    assert cls in ("SIMULATED / REPLAYED", "DOCUMENTED", "DOCUMENTED / SIMULATED")
    ui = (ROOT / "academy-ui/src/workbench/CheckpointWorkbench.tsx").read_text(encoding="utf-8")
    assert "NOT A LIVE RUN" in ui and "makes no claim" in ui
    for forbidden in ("launchLab", "fetch(", "/api/", "SPLUNK-VERIFIED", "splunk_verified", "XMLHttpRequest", "compliant", "secure deletion verified"):
        assert forbidden not in ui, forbidden


def parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


def independent(lab, mode, p, packet):
    m = {x["mode"]: x for x in packet["modes"]}[mode]
    d = p.get("derived")
    if d and d["kind"] == "within":
        w = d["window"]
        src = next(c for c in packet[w["lookup"]["list"]] if c[w["lookup"]["key"]] == m[w["lookup"]["by"]]) if "lookup" in w else packet[w["packet_path"]]
        return d["inside"] if parse(src[w["from"]]) <= parse(m[d["at"]]) <= parse(src[w["to"]]) else d["outside"]
    if d:
        return "yes" if m[d["a"]] == packet[d["b_packet"]] else "no"
    v = m[p["field"]]
    return next((o for o in p["options"] if v.startswith(o)), v) if p.get("match") == "startswith" else v


@pytest.mark.parametrize("lab", [f"LAB-{m}" for m in MODES])
def test_every_prediction_answer_matches_the_labs_own_review_and_is_recomputed_from_the_packet(lab):
    d = cp(lab); spec = d["spec"]; packet = source(lab)
    assert spec["order"] == ["BASELINE", "ATTACK", "RETEST"]
    assert {p["id"] for p in spec["predictions"]} == set(EXPECTED[lab])
    for p in spec["predictions"]:
        assert len(p["options"]) >= 2 and len(set(p["options"])) == len(p["options"])
        for mode in spec["order"]:
            got = independent(lab, mode, p, packet)
            assert got == EXPECTED[lab][p["id"]][mode], (p["id"], mode, got)
            assert got in p["options"], (p["id"], mode, "the packet's answer must be one of the options offered")
    if lab in REASONS:
        for mode in spec["order"]:
            m = next(x for x in packet["modes"] if x["mode"] == mode)
            assert m["ctrl_mcp_001_reason"] == REASONS[lab][mode]
    for mode in spec["order"]:
        m = next(x for x in packet["modes"] if x["mode"] == mode)
        if "resource_impact" in m:
            assert m["resource_impact"] == "NOT PROVEN", "the packet never proves resource impact; neither may the page"


def test_credential_lifetime_derived_answer_agrees_with_the_packets_own_status():
    packet = source("LAB-CREDENTIAL-LIFETIME"); creds = {c["credential_reference"]: c for c in packet["credentials"]}
    for m in packet["modes"]:
        inside = parse(creds[m["credential_reference"]]["not_before"]) <= parse(m["presented_at"]) <= parse(creds[m["credential_reference"]]["expires_at"])
        assert inside == (m["credential_status"] == "CURRENT")
    assert parse(packet["approval_expires_at"]) != parse(next(c for c in packet["credentials"] if c["status"] == "CURRENT")["expires_at"]), "two separate clocks"


def test_hitl_window_answer_agrees_with_the_packets_own_validity_field():
    packet = source("LAB-HITL-APPROVAL"); a = packet["approval"]
    for m in packet["modes"]:
        assert (parse(a["not_before"]) <= parse(m["action_submitted_at"]) <= parse(a["expires_at"])) == (m["approval_validity"] == "INSIDE WINDOW")


@pytest.mark.parametrize("lab", list(DIFFS))
def test_spot_the_difference_is_computed_from_the_packet(lab):
    d = cp(lab); packet = source(lab); by = {m["mode"]: m for m in packet["modes"]}
    fields = [f["field"] for f in d["spec"]["diff"]]
    assert [f for f in fields if by["BASELINE"].get(f) != by["ATTACK"].get(f)] == [f for f in fields if f in DIFFS[lab]]
    assert [f for f in fields if by["ATTACK"].get(f) != by["RETEST"].get(f)] == [], "ATTACK and RETEST record the same request"


def test_inventory_answers_are_computed_from_the_documented_list():
    d = cp(INVENTORY); items = source(INVENTORY)["components"]; spec = d["spec"]
    assert spec["kind"] == "inventory" and d["packet"]["evidence_classification"] == "DOCUMENTED"
    for q in spec["questions"]:
        w = q["where"]
        got = {i["name"] for i in items if (i[w["field"]] == w["equals"] if "equals" in w else i[w["field"]] != w["not_equals"] if "not_equals" in w else w["contains"] in i[w["field"]])}
        assert got == INVENTORY_ANSWERS[q["id"]], q["id"]
        assert EXP.clean(q["quote"]["text"]) in EXP.source_text(ROOT / q["quote"]["file"]), q["id"]
    assert source(INVENTORY)["cisco_aibom_compatibility"].startswith("NOT CLAIMED")


@pytest.mark.parametrize("lab", ALL)
def test_context_facts_tables_and_spl_are_the_packet_and_lab_text_unchanged(lab):
    d = cp(lab); packet = source(lab); spec = d["spec"]
    def dig(o, path):
        for k in path.split("."):
            o = o[k]
        return o
    for k in ("context", "packet_facts"):
        for x in spec.get(k, []):
            assert dig(packet, x["path"]) is not None, x
    for t in spec.get("tables", []):
        rows = dig(packet, t["path"])
        assert rows and all(c[0] in r for r in rows for c in t["columns"])
    for q in d["spl"]:
        assert q["text"] == (ROOT / q["source"]).read_text(encoding="utf-8").strip()


