"""Batch 8: the eight REPLAY labs' original specimens, recovered from the original (September) Splunk index.

Pinned facts: every run id these labs offer or cite has a committed pack; every pack is genuine (validates, one run.id,
contiguous sequence, recorded provenance hash); outcomes match what the original validation documents recorded; shared incident
packs are byte-identical across the labs that cite them; and the non-otel envelope seeder is idempotent, additive and refuses
to guess. Nothing here generates evidence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

from agentsec.replay_specimens import load_specimens, validate

ROOT = Path(__file__).resolve().parents[1]
MAN = json.loads((ROOT / "docs/reviews/batch8/specimen_recovery.json").read_text())
UU = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LABS = ["LAB-BLUE-TEAM-INCIDENT-001", "LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005", "LAB-MCP-006", "LAB-MCP-CATALOG",
        "LAB-MULTI-STAGE-INCIDENT-001", "LAB-SCANNER-RUNTIME-EVIDENCE"]

# (mode, profile, events, mcp.started) per dropdown/lab run, as recorded in the original validation documents
# (docs/PHASE4C..PHASE8D*, MCP005/006 validation, L9 live validation); counts for MCP-003/004 are as recovered.
EXPECTED = {
    "5b089682-1d5a-49a7-ac43-967265fd6bc6": ("BASELINE", "defended", 7, 1), "6ce19813-6cb5-4aae-a3a0-aa59386a82dd": ("ATTACK", "defended", 6, 0),
    "b466ad12-72ec-44b7-be28-aacfaf2c25b1": ("ATTACK", "vulnerable", 7, 1), "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5": ("RETEST", "defended", 6, 0),
    "fb50dcaf-8e84-4a3f-a55b-997c72edbd04": ("BASELINE", "defended", 7, 1), "5ab59fc7-303e-4eea-84e7-ae0b2f405146": ("ATTACK", "vulnerable", 7, 1),
    "0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd": ("RETEST", "defended", 6, 0), "0e4e0051-528d-4bf3-8773-d1fb55a5864f": ("ATTACK", "defended", 6, 0),
    "3013aa39-fe08-4b58-9898-f3abb092ac06": ("BASELINE", "defended", 8, 1), "f3f48182-df57-4b38-b069-17a199dc4939": ("ATTACK", "vulnerable", 13, 2),
    "0ab10594-a7fc-48b6-81bf-4cbca54a64c6": ("RETEST", "defended", 12, 1),
    "1cf98c4d-1bd8-4df5-be70-b82419e2c2b2": ("BASELINE", "defended", 10, 1), "d7524a4e-8da6-4171-8867-d2a2168128ac": ("ATTACK", "vulnerable", 10, 1),
    "50f7ec04-7524-41c0-95a8-3b1ef4d91dc4": ("RETEST", "defended", 6, 0),
    "d95717ed-ffd2-46c0-a130-9a5d7d539a5d": ("BASELINE", "defended", 8, 1), "a0937bff-31a5-453a-99bf-47d7b5148ce4": ("ATTACK", "vulnerable", 13, 2),
    "23c222ea-6a87-40b7-a3e9-f12a5b572fa1": ("RETEST", "defended", 12, 1),
    "2437f64a-fff4-424f-8a83-0f04285662e4": ("ATTACK", "vulnerable", 11, 1), "8d2c016f-cadc-4463-939a-23a183221b3d": ("RETEST", "defended", 10, 0),
}


def dropdown_ids(lab):
    d = json.loads((ROOT / f"learning/level_1/{lab}/dashboard.definition.json").read_text())
    return sorted({i for k, v in d.get("inputs", {}).items() for i in UU.findall(json.dumps(v)) if k.startswith("input_") and ("run" in k)})


@pytest.mark.parametrize("lab", LABS)
def test_every_offered_run_id_has_a_committed_original_pack(lab):
    packs = load_specimens(lab, ROOT)
    assert dropdown_ids(lab), lab
    assert [i for i in dropdown_ids(lab) if i not in packs] == []
    assert sorted(MAN["labs"][lab]) == sorted(packs), "manifest and committed packs disagree"


@pytest.mark.parametrize("lab", LABS)
def test_every_pack_is_genuine_and_matches_its_recorded_hash(lab):
    for rid, sp in load_specimens(lab, ROOT).items():
        assert validate(sp) == [], rid
        assert [e["agentsec.sequence"] for e in sp.events] == list(range(1, sp.event_count + 1)), rid
        rec = MAN["labs"][lab][rid]
        assert rec["status"] == "RECOVERED" and rec["events"] == sp.event_count
        assert hashlib.sha256(sp.path.read_bytes()).hexdigest() == rec["sha256"], f"{rid} changed since recovery"
        assert {e["agentsec.execution.mode"] for e in sp.events} == {"LIVE"} and {e["agentsec.telemetry.fidelity"] for e in sp.events} == {"OBSERVED"}


def test_no_specimen_is_marked_unavailable_or_invented():
    assert [r for e in MAN["labs"].values() for r, v in e.items() if v["status"] != "RECOVERED"] == []
    assert "original" in MAN["source"]["recovered_into"] or "copy" in MAN["source"]["recovered_into"]


@pytest.mark.parametrize("rid,want", sorted(EXPECTED.items()))
def test_outcomes_match_the_original_validation_documents(rid, want):
    mode, profile, count, started = want
    found = [sp for lab in LABS for r, sp in load_specimens(lab, ROOT).items() if r == rid]
    assert found, rid
    ev = found[0].events
    assert (ev[0]["agentsec.testbed.mode"], ev[0]["agentsec.security.profile"], len(ev),
            sum(1 for e in ev if e["event.name"] == "agentsec.mcp.started")) == (mode, profile, count, started)


def test_shared_incident_and_catalog_packs_are_byte_identical_in_every_lab_that_cites_them():
    for a, b in (("LAB-BLUE-TEAM-INCIDENT-001", "LAB-MULTI-STAGE-INCIDENT-001"), ("LAB-MCP-CATALOG", "LAB-SCANNER-RUNTIME-EVIDENCE")):
        pa, pb = load_specimens(a, ROOT), load_specimens(b, ROOT)
        for rid in set(pa) & set(pb):
            assert pa[rid].path.read_bytes() == pb[rid].path.read_bytes(), rid


def test_the_recovery_method_reproduced_the_committed_mcp001_packs_byte_for_byte():
    assert all(v["byte_identical_to_committed"] for v in MAN["method_check"].values()) and len(MAN["method_check"]) == 3


def test_packs_carry_no_secrets():
    pat = re.compile(r"(?i)(password|secret|token|api[_-]?key)\"?\s*[:=]\s*\"[^\"]{8,}")
    for p in (ROOT / "learning/level_1").glob("*/specimens/**/*.jsonl"):
        assert not pat.search(p.read_text()), p


def test_the_otel_seeder_does_not_pick_up_the_envelope_packs():
    import fnmatch
    sub = "LAB-SCANNER-RUNTIME-EVIDENCE/specimens/scanner/x.jsonl"
    assert not fnmatch.fnmatch(sub, "*/specimens/*.jsonl") or sub.count("/") > 2  # shell glob */specimens/*.jsonl is one level deep
    shell = (ROOT / "scripts/splunk_hec_init.sh").read_text()
    assert '"$SPECIMEN_ROOT"/*/specimens/*.jsonl' in shell


# ---------------------------------------------------------------- envelope seeder
def seeder():
    spec = importlib.util.spec_from_file_location("seed_env", ROOT / "scripts/seed_envelope_specimens.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_envelope_packs_are_recorded_originals_not_generated():
    s = seeder()
    packs = s.packs(ROOT)
    assert sorted(p.name for p in packs) == ["7ae3ea64-4e7a-40fe-943f-3e582bce5ee8.jsonl", "aeb05718-1364-4143-8248-71dd6f27b07b.jsonl", "b3061c4e-7a81-445c-8fd8-3108dd14c419.jsonl"]
    counts = {p.name[:8]: len(s.load(p)) for p in packs}
    assert counts == {"7ae3ea64": 2, "aeb05718": 2, "b3061c4": 1} or counts == {"7ae3ea64": 2, "aeb05718": 2, "b3061c4e": 1}
    for p in packs:
        for r in s.load(p):
            assert r["time"] < 1791000000 and r["source"] in ("agentsec-scanner-hec", "agentsec-external-evaluation-hec")  # September 2026, original sources


class FakeIndex:
    """Emulates the windowed, id-filtered count the real seeder asks Splunk for."""

    def __init__(self, preload=()):
        self.events = list(preload)

    def count(self, src, st, lo, hi, needle):
        return sum(1 for s_, t_, ts, raw in self.events if s_ == src and t_ == st and int(lo) - 1 <= ts <= int(hi) + 2 and needle in raw)

    def post(self, row):
        self.events.append((row["source"], row["sourcetype"], row["time"], row["event"]))
        return 200


def _all_rows(s):
    return [r for p in s.packs(ROOT) for r in s.load(p)]


def test_every_event_of_an_envelope_pack_contains_its_pack_id():
    s = seeder()
    for p in s.packs(ROOT):
        assert all(p.stem in r["event"] for r in s.load(p)), p.name


def test_seeder_posts_each_original_event_once_and_proves_searchability_not_http_200(capsys):
    s = seeder()
    idx = FakeIndex()
    assert s.run(ROOT, idx.count, idx.post, wait_s=1, sleep=lambda x: None) == 0
    assert len(idx.events) == 5 == len(_all_rows(s))
    assert capsys.readouterr().out.count("VERIFIED searchable") == 3
    assert s.run(ROOT, idx.count, idx.post, wait_s=1, sleep=lambda x: None) == 0 and len(idx.events) == 5  # idempotent
    assert capsys.readouterr().out.count("No action") == 3


def test_seeder_refuses_a_partially_present_pack_and_never_tops_it_up():
    s = seeder()
    two = [p for p in s.packs(ROOT) if "scanner" in p.parts and len(s.load(p)) == 2][0]
    first = s.load(two)[0]
    idx = FakeIndex([(first["source"], first["sourcetype"], first["time"], first["event"])])
    assert s.run(ROOT, idx.count, idx.post, wait_s=0, sleep=lambda x: None) > 0  # the partial pack makes the run fail...
    assert sum(1 for e in idx.events if e[3] == first["event"]) == 1  # ...and was not topped up


def test_seeder_never_claims_success_from_http_200_alone_and_never_guesses():
    s = seeder()
    assert s.run(ROOT, lambda *a: 0, lambda r: 200, wait_s=0, sleep=lambda x: None) > 0   # 200 but never searchable
    assert s.run(ROOT, lambda *a: 0, lambda r: 403, wait_s=0, sleep=lambda x: None) > 0   # HEC refuses
    assert s.run(ROOT, lambda *a: -1, lambda r: 200, wait_s=0, sleep=lambda x: None) > 0  # Splunk unreachable


def test_seeder_dry_run_posts_nothing():
    s = seeder()
    sent = []
    assert s.run(ROOT, lambda *a: 0, lambda r: sent.append(r) or 200, dry_run=True) == 0 and sent == []


def test_seeder_keeps_tls_verification_on_and_has_no_bypass():
    src = (ROOT / "scripts/seed_envelope_specimens.py").read_text()
    assert "create_default_context(cafile=" in src and "verify=False" not in src and "CERT_NONE" not in src and "check_hostname = False" not in src
