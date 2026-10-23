"""Batch 9: the live labs' own dropdown specimens (PI, RAG, MEMORY, GOAL, DELEGATION, CAPSTONE), recovered from the two
original September Splunk volumes with the Batch 8 method. Every offered run id has a committed original pack; every pack is
genuine (validates, contiguous sequence, recorded provenance hash); shared packs are byte-identical to the Batch 8 copies;
nothing is generated or marked as anything other than the recorded LIVE/OBSERVED original.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from agentsec.replay_specimens import load_specimens, validate

ROOT = Path(__file__).resolve().parents[1]
MAN = json.loads((ROOT / "docs/reviews/batch9/specimen_recovery.json").read_text())
UU = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LABS = ["LAB-PI-001", "LAB-RAG-CONTEXT", "LAB-MEMORY-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001",
        "LAB-AGENTSEC-CAPSTONE-001", "LAB-ADVANCED-CAPSTONE-MASTERY-001"]
# event counts the original validation documents recorded (PHASE2C: PI-001 baseline 22=22 / attack 6=6 and so on)
DOC_COUNTS = {"b3611d56-0d3f-4b2e-9a51-75ae36628155": 22, "f39fed12-de89-45ba-b684-5b6077942580": 22,
              "78f05d1b-728e-4e70-8993-f5e365871f87": 6, "bbe75cb8-0190-47d6-86be-5feba58ad5c0": 6}


def dropdown_ids(lab):
    d = json.loads((ROOT / f"learning/level_1/{lab}/dashboard.definition.json").read_text())
    return sorted({i for k, v in d.get("inputs", {}).items() if k.startswith("input_") and "run" in k for i in UU.findall(json.dumps(v))})


@pytest.mark.parametrize("lab", LABS)
def test_every_offered_run_id_has_a_committed_original_pack(lab):
    packs = load_specimens(lab, ROOT)
    assert [i for i in dropdown_ids(lab) if i not in packs] == []
    assert {k for k in MAN["labs"][lab] if "/" not in MAN["labs"][lab][k]["path"]} == set(packs)


@pytest.mark.parametrize("lab", LABS)
def test_every_pack_is_genuine_and_matches_its_recorded_hash(lab):
    for rid, sp in load_specimens(lab, ROOT).items():
        assert validate(sp) == [], rid
        assert [e["agentsec.sequence"] for e in sp.events] == list(range(1, sp.event_count + 1)), rid
        rec = MAN["labs"][lab][rid]
        assert rec["status"] == "RECOVERED" and rec["events"] == sp.event_count
        assert hashlib.sha256(sp.path.read_bytes()).hexdigest() == rec["sha256"], f"{rid} changed since recovery"
        assert {e["agentsec.execution.mode"] for e in sp.events} == {"LIVE"} and {e["agentsec.telemetry.fidelity"] for e in sp.events} == {"OBSERVED"}


def test_nothing_is_unavailable_and_event_counts_match_the_original_documents():
    assert [r for e in MAN["labs"].values() for r, v in e.items() if v["status"] != "RECOVERED"] == []
    for rid, n in DOC_COUNTS.items():
        assert MAN["labs"]["LAB-PI-001"][rid]["events"] == n


def test_a_run_cited_by_several_labs_is_byte_identical_everywhere():
    seen: dict[str, set[str]] = {}
    for lab, e in MAN["labs"].items():
        for rid, v in e.items():
            seen.setdefault(rid, set()).add(v["sha256"])
    assert all(len(h) == 1 for h in seen.values())
    # and identical to the Batch 8 copy where Batch 8 already held the run
    b8 = json.loads((ROOT / "docs/reviews/batch8/specimen_recovery.json").read_text())
    for lab, e in b8["labs"].items():
        for rid, v in e.items():
            if rid in seen:
                assert seen[rid] == {v["sha256"]}, rid


def test_provenance_names_both_volumes_and_the_backups_without_secrets():
    s = json.dumps(MAN)
    assert "0aa27f8fe380" in s and "65a0bd8b9afe" in s
    assert all(len(b["sha256"]) == 64 and b["files_hashed"] > 1000 for b in MAN["source"]["backups_outside_repo"].values())
    assert not re.search(r"password|token|secret", s, re.I)
