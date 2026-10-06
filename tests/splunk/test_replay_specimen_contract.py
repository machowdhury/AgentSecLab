"""A workshop may only offer a REPLAY specimen it can actually show.

The LAB-MCP-001 "Investigate specimen" dropdown offers three run.ids. For most
of this project's life those ids existed only as literals in a build script and
as event bodies in a gitignored ``artifacts/`` directory on one workstation.
Deployment carried neither. A clean install therefore shipped a dropdown whose
every option produced an empty table, and the Investigation Notebook's pre-run
fallback — the documented entry path for a learner who has not launched
anything yet — silently showed five blank panels.

These tests pin the contract that closed that gap:

    every run.id a dashboard presents as a canonical REPLAY specimen has a
    committed event pack, that pack genuinely belongs to that run.id, and
    deployment seeds it and then proves it is searchable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.replay_specimens import load_specimens, specimen_dir, validate

ROOT = Path(__file__).resolve().parents[2]
LAB = "LAB-MCP-001"
DEFINITION = ROOT / "learning" / "level_1" / LAB / "dashboard.definition.json"
HEC_INIT = (ROOT / "scripts" / "splunk_hec_init.sh").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

WORKSHOP = json.loads(DEFINITION.read_text(encoding="utf-8"))
SPECIMENS = load_specimens(LAB, ROOT)

#: What each pack is for, and how many events it has. Measured from the
#: original runs and documented in learning/level_1/LAB-MCP-001/README.md.
EXPECTED = {
    "163d11e2-e751-4282-9406-19b490542ed4": ("BASELINE", "defended", "ALLOW", 7),
    "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49": ("ATTACK", "vulnerable", "ALLOW", 7),
    "7a1d37b5-d589-4dfd-8322-25ebd0152dbc": ("RETEST", "defended", "DENY", 6),
}


def _dropdown_run_ids() -> list[str]:
    options = WORKSHOP["inputs"]["input_run_id"]["options"]
    ids = [str(item["value"]) for item in options["items"]]
    default = str(options["defaultValue"])
    assert default in ids, "the default specimen is not one of the offered options"
    return ids


# --- the promise and the packs agree ---------------------------------------


def test_every_offered_specimen_has_a_committed_pack():
    """Offering a run.id in the dropdown is a promise of evidence."""
    missing = [rid for rid in _dropdown_run_ids() if rid not in SPECIMENS]
    assert not missing, (
        f"{LAB} offers REPLAY specimens with no committed pack: {missing}. "
        "Deployment cannot seed what the repository does not ship."
    )


def test_the_default_specimen_is_backed_by_evidence():
    """A learner who opens INVESTIGATE before running anything lands here."""
    default = str(WORKSHOP["inputs"]["input_run_id"]["options"]["defaultValue"])
    assert default in SPECIMENS
    assert SPECIMENS[default].event_count > 0


def test_no_orphan_packs_are_shipped():
    """A pack nobody offers is dead weight that still gets seeded."""
    offered = set(_dropdown_run_ids())
    orphans = sorted(set(SPECIMENS) - offered)
    assert not orphans, f"committed packs no dashboard offers: {orphans}"


# --- the packs are honest ---------------------------------------------------


@pytest.mark.parametrize("run_id", sorted(EXPECTED))
def test_pack_events_all_belong_to_their_run_id(run_id):
    """Seeding one run's events under another run's name fabricates evidence."""
    assert run_id in SPECIMENS, f"no committed pack for {run_id}"
    assert validate(SPECIMENS[run_id]) == []


@pytest.mark.parametrize("run_id", sorted(EXPECTED))
def test_pack_matches_the_outcome_the_curriculum_documents(run_id):
    mode, profile, decision, count = EXPECTED[run_id]
    specimen = SPECIMENS[run_id]
    assert specimen.event_count == count
    assert specimen.mode == mode
    assert specimen.profile == profile
    assert specimen.decision == decision


@pytest.mark.parametrize("run_id", sorted(EXPECTED))
def test_pack_carries_the_fields_the_notebook_reads(run_id):
    """A pack that indexes cleanly but lacks these renders empty columns."""
    required = {
        "agentsec.run.id",
        "event.name",
        "agentsec.sequence",
        "agentsec.testbed.mode",
        "agentsec.security.profile",
    }
    decision_only = {
        "agentsec.control.id",
        "agentsec.control.decision",
        "agentsec.control.reason",
        "agentsec.mcp.requested_scope",
        "agentsec.mcp.allowed_scope",
        "gen_ai.tool.name",
    }
    specimen = SPECIMENS[run_id]
    for event in specimen.events:
        assert required <= set(event), f"{run_id}: event missing {required - set(event)}"
    decisions = [e for e in specimen.events if e["event.name"] == "agentsec.control.decision"]
    assert len(decisions) == 1, f"{run_id}: expected exactly one control decision event"
    assert decision_only <= set(decisions[0])


@pytest.mark.parametrize("run_id", sorted(EXPECTED))
def test_packs_contain_no_llm_evidence(run_id):
    """This lab makes no model call. A pack claiming one would be fabricated."""
    names = [str(e.get("event.name", "")) for e in SPECIMENS[run_id].events]
    assert not [n for n in names if n.startswith("agentsec.llm")]


# --- deployment actually seeds them ----------------------------------------


def test_deployment_seeds_committed_packs():
    assert "seed_replay_specimens" in HEC_INIT
    assert "/specimens:ro" in COMPOSE, "the packs are not mounted into the seeder"
    assert "AGENTSEC_SPECIMEN_ROOT" in COMPOSE


def test_seeding_proves_searchability_rather_than_trusting_hec():
    """HEC ACCEPTANCE != INDEXED EVIDENCE. A 200 is not a learner-visible row."""
    assert "indexed_count" in HEC_INIT
    assert "VERIFIED searchable" in HEC_INIT
    # A 200 from HEC must not be the success condition on its own.
    assert "HEC ACCEPTANCE IS NOT EVIDENCE READINESS" in HEC_INIT


def test_seeding_is_idempotent_and_refuses_to_duplicate():
    """Re-posting a partially indexed pack would inflate every count shown."""
    assert "already indexed" in HEC_INIT
    assert "PARTIAL" in HEC_INIT
    assert "Not re-posting" in HEC_INIT


def test_seeding_replays_bodies_verbatim_rather_than_restamping_them():
    """REPLAYED evidence is a recording. Re-dating it would misrepresent it."""
    assert "collector/raw" in HEC_INIT, "the /event endpoint would re-stamp _time"
    assert "--data-binary" in HEC_INIT
    props = (ROOT / "splunk_app/agentsec/default/props.conf").read_text(encoding="utf-8")
    assert 'TIME_PREFIX = "timestamp":' in props


def test_specimens_live_where_the_owning_module_says_they_do():
    assert specimen_dir(LAB, ROOT).is_dir()
    assert specimen_dir(LAB, ROOT) == ROOT / "learning" / "level_1" / LAB / "specimens"
