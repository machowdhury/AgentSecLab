"""REPLAY specimens are replayed from committed packs, never invented.

Deployment now seeds canonical REPLAY evidence (see
scripts/splunk_hec_init.sh). These tests pin the two halves of that contract:
a run.id with a committed pack gets seeded, and a run.id without one is
reported as unseeded rather than quietly assumed present.
"""

from pathlib import Path

from agentsec.replay_evidence import (
    EXAMPLE_RUN_ID,
    SEED_COMMAND,
    SEEDED,
    UNSEEDED,
    classify_otel_replay_seed,
    committed_pack,
)

ROOT = Path(__file__).resolve().parents[2]
MCP_BASELINE = "163d11e2-e751-4282-9406-19b490542ed4"


def test_seed_mechanism_exists_and_verifies_by_search():
    status = classify_otel_replay_seed(ROOT)
    assert status["seed_command"] == SEED_COMMAND
    assert status["seed_mechanism_present"] is True
    assert status["seed_mechanism_mounted"] is True
    # HEC acceptance is not evidence readiness: the seeder must confirm the
    # events are searchable before it reports success.
    assert status["seed_verifies_by_search"] is True


def test_run_id_without_a_committed_pack_is_reported_unseeded():
    status = classify_otel_replay_seed(ROOT, EXAMPLE_RUN_ID)
    assert status["committed_pack_present"] is False
    assert status["classification"] == UNSEEDED
    dashboard = (
        ROOT / "splunk_app/agentsec/default/data/ui/views/ws_lab_rag_context.xml"
    ).read_text(encoding="utf-8")
    assert EXAMPLE_RUN_ID in dashboard


def test_lab_mcp_001_baseline_has_a_committed_pack():
    status = classify_otel_replay_seed(ROOT, MCP_BASELINE)
    assert status["committed_pack_present"] is True
    assert status["classification"] == SEEDED
    assert committed_pack(ROOT, MCP_BASELINE) is not None


def test_scanner_evidence_is_not_an_otel_run_seed():
    status = classify_otel_replay_seed(ROOT)
    assert status["scanner_pack_present"] is True
    assert status["scanner_pack_is_otel_run_seed"] is False
