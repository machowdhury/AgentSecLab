"""REPLAY canonical otel copies are not fabricated by an upgrade."""

from pathlib import Path

from agentsec.replay_evidence import EXAMPLE_RUN_ID, classify_otel_replay_seed

ROOT = Path(__file__).resolve().parents[2]


def test_lab_up_does_not_invent_canonical_otel_events():
    status = classify_otel_replay_seed(ROOT)
    assert status["example_run_id"] == EXAMPLE_RUN_ID
    assert status["lab_up_posts_events"] is False
    assert status["refresh_app_posts_events"] is False
    assert status["seed_command"] is None
    assert status["scanner_pack_present"] is True
    assert status["scanner_pack_is_otel_run_seed"] is False
    assert status["classification"] == "ENVIRONMENT / DEPLOYMENT LIMITATION"
    dashboard = (ROOT / "splunk_app/agentsec/default/data/ui/views/ws_lab_rag_context.xml").read_text(
        encoding="utf-8"
    )
    assert EXAMPLE_RUN_ID in dashboard
    assert not (ROOT / "learning").joinpath(EXAMPLE_RUN_ID, "events.jsonl").is_file()
