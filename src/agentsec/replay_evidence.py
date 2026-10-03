"""Canonical otel REPLAY run.ids are historical index contents.

The repository does not ship those event bodies. lab-up and refresh-app do not
invent them. Scanner packs under docs/phase9b-evidence are a different
sourcetype and are not these run.ids.
"""

from __future__ import annotations

from pathlib import Path

EXAMPLE_RUN_ID = "51f70fb9-994e-4dd4-9b36-cac6fb1e8232"


def classify_otel_replay_seed(repo: Path) -> dict:
    lab_up = (repo / "scripts" / "lab-up.sh").read_text(encoding="utf-8")
    artifact = repo / "artifacts" / EXAMPLE_RUN_ID / "events.jsonl"
    scanner = (
        repo
        / "docs"
        / "phase9b-evidence"
        / "normal-b3061c4e-7a81-445c-8fd8-3108dd14c419"
        / "manifest.json"
    )
    return {
        "example_run_id": EXAMPLE_RUN_ID,
        "otel_event_pack_in_workspace": artifact.is_file(),
        "lab_up_posts_events": "post_hec" in lab_up or "events.jsonl" in lab_up,
        "refresh_app_posts_events": "--refresh-app" in lab_up and "events.jsonl" in lab_up,
        "scanner_pack_present": scanner.is_file(),
        "scanner_pack_is_otel_run_seed": False,
        "seed_command": None,
        "classification": "ENVIRONMENT / DEPLOYMENT LIMITATION",
    }
