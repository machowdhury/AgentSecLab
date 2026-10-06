"""Whether a canonical REPLAY run.id is actually backed by shippable evidence.

A workshop dropdown that offers a run.id is promising the learner a result.
Historically that promise had no backing: the event bodies existed only in the
gitignored ``artifacts/`` tree of whichever workstation first ran the lab, and
neither ``lab-up`` nor ``--refresh-app`` carried them into a new index. A clean
install got an empty dashboard.

That is now fixable per lab, but it is not fixed everywhere. A lab is covered
only once its packs are committed under
``learning/level_1/<LAB>/specimens/``; the seeder in
``scripts/splunk_hec_init.sh`` replays exactly those and nothing else. This
module reports which state a given run.id is in, so the gap stays visible
instead of being assumed closed.
"""

from __future__ import annotations

from pathlib import Path

from agentsec.replay_specimens import SPECIMEN_DIR_NAME, SPECIMEN_FILE_SUFFIX

#: A REPLAY id referenced by a shipped dashboard that has no committed pack.
EXAMPLE_RUN_ID = "51f70fb9-994e-4dd4-9b36-cac6fb1e8232"

#: The component that owns seeding. It also owns the index and the HEC token,
#: so evidence readiness cannot drift away from index creation.
SEED_COMMAND = "scripts/splunk_hec_init.sh"

SEEDED = "SEEDED BY DEPLOYMENT"
UNSEEDED = "UNSEEDED — NO COMMITTED PACK"


def committed_pack(repo: Path, run_id: str) -> Path | None:
    """The committed pack for ``run_id``, or None if no lab ships one."""
    matches = sorted(
        (repo / "learning" / "level_1").glob(
            f"*/{SPECIMEN_DIR_NAME}/{run_id}{SPECIMEN_FILE_SUFFIX}"
        )
    )
    return matches[0] if matches else None


def classify_otel_replay_seed(repo: Path, run_id: str = EXAMPLE_RUN_ID) -> dict:
    hec_init = (repo / SEED_COMMAND).read_text(encoding="utf-8")
    compose = (repo / "docker-compose.yml").read_text(encoding="utf-8")
    pack = committed_pack(repo, run_id)
    scanner = (
        repo
        / "docs"
        / "phase9b-evidence"
        / "normal-b3061c4e-7a81-445c-8fd8-3108dd14c419"
        / "manifest.json"
    )
    return {
        "run_id": run_id,
        "committed_pack_present": pack is not None,
        # The seeder replays committed packs verbatim. It never invents an
        # event body, and it never re-stamps one to look recent.
        "seed_mechanism_present": "seed_replay_specimens" in hec_init,
        "seed_mechanism_mounted": "/specimens:ro" in compose,
        "seed_verifies_by_search": "indexed_count" in hec_init,
        "seed_command": SEED_COMMAND,
        "scanner_pack_present": scanner.is_file(),
        # Scanner evidence is a different sourcetype. It is not an otel run.
        "scanner_pack_is_otel_run_seed": False,
        "classification": SEEDED if pack is not None else UNSEEDED,
    }
