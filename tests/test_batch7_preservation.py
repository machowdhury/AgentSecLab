"""Curriculum-preservation guard. The original 31 entries are pinned to the byte-for-byte hashes recorded from the
baseline export (docs/reviews/batch7/preservation_baseline.json). Adding is allowed; changing or removing is not,
unless the baseline manifest is deliberately regenerated and the change is reviewed."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "docs/reviews/batch7/preservation_baseline.json").read_text())


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def test_all_31_original_registry_entries_survive_with_unchanged_classification():
    reg = {e["lab_id"]: e for e in json.loads((ROOT / "learning/academy/lab_registry_data.json").read_text())["entries"]}
    assert len(BASE["registry_ids"]) == 31 and set(BASE["registry_ids"]) <= set(reg)
    for lab in BASE["registry_ids"]:
        now = {k: reg[lab].get(k) for k in ("tier", "primary_domain", "secondary_domain", "pillars", "domain_confidence")}
        assert now == BASE["registry"][lab], lab
    assert len({e for e in reg}) == len(reg)  # no duplicate ids


def test_every_original_learning_file_is_byte_identical():
    changed = [rel for files in BASE["lab_files"].values() for rel, h in files.items()
               if not (ROOT / rel).is_file() or sha(ROOT / rel) != h]
    assert changed == []


def test_original_splunk_views_are_identical_except_the_home_that_lists_the_new_mission():
    cur = {p.name: sha(p) for p in (ROOT / "splunk_app/agentsec/default/data/ui/views").glob("*.xml")}
    diff = sorted(k for k, h in BASE["splunk_views"].items() if cur.get(k) != h)
    assert diff == ["ws_agentsec_home.xml"]


def test_original_curriculum_path_checkpoints_and_modes_are_a_prefix_of_the_current_ones():
    cur = json.loads((ROOT / "learning/academy/curriculum.json").read_text())
    assert cur["checkpoints"] == BASE["curriculum_checkpoints"]
    for i, (title, labs) in enumerate(BASE["curriculum_path"]):
        now = [tuple(l) for l in cur["levels"][i]["labs"] and [[x["lab_id"], x["mode"], x.get("view")] for x in cur["levels"][i]["labs"]]]
        assert [tuple(l) for l in labs] == now[: len(labs)], title


def test_attack_service_image_ships_every_file_the_attack_ui_reads_at_request_time():
    # Baseline defect found in Batch 7: without framework_refs.json "/" and every /labs/<id> page returned HTTP 500 in Docker.
    docker = (ROOT / "docker/Dockerfile.attack").read_text()
    assert "COPY learning/academy/framework_refs.json ./learning/academy/framework_refs.json" in docker
    assert (ROOT / "learning/academy/framework_refs.json").is_file()
