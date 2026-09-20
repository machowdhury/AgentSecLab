"""Learner-facing lab manifests. Not authorization and not coded policy."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from agentsec.settings import REPO_ROOT

MANIFEST_NAME = "lab-manifest.json"
REQUIRED_KEYS = (
    "lab_id",
    "title",
    "security_question",
    "specimens",
    "prediction",
    "limitations",
)


def manifest_path(lab_id: str) -> Path:
    return REPO_ROOT / "learning" / "level_1" / lab_id / MANIFEST_NAME


@lru_cache(maxsize=8)
def load_lab_manifest(lab_id: str) -> dict:
    path = manifest_path(lab_id)
    if not path.is_file():
        raise FileNotFoundError(lab_id)
    return json.loads(path.read_text(encoding="utf-8"))


def validate_lab_manifest(lab_id: str) -> dict:
    data = load_lab_manifest(lab_id)
    if not isinstance(data, dict):
        raise ValueError(f"{lab_id} manifest root must be an object")
    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise ValueError(f"{lab_id} manifest missing keys: {missing}")
    if data.get("not_authorization") is False:
        raise ValueError(f"{lab_id} learning manifest must not claim authorization")
    specimens = data.get("specimens")
    if not isinstance(specimens, list) or not specimens:
        raise ValueError(f"{lab_id} specimens list is empty")
    for row in specimens:
        if not isinstance(row, dict) or "specimen_id" not in row or "mode" not in row:
            raise ValueError(f"{lab_id} specimen row is incomplete")
        if "live" not in row:
            raise ValueError(f"{lab_id} specimen must declare live capability honestly")
    return data


def prediction_for(lab_id: str, mode: str) -> dict | None:
    try:
        manifest = load_lab_manifest(lab_id)
    except FileNotFoundError:
        return None
    block = manifest.get("prediction")
    if not isinstance(block, dict):
        return None
    item = block.get(mode)
    return item if isinstance(item, dict) else None
