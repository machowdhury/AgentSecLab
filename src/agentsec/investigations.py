"""Guided investigation metadata. Not authorization and not coded policy."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from agentsec.settings import REPO_ROOT

INVESTIGATIONS_NAME = "investigations.json"
REQUIRED_KEYS = (
    "investigation_id",
    "title",
    "security_question",
    "learning_objective",
    "difficulty",
    "prerequisites",
    "starter_guidance",
    "hint_1",
    "hint_2",
    "solution_spl_id",
    "expected_result_shape",
    "result_explanation",
    "security_interpretation",
    "does_not_prove",
    "related_control",
    "related_invariant",
    "related_hunt",
    "next_investigation",
)


def investigations_path(lab_id: str) -> Path:
    return REPO_ROOT / "learning" / "level_1" / lab_id / INVESTIGATIONS_NAME


@lru_cache(maxsize=8)
def load_investigations(lab_id: str) -> dict:
    path = investigations_path(lab_id)
    if not path.is_file():
        raise FileNotFoundError(lab_id)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{lab_id} investigations root must be an object")
    return data


def investigation_rows(lab_id: str) -> list[dict]:
    data = load_investigations(lab_id)
    rows = data.get("investigations")
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{lab_id} investigations list is empty")
    return rows


def validate_investigations(lab_id: str) -> list[dict]:
    data = load_investigations(lab_id)
    if data.get("not_authorization") is not True:
        raise ValueError(f"{lab_id} investigations must declare not_authorization=true")
    rows = investigation_rows(lab_id)
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("investigation row is not an object")
        missing = [key for key in REQUIRED_KEYS if key not in row]
        if missing:
            raise ValueError(f"investigation missing keys: {missing}")
        ident = row["investigation_id"]
        if ident in seen:
            raise ValueError(f"duplicate investigation_id {ident}")
        seen.add(ident)
    return rows
