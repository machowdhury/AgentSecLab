"""Learner academy metadata. Not authorization and not coded policy."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from agentsec.settings import REPO_ROOT

CURRICULUM_PATH = REPO_ROOT / "learning" / "academy" / "curriculum.json"

PATH_B_GATE = (
    "This is **Path B — show solution**. Open it only after you tried Path A in "
    "Search. It is an answer key, not policy. Splunk does not enforce."
)

REPLAY_HUNT_BANNER = """**REPLAY workshop.** There is no Attack Service launcher here. This is historical evidence, not a launch you just minted.

**WHY search this?** Reconstruct a canonical experiment in Search. Practice Path A without minting a new run.id.

**Path A — try it yourself:** [Open Splunk Search](http://127.0.0.1:8000/en-US/app/search/search). Copy a canonical Investigate specimen run.id. Constraining `index=agentsec_telemetry sourcetype=otel:agentic:json` and quoted `agentsec.run.id` is the starting point. Construct the hunt before you treat the tables as the answer. If zero rows, this volume may not contain that specimen. Empty is not DENY.

**Path B — show solution:** the bound tables on this tab are the expected shape for that specimen. Read them after Path A. They are not policy and not LIVE launch evidence.

**YOU SHOULD SEE** control.id, decision, reason, and whether execution events exist.
**THAT MEANS** this is the expected shape of a historical copy.
**IT DOES NOT MEAN** Splunk enforced the decision.
**NEXT** COMPARE ATTACK vs RETEST on the same fields, then PROVE.
"""

LIVE_INVESTIGATE_GATE = """**Path A is the default.** Construct the hunt in Splunk Search with your LIVE run.id.

**Path B is optional.** Solution SPL appears after Hint 1 and Hint 2. Do not skip Path A. Path B is an answer key, not policy. Splunk does not enforce.

If Search returns zero rows, wait until Attack Service says **EVIDENCE READY**, then paste the LIVE run.id. Empty is not DENY, not prevention, and not a broken lab.
"""

CAPSTONE_PATH_B_GATE = (
    "This is a **review key**, not the default path. Reconstruct the chain in "
    "Search first. Path B does not authorize, detect, or prove completeness."
)


@lru_cache(maxsize=1)
def load_curriculum() -> dict:
    data = json.loads(CURRICULUM_PATH.read_text(encoding="utf-8"))
    if data.get("not_authorization") is not True:
        raise ValueError("academy curriculum must declare not_authorization=true")
    if data.get("schema_version") != "1.9.0":
        raise ValueError("academy curriculum must remain schema 1.9.0")
    return data


def lab_row(lab_id: str) -> dict | None:
    for level in load_curriculum()["levels"]:
        for row in level.get("labs") or []:
            if row.get("lab_id") == lab_id:
                return {**row, "level_id": level["id"], "level_title": level["title"]}
    return None


def next_lab(lab_id: str) -> dict | None:
    rows: list[dict] = []
    for level in load_curriculum()["levels"]:
        for row in level.get("labs") or []:
            rows.append({**row, "level_id": level["id"], "level_title": level["title"]})
    for index, row in enumerate(rows):
        if row["lab_id"] == lab_id:
            if index + 1 < len(rows):
                return rows[index + 1]
            return None
    return None


def previous_lab(lab_id: str) -> dict | None:
    rows: list[dict] = []
    for level in load_curriculum()["levels"]:
        for row in level.get("labs") or []:
            rows.append(row)
    for index, row in enumerate(rows):
        if row["lab_id"] == lab_id:
            if index > 0:
                return rows[index - 1]
            return None
    return None


ASSESSMENTS_PATH = REPO_ROOT / "learning" / "academy" / "assessments.json"
COMPETENCY_LEVELS = (
    "FOUNDATIONAL",
    "PRACTITIONER",
    "INVESTIGATOR",
    "ADVANCED",
    "PURPLE TEAM",
)
EVIDENCE_MODES = ("NONE", "REPLAY", "LIVE")
KNOWN_CONTROLS = frozenset(
    {
        "CTRL-INPUT-001",
        "CTRL-MCP-001",
        "CTRL-RAG-CONTEXT-001",
        "CTRL-MEMORY-CONTEXT-001",
        "CTRL-GOAL-INTEGRITY-001",
        "CTRL-IDENTITY-001",
    }
)
BANNED_ASSESSMENT_KEYS = frozenset(
    {
        "grants",
        "allowed_tools",
        "allowed_scopes",
        "security_profile",
        "coded_policy",
        "payload",
        "shell",
        "python",
    }
)
REQUIRED_ASSESSMENT_KEYS = (
    "assessment_id",
    "title",
    "competency_level",
    "splunk_skill",
    "lab_id",
    "evidence_mode",
    "run_ids",
    "security_question",
    "task",
    "starter_context",
    "hint_1",
    "hint_2",
    "solution_spl_id",
    "related_hunt",
    "related_control",
    "related_invariant",
    "expected_reasoning",
    "supported_claims",
    "corroborated_claims",
    "not_proven_claims",
    "incorrect_claims",
    "attacker_controlled",
    "server_owned",
    "observability_only",
    "next_assessment",
)


def hunt_path(spl_id: str) -> Path:
    matches = [
        path
        for path in (REPO_ROOT / "learning" / "level_1").rglob(f"{spl_id}.spl")
        if path.parent.name == "searches" and not spl_id.startswith("DET-")
    ]
    if len(matches) != 1:
        raise FileNotFoundError(f"expected one hunt file for {spl_id}, found {matches}")
    return matches[0]


def hunt_spl(spl_id: str) -> str:
    return hunt_path(spl_id).read_text(encoding="utf-8").strip()


def path_b_spl(row: dict) -> str | None:
    spl_id = row.get("solution_spl_id")
    if not spl_id:
        return None
    spl = hunt_spl(str(spl_id))
    run_ids = row.get("run_ids") or {}
    run_id = (
        run_ids.get("specimen")
        or run_ids.get("attack")
        or run_ids.get("retest")
        or next(iter(run_ids.values()), None)
    )
    if run_id and "__RUN_ID__" in spl:
        return spl.replace("__RUN_ID__", f'"{run_id}"')
    return spl


@lru_cache(maxsize=1)
def load_assessments() -> dict:
    data = json.loads(ASSESSMENTS_PATH.read_text(encoding="utf-8"))
    if data.get("not_authorization") is not True:
        raise ValueError("assessments must declare not_authorization=true")
    if data.get("schema_version") != "1.9.0":
        raise ValueError("assessments must remain schema 1.9.0")
    if data.get("progress_persistence") is not False:
        raise ValueError("assessments must not enable progress persistence")
    if data.get("not_certification") is not True:
        raise ValueError("assessments must declare not_certification=true")
    return data


def _lab_rows() -> list[dict]:
    rows: list[dict] = []
    for level in load_curriculum()["levels"]:
        for row in level.get("labs") or []:
            rows.append(row)
    return rows


def validate_assessments() -> list[dict]:
    data = load_assessments()
    banned = BANNED_ASSESSMENT_KEYS.intersection(data)
    if banned:
        raise ValueError(f"assessment catalog contains banned keys: {sorted(banned)}")
    rows = data.get("challenges")
    if not isinstance(rows, list) or not rows:
        raise ValueError("assessments challenges list is empty")
    known_labs = {row["lab_id"] for row in _lab_rows()}
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("challenge is not an object")
        extra_banned = BANNED_ASSESSMENT_KEYS.intersection(row)
        if extra_banned:
            raise ValueError(f"challenge banned keys: {sorted(extra_banned)}")
        missing = [key for key in REQUIRED_ASSESSMENT_KEYS if key not in row]
        if missing:
            raise ValueError(f"challenge missing keys: {missing}")
        ident = row["assessment_id"]
        if ident in seen:
            raise ValueError(f"duplicate assessment_id {ident}")
        seen.add(ident)
        if row["competency_level"] not in COMPETENCY_LEVELS:
            raise ValueError(f"unknown competency_level on {ident}")
        if row["evidence_mode"] not in EVIDENCE_MODES:
            raise ValueError(f"unknown evidence_mode on {ident}")
        lab_id = row["lab_id"]
        if lab_id is not None and lab_id not in known_labs:
            raise ValueError(f"unknown lab_id {lab_id}")
        if row["evidence_mode"] == "NONE" and row.get("run_ids"):
            raise ValueError(f"{ident} NONE mode must not carry run_ids")
        if row["evidence_mode"] in {"REPLAY", "LIVE"} and not row.get("run_ids"):
            raise ValueError(f"{ident} must cite specimen run_ids")
        for spl_id in (row.get("solution_spl_id"), row.get("related_hunt")):
            if spl_id:
                if str(spl_id).startswith("DET-"):
                    raise ValueError(f"{ident} must not reference DET-*")
                hunt_path(str(spl_id))
        control = row.get("related_control")
        if control and control not in KNOWN_CONTROLS:
            raise ValueError(f"{ident} unknown control {control}")
        if not row["incorrect_claims"]:
            raise ValueError(f"{ident} must teach incorrect claims")
        if not row["task"] or not row["hint_1"] or not row["expected_reasoning"]:
            raise ValueError(f"{ident} Path A/B content incomplete")
    for row in rows:
        nxt = row["next_assessment"]
        if nxt is not None and nxt not in seen:
            raise ValueError(f"{row['assessment_id']} next_assessment missing {nxt}")
    rubric = data.get("rubric") or {}
    dims = rubric.get("dimensions") or []
    if len(dims) < 5:
        raise ValueError("mastery rubric is incomplete")
    return rows


def challenges_for(level: str) -> list[dict]:
    return [row for row in validate_assessments() if row["competency_level"] == level]
