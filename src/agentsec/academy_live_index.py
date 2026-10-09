"""Durable Academy LIVE run references for LAB-MCP-001.

Launcher memory is not the only source of notebook history. Each successful
LAB-MCP-001 launch writes a sidecar next to the runtime artifact and an index
under the artifacts directory. After Attack Service restart the notebook can
rehydrate those UUIDs. This is not a tree browser: lookup is UUID-gated and
only LAB-MCP-001 LIVE refs are accepted.

The index never stores credentials, tokens, or request argument bodies.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentsec.academy_evidence import LAB_ID, RUNTIME_SCHEMA, is_run_id

INDEX_NAME = "academy_live_index.json"
REF_NAME = "academy_ref.json"
INDEX_SCHEMA = "agentsec.academy.live_index"
REF_SCHEMA = "agentsec.academy.live_ref"
INDEX_VERSION = "1.0.0"
SCENARIOS = frozenset({"ATTACK", "RETEST", "BASELINE"})
EVIDENCE_MODE = "LIVE"

_LOCK = threading.Lock()


@dataclass(frozen=True)
class LiveRunRef:
    run_id: str
    lab_id: str
    scenario: str
    evidence_mode: str
    recorded_at: str
    artifact: str
    schema_version: str
    profile: str | None
    specimen_id: str | None
    status: str

    def to_public(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "lab_id": self.lab_id,
            "scenario": self.scenario,
            "evidence_mode": self.evidence_mode,
            "recorded_at": self.recorded_at,
            "artifact": self.artifact,
            "schema_version": self.schema_version,
            "profile": self.profile,
            "specimen_id": self.specimen_id,
            "status": self.status,
        }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _index_path(artifacts_dir: Path) -> Path:
    return artifacts_dir / INDEX_NAME


def _ref_path(artifacts_dir: Path, run_id: str) -> Path:
    return artifacts_dir / run_id / REF_NAME


def _events_path(artifacts_dir: Path, run_id: str) -> Path:
    return artifacts_dir / run_id / "events.jsonl"


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _status_for(artifacts_dir: Path, run_id: str) -> str:
    path = _events_path(artifacts_dir, run_id)
    if not path.is_file():
        return "missing"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return "incomplete"
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return "incomplete"
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError:
        return "incomplete"
    if not isinstance(first, dict) or first.get("agentsec.run.id") != run_id:
        return "incomplete"
    return "complete"


def _normalize_entry(raw: object, artifacts_dir: Path) -> LiveRunRef | None:
    if not isinstance(raw, dict):
        return None
    run_id = raw.get("run_id")
    if not is_run_id(run_id):
        return None
    assert isinstance(run_id, str)
    lab_id = raw.get("lab_id")
    scenario = raw.get("scenario")
    evidence_mode = raw.get("evidence_mode")
    if lab_id != LAB_ID or scenario not in SCENARIOS or evidence_mode != EVIDENCE_MODE:
        return None
    recorded_at = raw.get("recorded_at")
    if not isinstance(recorded_at, str) or not recorded_at:
        recorded_at = _now()
    schema_version = raw.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version:
        schema_version = RUNTIME_SCHEMA
    profile = raw.get("profile")
    if profile is not None and not isinstance(profile, str):
        profile = None
    specimen_id = raw.get("specimen_id")
    if specimen_id is not None and not isinstance(specimen_id, str):
        specimen_id = None
    return LiveRunRef(
        run_id=run_id,
        lab_id=LAB_ID,
        scenario=str(scenario),
        evidence_mode=EVIDENCE_MODE,
        recorded_at=recorded_at,
        artifact=f"artifacts/{run_id}/events.jsonl",
        schema_version=schema_version,
        profile=profile,
        specimen_id=specimen_id,
        status=_status_for(artifacts_dir, run_id),
    )


def _load_index_unlocked(artifacts_dir: Path) -> list[LiveRunRef]:
    path = _index_path(artifacts_dir)
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, dict) or raw.get("schema") != INDEX_SCHEMA:
        return []
    entries = raw.get("entries")
    if not isinstance(entries, list):
        return []
    seen: set[str] = set()
    out: list[LiveRunRef] = []
    for item in entries:
        ref = _normalize_entry(item, artifacts_dir)
        if ref is None or ref.run_id in seen:
            continue
        seen.add(ref.run_id)
        out.append(ref)
    return out


def _sidecar_ref(artifacts_dir: Path, run_id: str) -> LiveRunRef | None:
    path = _ref_path(artifacts_dir, run_id)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("schema") != REF_SCHEMA:
        return None
    return _normalize_entry(raw, artifacts_dir)


def persist_live_run(
    artifacts_dir: Path,
    *,
    run_id: str,
    scenario: str,
    profile: str | None = None,
    specimen_id: str | None = None,
    schema_version: str = RUNTIME_SCHEMA,
    recorded_at: str | None = None,
) -> LiveRunRef | None:
    """Record a LAB-MCP-001 LIVE run. Duplicate run.ids replace in place."""
    if not is_run_id(run_id) or scenario not in SCENARIOS:
        return None
    ref = LiveRunRef(
        run_id=run_id,
        lab_id=LAB_ID,
        scenario=scenario,
        evidence_mode=EVIDENCE_MODE,
        recorded_at=recorded_at or _now(),
        artifact=f"artifacts/{run_id}/events.jsonl",
        schema_version=schema_version or RUNTIME_SCHEMA,
        profile=profile,
        specimen_id=specimen_id,
        status=_status_for(artifacts_dir, run_id),
    )
    sidecar = {
        "schema": REF_SCHEMA,
        "version": INDEX_VERSION,
        "run_id": ref.run_id,
        "lab_id": ref.lab_id,
        "scenario": ref.scenario,
        "evidence_mode": ref.evidence_mode,
        "recorded_at": ref.recorded_at,
        "artifact": REF_NAME,
        "events_artifact": "events.jsonl",
        "schema_version": ref.schema_version,
        "profile": ref.profile,
        "specimen_id": ref.specimen_id,
    }
    with _LOCK:
        _atomic_write(_ref_path(artifacts_dir, run_id), sidecar)
        current = [item for item in _load_index_unlocked(artifacts_dir) if item.run_id != run_id]
        current.append(ref)
        _atomic_write(
            _index_path(artifacts_dir),
            {
                "schema": INDEX_SCHEMA,
                "version": INDEX_VERSION,
                "lab_id": LAB_ID,
                "entries": [
                    {
                        "run_id": item.run_id,
                        "lab_id": item.lab_id,
                        "scenario": item.scenario,
                        "evidence_mode": item.evidence_mode,
                        "recorded_at": item.recorded_at,
                        "artifact": item.artifact,
                        "schema_version": item.schema_version,
                        "profile": item.profile,
                        "specimen_id": item.specimen_id,
                    }
                    for item in current
                ],
            },
        )
    return ref


def is_authorized(artifacts_dir: Path, run_id: str) -> bool:
    """True when this UUID is a durable LAB-MCP-001 LIVE ref (index or sidecar)."""
    if not is_run_id(run_id):
        return False
    with _LOCK:
        for item in _load_index_unlocked(artifacts_dir):
            if item.run_id == run_id:
                return True
        return _sidecar_ref(artifacts_dir, run_id) is not None


def get_ref(artifacts_dir: Path, run_id: str) -> LiveRunRef | None:
    if not is_run_id(run_id):
        return None
    with _LOCK:
        for item in _load_index_unlocked(artifacts_dir):
            if item.run_id == run_id:
                return item
        return _sidecar_ref(artifacts_dir, run_id)


def list_refs(artifacts_dir: Path) -> list[LiveRunRef]:
    with _LOCK:
        refs = list(_load_index_unlocked(artifacts_dir))
        known = {item.run_id for item in refs}
        # Sidecars recover entries if the index file was truncated.
        if artifacts_dir.is_dir():
            for child in artifacts_dir.iterdir():
                if not child.is_dir() or child.name in known or not is_run_id(child.name):
                    continue
                sidecar = _sidecar_ref(artifacts_dir, child.name)
                if sidecar is not None:
                    refs.append(sidecar)
                    known.add(child.name)
        return refs


def notebook_slots(artifacts_dir: Path) -> dict[str, Any]:
    """Latest complete LIVE ATTACK and RETEST refs, plus incomplete/missing notes."""
    refs = list_refs(artifacts_dir)
    refs.sort(key=lambda item: item.recorded_at)
    slots: dict[str, LiveRunRef | None] = {"ATTACK": None, "RETEST": None}
    notes: list[str] = []
    for ref in refs:
        if ref.scenario not in slots:
            continue
        if ref.status == "complete":
            slots[ref.scenario] = ref
        elif slots[ref.scenario] is None:
            notes.append(
                f"{ref.scenario} run {ref.run_id} is recorded but its event record is {ref.status}."
            )
    return {
        "lab_id": LAB_ID,
        "evidence_mode": EVIDENCE_MODE,
        "slots": {key: (None if value is None else value.to_public()) for key, value in slots.items()},
        "runs": [item.to_public() for item in refs],
        "notes": notes,
        "not_authorization": True,
    }


def launch_body_from_ref(ref: LiveRunRef) -> dict[str, Any]:
    """Minimal launch metadata after a restart. Handler counts stay NOT MEASURED."""
    return {
        "mode": ref.scenario,
        "profile": ref.profile,
        "specimen_id": ref.specimen_id,
        "execution_mode": EVIDENCE_MODE,
        "recovered": True,
        "runtime": {},
        "note": (
            "Recovered from the durable Academy LIVE index after service restart. "
            "Handler counts from the original launch response are NOT MEASURED here; "
            "use the event record."
        ),
    }
