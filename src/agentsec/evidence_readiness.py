"""Bounded evidence-readiness probe. HEC success is not EVIDENCE_READY."""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

from agentsec.search_handoff import completeness_spl

logger = logging.getLogger("agentsec.evidence_readiness")

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_INTERVAL_SEC = 2
MAX_TIMEOUT_SEC = 120
MAX_INTERVAL_SEC = 15
SPLUNK_CONTAINER = "agentsec_splunk"


def count_local_events(artifacts_dir: Path, run_id: str) -> int | None:
    path = artifacts_dir / run_id / "events.jsonl"
    if not path.is_file():
        return None
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def read_export_doc(artifacts_dir: Path, run_id: str) -> dict | None:
    path = artifacts_dir / run_id / "export.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def clamp_timeout(raw: object, default: int = DEFAULT_TIMEOUT_SEC) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(0, min(MAX_TIMEOUT_SEC, value))


def clamp_interval(raw: object, default: int = DEFAULT_INTERVAL_SEC) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(1, min(MAX_INTERVAL_SEC, value))


def probe_splunk_count(
    run_id: str,
    *,
    container: str = SPLUNK_CONTAINER,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict:
    """Count indexed events for run.id. Password stays in the Splunk container env."""

    spl = completeness_spl(run_id)
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    )
    run = runner or subprocess.run
    try:
        proc = run(
            ["docker", "exec", "-u", "splunk", container, "bash", "-lc", inner],
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
    except FileNotFoundError:
        return {
            "splunk_attempted": False,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "docker_not_available",
        }
    except subprocess.TimeoutExpired:
        return {
            "splunk_attempted": True,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "splunk_probe_timeout",
        }
    if proc.returncode != 0:
        logger.info("splunk evidence probe failed rc=%s", proc.returncode)
        return {
            "splunk_attempted": True,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "splunk_probe_failed",
        }
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln and not ln.startswith("WARNING:")]
    if not lines:
        return {
            "splunk_attempted": True,
            "splunk_ok": True,
            "splunk_count": 0,
            "error": None,
        }
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    if not rows or "n" not in rows[0]:
        return {
            "splunk_attempted": True,
            "splunk_ok": True,
            "splunk_count": 0,
            "error": None,
        }
    try:
        count = int(rows[0]["n"])
    except (TypeError, ValueError):
        count = 0
    return {
        "splunk_attempted": True,
        "splunk_ok": True,
        "splunk_count": count,
        "error": None,
    }


def wait_for_searchable_evidence(
    run_id: str,
    *,
    artifacts_dir: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SEC,
    interval_seconds: int = DEFAULT_INTERVAL_SEC,
    probe_fn: Callable[[str], dict] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> dict:
    """Poll until Splunk has at least one event for run.id, or the budget expires.

    Does not treat local export.json hec.ok / otlp.ok as EVIDENCE_READY.
    """

    timeout_seconds = clamp_timeout(timeout_seconds)
    interval_seconds = clamp_interval(interval_seconds)
    local_count = count_local_events(artifacts_dir, run_id)
    export_doc = read_export_doc(artifacts_dir, run_id) or {}
    probe = probe_fn or probe_splunk_count
    deadline = monotonic_fn() + timeout_seconds
    last: dict = {
        "splunk_attempted": False,
        "splunk_ok": False,
        "splunk_count": None,
        "error": None,
    }
    timed_out = False
    while True:
        last = probe(run_id)
        count = last.get("splunk_count")
        if isinstance(count, int) and count >= 1:
            timed_out = False
            break
        if timeout_seconds <= 0:
            timed_out = not (isinstance(count, int) and count >= 1)
            break
        if monotonic_fn() >= deadline:
            timed_out = True
            break
        sleep_fn(interval_seconds)

    splunk_count = last.get("splunk_count") if isinstance(last.get("splunk_count"), int) else None
    searchable = isinstance(splunk_count, int) and splunk_count >= 1
    completeness_ok = (
        searchable and local_count is not None and splunk_count == local_count
    )
    evidence_state = "EVIDENCE_READY" if searchable else "WAITING_FOR_EVIDENCE"
    return {
        "run_id": run_id,
        "evidence_state": evidence_state,
        "splunk_verified": searchable,
        "splunk_attempted": bool(last.get("splunk_attempted")),
        "splunk_ok": bool(last.get("splunk_ok")),
        "splunk_count": splunk_count,
        "local_event_count": local_count,
        "completeness_ok": completeness_ok,
        "evidence_timeout": timed_out and not searchable,
        "probe_error": last.get("error"),
        "otlp.ok": export_doc.get("otlp.ok"),
        "hec.ok": export_doc.get("hec.ok"),
        "note": (
            "EVIDENCE_READY means Splunk returned dc(_raw)>=1 for this run.id. "
            "otlp.ok and HEC HTTP 200 are not EVIDENCE_READY. "
            "Timeout is not a failed attack, DENY, SAFE, or BLOCKED."
        ),
    }


def env_timeout() -> int:
    return clamp_timeout(os.environ.get("AGENTSEC_EVIDENCE_TIMEOUT_SEC"), DEFAULT_TIMEOUT_SEC)


def env_interval() -> int:
    return clamp_interval(os.environ.get("AGENTSEC_EVIDENCE_INTERVAL_SEC"), DEFAULT_INTERVAL_SEC)
