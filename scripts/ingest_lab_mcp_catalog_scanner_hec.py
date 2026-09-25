#!/usr/bin/env python3
"""Ingest canonical Phase 9B scanner packs into Splunk HEC.

Does not modify runtime authorization. Does not send otel:agentic:json.
Does not print secrets. Uses SPLUNK_HEC_TOKEN from the repository .env.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from agentsec.scanners.hec_events import (  # noqa: E402
    INDEX_NAME,
    SOURCETYPE,
    events_from_canonical_packs,
)


def load_env_value(key: str) -> str:
    env_path = ROOT / ".env"
    if not env_path.is_file():
        return ""
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return ""


def splunk_search(spl: str) -> str:
    password = load_env_value("SPLUNK_PASSWORD")
    if not password:
        raise SystemExit("SPLUNK_PASSWORD missing from .env")
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    )
    proc = subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "splunk",
            "-e",
            f"SPLUNK_PASSWORD={password}",
            "agentsec_splunk",
            "bash",
            "-lc",
            inner,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-800:] if proc.stderr else "splunk search failed\n")
        raise RuntimeError("Splunk search unavailable or failed")
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln and not ln.startswith("WARNING:")]
    return "\n".join(lines)


def existing_raw_count(scan_id: str) -> int | None:
    try:
        csv_text = splunk_search(
            f'index={INDEX_NAME} sourcetype={SOURCETYPE} earliest=0 scan_id={scan_id} | stats dc(_raw) as n'
        )
    except RuntimeError:
        return None
    rows = [ln for ln in csv_text.splitlines() if ln]
    if len(rows) < 2:
        return 0
    try:
        return int(rows[1].split(",")[0])
    except ValueError:
        return 0


def post_hec(payload: dict) -> int:
    token = load_env_value("SPLUNK_HEC_TOKEN")
    if not token:
        raise SystemExit("SPLUNK_HEC_TOKEN missing from .env")
    url = "http://127.0.0.1:8088/services/collector/event"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except urllib.error.URLError as exc:
        raise RuntimeError("HEC unavailable; no evidence was submitted") from exc


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    events = events_from_canonical_packs(ROOT)
    expected_by_scan: dict[str, int] = {}
    for payload in events:
        scan_id = payload["event"]["scan_id"]
        expected_by_scan[scan_id] = expected_by_scan.get(scan_id, 0) + 1
    print(
        json.dumps(
            {
                "local_normalized_events": len(events),
                "by_scan_id": expected_by_scan,
                "sourcetype": SOURCETYPE,
                "index": INDEX_NAME,
                "dry_run": dry_run,
            }
        )
    )
    if dry_run:
        return
    submitted = 0
    statuses: list[int] = []
    skipped = 0
    skip_scans: set[str] = set()
    for scan_id, expected in expected_by_scan.items():
        existing = existing_raw_count(scan_id)
        if existing is not None and existing >= expected:
            skip_scans.add(scan_id)
            skipped += expected
    for payload in events:
        scan_id = payload["event"]["scan_id"]
        if scan_id in skip_scans:
            continue
        code = post_hec(payload)
        statuses.append(code)
        if code == 200:
            submitted += 1
        else:
            print(json.dumps({"error": "hec_http", "status": code, "scan_id": scan_id}))
            raise SystemExit(1)
    print(
        json.dumps(
            {
                "events_submitted": submitted,
                "events_skipped_already_present": skipped,
                "hec_status_codes": statuses,
            }
        )
    )


if __name__ == "__main__":
    main()
