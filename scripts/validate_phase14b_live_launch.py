#!/usr/bin/env python3
"""Phase 14B LIVE launch probe. Not a pytest substitute.

Requires Attack Service + AcmeBank (+ Splunk for the evidence step).
Uses a FRESH run.id. Canonical REPLAY ids are not proof.

Password stays inside the Splunk container environment.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.evidence_readiness import count_local_events, probe_splunk_count, wait_for_searchable_evidence
from agentsec.search_handoff import starter_spl

ATTACK_URL = os.environ.get("AGENTSEC_ATTACK_URL", "http://127.0.0.1:5001")
ARTIFACTS = ROOT / "artifacts"


def post_launch(specimen_id: str, mode: str, profile: str) -> dict:
    body = json.dumps(
        {
            "lab_id": "LAB-PI-001",
            "specimen_id": specimen_id,
            "profile": profile,
            "mode": mode,
            "execution": "live",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{ATTACK_URL}/api/launch",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


def acme_profile() -> str:
    req = urllib.request.Request("http://127.0.0.1:5000/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return str(data.get("security.profile") or "defended")


def main() -> int:
    try:
        profile = acme_profile()
    except urllib.error.URLError as exc:
        print(json.dumps({"error": "acmebank_unreachable", "detail": str(exc)}))
        return 2

    reports = []
    for specimen_id, mode in (("ATK-001", "BASELINE"), ("ATK-002", "ATTACK")):
        try:
            launched = post_launch(specimen_id, mode, profile)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            print(json.dumps({"error": "launch_http", "status": exc.code, "body": detail[:800]}))
            return 3
        run_id = launched.get("run_id")
        if not run_id or launched.get("execution_mode") != "LIVE":
            print(json.dumps({"error": "missing_live_run_id", "body": launched}, indent=2))
            return 4
        local = count_local_events(ARTIFACTS, run_id)
        evidence = wait_for_searchable_evidence(
            run_id,
            artifacts_dir=ARTIFACTS,
            timeout_seconds=60,
            interval_seconds=2,
            probe_fn=probe_splunk_count,
        )
        reports.append(
            {
                "specimen_id": specimen_id,
                "mode": mode,
                "profile": profile,
                "run_id": run_id,
                "execution_mode": launched.get("execution_mode"),
                "evidence_state_at_launch": launched.get("evidence_state"),
                "splunk_verified_at_launch": launched.get("splunk_verified"),
                "local_event_count": local,
                "otlp.ok": launched.get("otlp.ok"),
                "hec.ok": launched.get("hec.ok"),
                "evidence": evidence,
                "starter_spl": starter_spl(run_id),
                "canonical_replay_ids_used": False,
            }
        )
        time.sleep(1)

    print(json.dumps({"phase": "14B", "live_launches": reports}, indent=2))
    if not reports:
        return 5
    if not any(row["evidence"].get("splunk_verified") for row in reports):
        print("LIVE Splunk evidence not observed before timeout (not a failed attack).", file=sys.stderr)
        return 6
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
