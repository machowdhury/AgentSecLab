#!/usr/bin/env python3
"""Phase 14E LIVE MCP ATTACK/RETEST probe. Not a pytest substitute.

Posts only lab_id/specimen_id/mode/execution. Does not send profile, tool,
scope, grants, or policy. Password stays in the Splunk container env.
"""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.evidence_readiness import count_local_events, probe_splunk_count

ATTACK_URL = os.environ.get("AGENTSEC_ATTACK_URL", "http://127.0.0.1:5001")
ARTIFACTS = ROOT / "artifacts"
SPLUNK_CONTAINER = "agentsec_splunk"
HUNTS = (
    "Q-MCP-WHO",
    "Q-MCP-AUTHZ",
    "Q-MCP-TOOL",
    "Q-MCP-EXECUTED",
    "Q-MCP-AFTER-DENY",
)


def post_json(path: str, body: dict, timeout: int = 180) -> tuple[int, dict]:
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{ATTACK_URL}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(detail)
        except json.JSONDecodeError:
            data = {"raw": detail[:800]}
        return exc.code, data


def get_json(url: str, timeout: int = 10) -> tuple[int, dict]:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def load_events(run_id: str) -> list[dict]:
    path = ARTIFACTS / run_id / "events.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def summarize_local(run_id: str) -> dict:
    events = load_events(run_id)
    names = [str(row.get("event.name") or "") for row in events]
    versions = sorted(
        {
            str(row.get("agentsec.schema.version") or "")
            for row in events
            if row.get("agentsec.schema.version")
        }
    )
    hashes = sorted(
        {
            str(row.get("agentsec.content.hash") or "")
            for row in events
            if row.get("agentsec.content.hash")
        }
    )
    controls = [
        {
            "decision": row.get("agentsec.control.decision"),
            "reason": row.get("agentsec.control.reason"),
            "control_id": row.get("agentsec.control.id"),
            "tool": row.get("gen_ai.tool.name"),
            "requested_scope": row.get("agentsec.mcp.requested_scope"),
            "profile": row.get("agentsec.security.profile"),
            "mode": row.get("agentsec.testbed.mode"),
        }
        for row in events
        if row.get("event.name") == "agentsec.control.decision"
    ]
    return {
        "local_event_count": len(events),
        "schema_versions": versions,
        "content_hashes": hashes,
        "event_names": names,
        "controls": controls,
        "mcp_started": names.count("agentsec.mcp.started"),
        "mcp_completed": names.count("agentsec.mcp.completed"),
        "mcp_failed": names.count("agentsec.mcp.failed"),
    }


def splunk_csv(spl: str) -> dict:
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    )
    try:
        proc = subprocess.run(
            ["docker", "exec", "-u", "splunk", SPLUNK_CONTAINER, "bash", "-lc", inner],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "docker_not_available", "rows": []}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "splunk_probe_timeout", "rows": []}
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "splunk_probe_failed",
            "returncode": proc.returncode,
            "rows": [],
        }
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln and not ln.startswith("WARNING:")]
    if not lines:
        return {"ok": True, "rows": []}
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    return {"ok": True, "rows": rows}


def hunt_spl(name: str, run_id: str) -> str:
    path = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches" / f"{name}.spl"
    return path.read_text(encoding="utf-8").replace("__RUN_ID__", run_id)


def inspect_run(launched: dict, mode: str) -> dict:
    run_id = launched.get("run_id")
    local = summarize_local(run_id)
    time.sleep(2)
    completeness = None
    for _ in range(20):
        completeness = probe_splunk_count(run_id)
        if completeness.get("splunk_ok") and int(completeness.get("splunk_count") or 0) > 0:
            break
        time.sleep(3)
    hunts = {}
    for name in HUNTS:
        hunts[name] = splunk_csv(hunt_spl(name, run_id))
    schema = splunk_csv(
        f'index=agentsec_telemetry sourcetype=otel:agentic:json earliest=-1h '
        f'"agentsec.run.id"="{run_id}" | stats dc(_raw) as n, '
        f'values("agentsec.schema.version") as schema'
    )
    return {
        "mode": mode,
        "run_id": run_id,
        "execution_mode": launched.get("execution_mode"),
        "experiment_id": launched.get("experiment_id"),
        "profile": launched.get("profile"),
        "input_fingerprint": launched.get("input_fingerprint"),
        "runtime": launched.get("runtime"),
        "search_handoff_hunts": (launched.get("search_handoff") or {}).get("reused_hunts"),
        "local": local,
        "evidence_probe": completeness,
        "splunk_schema": schema,
        "hunts": {
            name: {
                "ok": payload.get("ok"),
                "error": payload.get("error"),
                "row_count": len(payload.get("rows") or []),
                "rows": (payload.get("rows") or [])[:8],
            }
            for name, payload in hunts.items()
        },
    }


def main() -> int:
    report: dict = {"phase": "14E", "lab_id": "LAB-MCP-001"}
    try:
        _, health = get_json("http://127.0.0.1:5000/health")
        report["acmebank_health_before"] = {
            "security.profile": health.get("security.profile"),
            "testbed.mode.override": health.get("testbed.mode.override"),
        }
    except urllib.error.URLError as exc:
        print(json.dumps({"error": "acmebank_unreachable", "detail": str(exc)}))
        return 2

    status, rejected = post_json(
        "/api/launch",
        {
            "lab_id": "LAB-MCP-001",
            "specimen_id": "MCP-002",
            "mode": "ATTACK",
            "execution": "live",
            "tool": "lookup_customer_tier",
        },
    )
    report["authority_like_rejected"] = {
        "http_status": status,
        "error": rejected.get("error"),
    }
    if status != 400 or rejected.get("error") != "unknown_fields":
        print(json.dumps(report, indent=2))
        return 3

    launches = []
    for mode in ("ATTACK", "RETEST"):
        status, body = post_json(
            "/api/launch",
            {
                "lab_id": "LAB-MCP-001",
                "specimen_id": "MCP-002",
                "mode": mode,
                "execution": "live",
            },
        )
        if status != 200 or body.get("execution_mode") != "LIVE" or not body.get("run_id"):
            report["launch_error"] = {"mode": mode, "http_status": status, "body": body}
            print(json.dumps(report, indent=2))
            return 4
        launches.append(inspect_run(body, mode))
        time.sleep(1)

    attack, retest = launches
    try:
        _, health_after = get_json("http://127.0.0.1:5000/health")
        report["acmebank_health_after"] = {
            "security.profile": health_after.get("security.profile"),
            "testbed.mode.override": health_after.get("testbed.mode.override"),
        }
    except urllib.error.URLError as exc:
        report["acmebank_health_after"] = {"error": str(exc)}

    report["attack"] = attack
    report["retest"] = retest
    report["equivalence"] = {
        "run_ids_distinct": attack["run_id"] != retest["run_id"],
        "fingerprints_equal": attack["input_fingerprint"] == retest["input_fingerprint"],
        "local_hashes_equal": attack["local"]["content_hashes"] == retest["local"]["content_hashes"]
        and bool(attack["local"]["content_hashes"]),
        "same_tool_scope": True,
        "attack_profile": attack.get("profile"),
        "retest_profile": retest.get("profile"),
        "attack_handler": (attack.get("runtime") or {}).get("handler_invoke_count"),
        "retest_handler": (retest.get("runtime") or {}).get("handler_invoke_count"),
        "attack_blocked": (attack.get("runtime") or {}).get("blocked"),
        "retest_blocked": (retest.get("runtime") or {}).get("blocked"),
    }

    out = ROOT / "artifacts" / "phase14e_live_mcp.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    eq = report["equivalence"]
    if not eq["run_ids_distinct"] or not eq["fingerprints_equal"]:
        return 5
    if eq["attack_handler"] != 1 or eq["retest_handler"] != 0:
        return 6
    if eq["attack_blocked"] is not False or eq["retest_blocked"] is not True:
        return 7
    if not any(
        (row.get("evidence_probe") or {}).get("splunk_ok")
        and int((row.get("evidence_probe") or {}).get("splunk_count") or 0) > 0
        for row in launches
    ):
        print("LIVE Splunk evidence not observed before timeout (not a failed attack).", file=sys.stderr)
        return 8
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
