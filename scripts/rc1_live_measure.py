#!/usr/bin/env python3
"""RC1 LIVE pair measurement. Does not print secrets. Writes JSON only."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "releases" / "V1_0_0_RC1_LIVE_PAIRS.json"

PAIRS = (
    ("LAB-PI-001", "ATK-002"),
    ("LAB-MCP-001", "MCP-002"),
    ("LAB-RAG-CONTEXT", "RAG-001"),
    ("LAB-MEMORY-001", "MEMORY-001"),
    ("LAB-AGENT-GOAL-INTEGRITY-001", "GOAL-001"),
    ("LAB-AGENT-DELEGATION-001", "A2A-001"),
    ("LAB-AGENTSEC-CAPSTONE-001", "CAPSTONE-001"),
)


def env(key: str) -> str:
    for raw in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if raw.startswith(key + "="):
            return raw.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"missing {key}")


def launch(lab_id: str, specimen_id: str, mode: str) -> dict:
    req = urllib.request.Request(
        "http://127.0.0.1:5001/api/launch",
        data=json.dumps(
            {
                "lab_id": lab_id,
                "specimen_id": specimen_id,
                "mode": mode,
                "execution": "live",
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode())
        body["_http"] = resp.status
        return body


def reject(extra: dict) -> dict:
    payload = {
        "lab_id": "LAB-MCP-001",
        "specimen_id": "MCP-002",
        "mode": "ATTACK",
        "execution": "live",
        **extra,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:5001/api/launch",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"http": resp.status, "body": json.loads(resp.read().decode())}
    except Exception as exc:
        data = {"http": getattr(exc, "code", None), "error_type": type(exc).__name__}
        if hasattr(exc, "read"):
            try:
                data["body"] = json.loads(exc.read().decode())
            except Exception:
                data["body"] = None
        return data


def splunk_dc(run_id: str, password: str) -> str:
    spl = (
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=-4h "
        f'"agentsec.run.id"="{run_id}" | stats dc(_raw) as n'
    )
    out = subprocess.check_output(
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
            f"/opt/splunk/bin/splunk search {json.dumps(spl)} -auth admin:$SPLUNK_PASSWORD",
        ],
        text=True,
    )
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("WARNING") and not ln.startswith("INFO:")]
    return lines[-1] if lines else ""


def wait_dc(run_id: str, password: str, expect: int | None) -> str:
    last = ""
    for _ in range(12):
        last = splunk_dc(run_id, password)
        if last.isdigit() and (expect is None or int(last) >= max(1, expect or 1)):
            if expect is None or int(last) == expect or int(last) > 0:
                return last
        time.sleep(4)
    return last


def slim(body: dict) -> dict:
    runtime = body.get("runtime") if isinstance(body.get("runtime"), dict) else {}
    handoff = body.get("search_handoff") if isinstance(body.get("search_handoff"), dict) else {}
    keep_handoff = {
        k: handoff.get(k)
        for k in (
            "copy_run_id",
            "copy_write_run_id",
            "copy_recall_run_id",
            "copy_retrieve_run_id",
        )
        if k in handoff
    }
    return {
        "http": body.get("_http"),
        "run_id": body.get("run_id"),
        "lab_id": body.get("lab_id"),
        "mode": body.get("mode"),
        "specimen_id": body.get("specimen_id"),
        "experiment_id": body.get("experiment_id"),
        "profile": body.get("profile"),
        "evidence_state": body.get("evidence_state"),
        "runtime_status": body.get("runtime_status"),
        "local_event_count": body.get("local_event_count"),
        "input_fingerprint": body.get("input_fingerprint"),
        "intentionally_vulnerable": body.get("intentionally_vulnerable"),
        "handler_invoke_count": runtime.get("handler_invoke_count"),
        "runtime_excerpt": {
            k: runtime.get(k)
            for k in (
                "handler_invoke_count",
                "control_decision",
                "mcp_decision",
                "actual",
            )
            if k in runtime
        },
        "search_handoff_ids": keep_handoff,
    }


def main() -> int:
    password = env("SPLUNK_PASSWORD")
    rejections = {}
    for field in (
        "profile",
        "grants",
        "allowed_tools",
        "allowed_scope",
        "roles",
        "permissions",
        "python",
        "spl",
        "environment",
        "payload",
        "policy",
    ):
        rejections[field] = reject({field: "injected"})

    rows = []
    for lab, specimen in PAIRS:
        attack = launch(lab, specimen, "ATTACK")
        retest = launch(lab, specimen, "RETEST")
        a = slim(attack)
        r = slim(retest)
        ids = [i for i in (a.get("run_id"), r.get("run_id")) if i]
        extra = []
        for src in (a, r):
            extra.extend(
                v
                for v in (src.get("search_handoff_ids") or {}).values()
                if isinstance(v, str) and v not in ids
            )
        completeness = []
        for rid, local in (
            (a.get("run_id"), a.get("local_event_count")),
            (r.get("run_id"), r.get("local_event_count")),
        ):
            if not rid:
                continue
            dc = wait_dc(rid, password, local if isinstance(local, int) else None)
            completeness.append(
                {
                    "run_id": rid,
                    "local_event_count": local,
                    "splunk_dc_raw": dc,
                    "match": str(local) == dc if local is not None else False,
                }
            )
        rows.append(
            {
                "lab_id": lab,
                "specimen_id": specimen,
                "attack": a,
                "retest": r,
                "completeness": completeness,
            }
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "evidence_class": "MEASURED/OBSERVED RC1 validation — not official historical REPLAY pairs",
        "schema_expected": "1.9.0",
        "rejections": rejections,
        "pairs": rows,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(OUT.relative_to(ROOT)), "labs": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
