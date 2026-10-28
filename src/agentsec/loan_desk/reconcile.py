"""Reconcile one Loan Desk run: events this process emitted (local) versus events Splunk indexed.

Host-side only. It reuses the existing `docker exec ... splunk search` mechanism (the admin password stays inside
the Splunk container; nothing here reads or prints it). It never uses the management REST probe.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import time
from collections import Counter
from typing import Callable

# Overridable so a disposable copy of the lab can be verified without ever touching the real Splunk container.
SPLUNK_CONTAINER = os.environ.get("AGENTSEC_SPLUNK_CONTAINER", "agentsec_splunk")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", SPLUNK_CONTAINER):
    raise ValueError("AGENTSEC_SPLUNK_CONTAINER is not a valid container name")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BASE = 'index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-24h "agentsec.run.id"="{run}"'


def run_spl(spl: str, *, container: str = SPLUNK_CONTAINER, runner: Callable | None = None, client=None) -> list[dict]:
    if client is None and runner is None:
        from agentsec.splunk_client import SplunkError, client_for_mode
        try:
            client = client_for_mode()          # None in BUNDLED mode; external modes never fall back to docker
        except SplunkError as exc:
            raise RuntimeError(f"splunk configuration invalid ({exc.stage}/{exc.code})") from None
    if client is not None:
        from agentsec.splunk_client import SplunkError
        try:
            return client.export_rows(spl, timeout_s=90, max_rows=500)
        except SplunkError as exc:
            raise RuntimeError(f"splunk search failed ({exc.stage}/{exc.code})") from None
    from agentsec import spl_policy
    try:
        spl = spl_policy.checked(spl, backend="docker-exec")          # admin-credential path: same read-only policy as REST
    except spl_policy.SplPolicyViolation as exc:
        raise RuntimeError(f"splunk search refused by the read-only policy ({exc.code})") from None
    inner = "/opt/splunk/bin/splunk search " + json.dumps(" ".join(spl.split())) + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv -maxout 500'
    proc = (runner or subprocess.run)(["docker", "exec", "-u", "splunk", container, "bash", "-lc", inner],
                                       capture_output=True, text=True, check=False, timeout=90)
    if proc.returncode != 0:
        raise RuntimeError(f"splunk search failed rc={proc.returncode}")
    text = proc.stdout.strip()
    return list(csv.DictReader(io.StringIO(text))) if text else []


def indexed_view(run_id: str, **kw) -> dict:
    if not UUID.match(run_id):
        raise ValueError("run_id must be a lowercase UUID")
    base = BASE.format(run=run_id)
    totals = run_spl(base + " | stats count AS events dc(agentsec.sequence) AS distinct_sequences dc(span_id) AS spans", **kw)
    # agentsec.sequence / event.name come back multivalue (indexed JSON extraction + search-time extraction), so
    # dedupe each to one value per event before comparing; counting values instead of events would double them.
    seqs = run_spl(base + """ | eval seq=mvindex(mvdedup('agentsec.sequence'),0), ev=mvindex(mvdedup('event.name'),0)
                           | table seq ev | sort 0 num(seq)""", **kw)
    mv = run_spl(base + """ | eval mv=if(mvcount('agentsec.sequence')>1,1,0) | stats sum(mv) AS events_with_multivalue_sequence""", **kw)
    # What a careless search would report: expanding the multivalue invariant list multiplies the row count.
    inflated = run_spl(base + " | stats count(agentsec.sequence) AS rows", **kw)
    t = totals[0] if totals else {}
    return {
        "events": int(t.get("events") or 0), "distinct_sequences": int(t.get("distinct_sequences") or 0),
        "sequences": [int(r["seq"]) for r in seqs if r.get("seq")],
        "by_event": dict(Counter(r["ev"] for r in seqs if r.get("ev"))),
        "events_with_multivalue_sequence": int((mv[0].get("events_with_multivalue_sequence") if mv else 0) or 0),
        "naive_value_count": int(inflated[0]["rows"]) if inflated and inflated[0].get("rows") else 0,
    }


def reconcile(local_events: list[dict], indexed: dict) -> dict:
    local_seq = sorted(int(e["agentsec.sequence"]) for e in local_events)
    local_by = dict(Counter(e["event.name"] for e in local_events))
    problems = []
    if indexed["events"] != len(local_events):
        problems.append(f"count_mismatch local={len(local_events)} indexed={indexed['events']}")
    if indexed["events"] != indexed["distinct_sequences"]:
        problems.append("duplicate_events_indexed")
    if sorted(indexed["sequences"]) != local_seq:
        problems.append("sequence_set_mismatch")
    if indexed["by_event"] != local_by:
        problems.append("per_event_name_mismatch")
    return {"reconciled": not problems, "problems": problems, "local_events": len(local_events),
            "indexed_events": indexed["events"], "distinct_sequences": indexed["distinct_sequences"],
            "by_event_local": local_by, "by_event_indexed": indexed["by_event"],
            "naive_value_count": indexed["naive_value_count"],
            "events_with_multivalue_sequence": indexed.get("events_with_multivalue_sequence", 0),
            "inflation_note": "count(agentsec.sequence) counts field values and is larger than the event count because the "
                              "field is multivalue in Splunk; the reconciliation counts events and dedupes values."}


def wait_and_reconcile(run_id: str, local_events: list[dict], *, timeout_s: int = 150, **kw) -> dict:
    deadline, last = time.monotonic() + timeout_s, None
    while True:
        try:
            last = indexed_view(run_id, **kw)
        except RuntimeError as exc:
            last = {"events": 0, "distinct_sequences": 0, "sequences": [], "by_event": {}, "naive_value_count": 0,
                    "error": str(exc)}
        if last["events"] >= len(local_events) or time.monotonic() > deadline:
            break
        time.sleep(5)
    out = reconcile(local_events, last)
    out["run_id"] = run_id
    out["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["method"] = "host docker-exec splunk search (read-only)" if os.environ.get("AGENTSEC_SPLUNK_MODE", "BUNDLED").upper() == "BUNDLED" else "strict-TLS Splunk REST search (read-only, search-only token)"
    if "error" in last:
        out["error"] = last["error"]
    return out
