"""Evidence the Academy notebook may show for LAB-MCP-001. Read-only; never a decision.

Two sources exist, and the notebook must never blur them:

* REPLAY — a committed specimen pack under
  ``learning/level_1/LAB-MCP-001/specimens/<run.id>.jsonl``. A genuine historical
  run, re-indexed verbatim into Splunk at deployment. It is a recording, not a
  new measurement.
* LIVE — the runtime event record ``<artifacts>/<run.id>/events.jsonl`` written
  by the AcmeBank runtime for a run this Attack Service launched. This view
  reads the local record; it does not prove Splunk indexed it.

Every fact below names the event (sequence, name, timestamp) it came from. A
fact with no supporting event is ``NOT MEASURED``; absence of an execution
event is ``NOT OBSERVED``, never "safe". CTRL-MCP-001 remains the only policy
decision point: this module reports what the control recorded and has no way
to influence it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

from agentsec.external_evidence.contract import EXTERNAL_CONTRACT_VERSION
from agentsec.replay_specimens import SPECIMEN_FILE_SUFFIX, specimen_dir
from agentsec.search_handoff import INDEX, SOURCETYPE, workshop_url

LAB_ID = "LAB-MCP-001"
CONTROL_ID = "CTRL-MCP-001"
RUNTIME_SCHEMA = "1.9.0"

REPLAY = "REPLAY"
LIVE = "LIVE"
SYNTHETIC = "SYNTHETIC"
UNAVAILABLE = "UNAVAILABLE"

NOT_MEASURED = "NOT MEASURED"
NOT_OBSERVED = "NOT OBSERVED"
OBSERVED = "OBSERVED"

#: The committed REPLAY specimens and the role each one plays in the workshop.
REPLAY_ROLES = {
    "163d11e2-e751-4282-9406-19b490542ed4": "BASELINE",
    "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49": "ATTACK",
    "7a1d37b5-d589-4dfd-8322-25ebd0152dbc": "RETEST",
}

RUN_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

#: A single run record larger than this is refused rather than parsed.
MAX_RECORD_BYTES = 1_000_000
MAX_EVENTS = 200

#: Fields the notebook may display. Anything else in an event stays on disk.
DISPLAY_FIELDS = (
    "timestamp",
    "agentsec.sequence",
    "event.name",
    "agentsec.run.id",
    "agentsec.testbed.mode",
    "agentsec.security.profile",
    "agentsec.execution.mode",
    "agentsec.telemetry.fidelity",
    "agentsec.schema.version",
    "agentsec.lab.id",
    "agentsec.attack.id",
    "agentsec.principal.id",
    "agentsec.workflow.entry",
    "agentsec.trust_boundary",
    "agentsec.invariant.id",
    "agentsec.operation.type",
    "agentsec.control.id",
    "agentsec.control.type",
    "agentsec.control.decision",
    "agentsec.control.reason",
    "gen_ai.tool.name",
    "mcp.method.name",
    "agentsec.mcp.requested_scope",
    "agentsec.mcp.allowed_scope",
    "agentsec.operation.attempted",
    "agentsec.operation.executed",
    "agentsec.operation.outcome",
    "agentsec.mcp.result.trust",
    "agentsec.mcp.result.provenance",
    "agentsec.duration_ms",
    "service.name",
    "trace_id",
)

LLM_EVENT_MARKERS = ("llm", "gen_ai.chat", "gen_ai.generate")


class EvidenceError(Exception):
    """A request the notebook must refuse. ``code`` is a stable error string."""

    def __init__(self, code: str, status: int, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    provenance: str
    source: str
    sha256: str
    events: tuple[dict, ...]
    role: str | None


def is_run_id(value: object) -> bool:
    return isinstance(value, str) and RUN_ID_RE.fullmatch(value) is not None


def _read_events(path: Path, run_id: str) -> tuple[tuple[dict, ...], str]:
    size = path.stat().st_size
    if size > MAX_RECORD_BYTES:
        raise EvidenceError("record_too_large", 413, f"The event record is {size} bytes; the notebook reads at most {MAX_RECORD_BYTES}.")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    events: list[dict] = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError("record_malformed", 422, f"Line {number} of the event record is not JSON.") from exc
        if not isinstance(event, dict):
            raise EvidenceError("record_malformed", 422, f"Line {number} of the event record is not an object.")
        if event.get("agentsec.run.id") != run_id:
            # Showing another run's event under this run.id would be evidence fabrication.
            raise EvidenceError("record_mismatch", 422, f"Line {number} carries a different run.id than the record name.")
        events.append(event)
        if len(events) > MAX_EVENTS:
            raise EvidenceError("record_too_large", 413, f"The record has more than {MAX_EVENTS} events.")
    events.sort(key=lambda e: (_as_int(e.get("agentsec.sequence")), str(e.get("timestamp", ""))))
    return tuple(events), digest


def _as_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 1_000_000


def replay_pack_path(run_id: str, root: Path | None = None) -> Path:
    return specimen_dir(LAB_ID, root) / f"{run_id}{SPECIMEN_FILE_SUFFIX}"


def load_run(
    run_id: object,
    *,
    artifacts_dir: Path,
    live_run_ids: frozenset[str] | set[str],
    root: Path | None = None,
) -> RunRecord:
    """Load one run the notebook is allowed to show.

    REPLAY: only the committed LAB-MCP-001 specimens. LIVE: only run.ids this
    Attack Service launched for LAB-MCP-001, including IDs recovered from the
    durable Academy LIVE index (``live_run_ids``). Any other id is refused, so
    the endpoint cannot be used to browse the artifacts tree.
    """
    if not is_run_id(run_id):
        raise EvidenceError("malformed_run_id", 400, "A run.id is a lowercase UUID.")
    assert isinstance(run_id, str)
    if run_id in REPLAY_ROLES:
        path = replay_pack_path(run_id, root)
        if not path.is_file():
            raise EvidenceError("replay_pack_missing", 404, "The committed REPLAY pack is not present in this deployment.")
        events, digest = _read_events(path, run_id)
        return RunRecord(
            run_id=run_id,
            provenance=REPLAY,
            source=f"learning/level_1/{LAB_ID}/specimens/{run_id}{SPECIMEN_FILE_SUFFIX}",
            sha256=digest,
            events=events,
            role=REPLAY_ROLES[run_id],
        )
    if run_id not in live_run_ids:
        raise EvidenceError(
            "unknown_run",
            404,
            "This Attack Service has no durable LAB-MCP-001 LIVE reference for that run.id. "
            "Splunk may still hold its evidence; use the Splunk link.",
        )
    path = artifacts_dir / run_id / "events.jsonl"
    if not path.is_file():
        raise EvidenceError(
            "live_record_missing",
            404,
            "The runtime event record for this run is not present. That is missing evidence, not a missing run.",
        )
    events, digest = _read_events(path, run_id)
    return RunRecord(
        run_id=run_id,
        provenance=LIVE,
        source=f"artifacts/{run_id}/events.jsonl",
        sha256=digest,
        events=events,
        role=None,
    )


def _citation(event: dict) -> dict:
    return {
        "sequence": event.get("agentsec.sequence"),
        "event_name": event.get("event.name"),
        "timestamp": event.get("timestamp"),
    }


def _first(events: tuple[dict, ...], name: str) -> dict | None:
    for event in events:
        if event.get("event.name") == name:
            return event
    return None


def _field(events: tuple[dict, ...], name: str) -> str | None:
    for event in events:
        value = event.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _presence(event: dict | None) -> dict:
    if event is None:
        return {"value": NOT_OBSERVED, "source": None}
    return {"value": OBSERVED, "source": _citation(event)}


def derive_facts(record: RunRecord) -> dict:
    """Facts the notebook states, each tied to the event that supports it."""
    events = record.events
    control = next(
        (
            e
            for e in events
            if e.get("event.name") == "agentsec.control.decision" and e.get("agentsec.control.id") == CONTROL_ID
        ),
        None,
    )
    started = _first(events, "agentsec.mcp.started")
    completed = _first(events, "agentsec.mcp.completed")
    stopped = _first(events, "agentsec.pipeline.stopped")
    run_completed = _first(events, "agentsec.run.completed")
    llm_events = [
        e for e in events if any(marker in str(e.get("event.name", "")).lower() for marker in LLM_EVENT_MARKERS)
    ]

    def from_control(name: str) -> dict:
        if control is None or control.get(name) in (None, ""):
            return {"value": NOT_MEASURED, "source": None}
        return {"value": str(control.get(name)), "source": _citation(control)}

    decision = from_control("agentsec.control.decision")
    reason = from_control("agentsec.control.reason")
    reason_code = reason["value"].split(":", 1)[0] if reason["value"] != NOT_MEASURED else NOT_MEASURED

    warnings: list[str] = []
    if decision["value"] == "DENY" and started is not None:
        warnings.append(
            "The control recorded DENY but an mcp.started event is also present. Do not report this run as prevented; investigate."
        )
    if decision["value"] == NOT_MEASURED:
        warnings.append("No CTRL-MCP-001 decision event is in this record. The decision is NOT MEASURED, not ALLOW.")

    timestamps = [str(e.get("timestamp")) for e in events if e.get("timestamp")]
    return {
        "run_id": record.run_id,
        "provenance": record.provenance,
        "role": record.role,
        "testbed_mode": _field(events, "agentsec.testbed.mode") or NOT_MEASURED,
        "security_profile": _field(events, "agentsec.security.profile") or NOT_MEASURED,
        "execution_mode_recorded": _field(events, "agentsec.execution.mode") or NOT_MEASURED,
        "telemetry_fidelity": _field(events, "agentsec.telemetry.fidelity") or NOT_MEASURED,
        "schema_version_recorded": _field(events, "agentsec.schema.version") or NOT_MEASURED,
        "attack_id": _field(events, "agentsec.attack.id") or NOT_MEASURED,
        "control_id": CONTROL_ID,
        "decision": decision,
        "reason": reason,
        "reason_code": reason_code,
        "requested_tool": from_control("gen_ai.tool.name"),
        "requested_scope": from_control("agentsec.mcp.requested_scope"),
        "allowed_scope": from_control("agentsec.mcp.allowed_scope"),
        "handler_started": _presence(started),
        "handler_completed": _presence(completed),
        "pipeline_stopped": _presence(stopped),
        "run_completed": _presence(run_completed),
        "llm_event_count": len(llm_events),
        "event_count": len(events),
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
        "warnings": warnings,
    }


def display_events(record: RunRecord) -> list[dict]:
    rows = []
    for event in record.events:
        rows.append({name: event[name] for name in DISPLAY_FIELDS if name in event and event[name] not in (None, "")})
    return rows


def _epoch(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def time_bounds(facts: dict, *, pad_seconds: int = 300) -> tuple[str, str]:
    """SPL earliest/latest that contain the run, so REPLAY runs are not hidden by -1h."""
    first = _epoch(facts.get("first_timestamp"))
    last = _epoch(facts.get("last_timestamp"))
    if first is None or last is None:
        return "-24h", "now"
    return str(first - pad_seconds), str(last + pad_seconds)


def pair_bounds(a: dict, b: dict) -> tuple[str, str]:
    """One window holding both runs; all time when either run has no timestamps."""
    ea, la = time_bounds(a)
    eb, lb = time_bounds(b)
    if not all(value.isdigit() for value in (ea, la, eb, lb)):
        return "0", "now"
    return str(min(int(ea), int(eb))), str(max(int(la), int(lb)))


def run_spl(run_ids: list[str], earliest: str, latest: str) -> str:
    clause = " OR ".join(f'"agentsec.run.id"="{run_id}"' for run_id in run_ids)
    if len(run_ids) > 1:
        clause = f"({clause})"
    return f"index={INDEX} sourcetype={SOURCETYPE} earliest={earliest} latest={latest} {clause}"


def splunk_search_url(spl: str, splunk_web: str) -> str:
    return f"{splunk_web.rstrip('/')}/en-US/app/search/search?{urlencode({'q': 'search ' + spl}, quote_via=quote)}"


def studio_url(record: RunRecord, splunk_web: str) -> str | None:
    base = workshop_url(LAB_ID, splunk_web=splunk_web)
    if base is None:
        return None
    token = "form.run_id" if record.provenance == REPLAY else "form.live_run_id"
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode({token: record.run_id}, quote_via=quote)}"


def splunk_links(record: RunRecord, facts: dict, splunk_web: str) -> dict:
    earliest, latest = time_bounds(facts)
    spl = run_spl([record.run_id], earliest, latest)
    return {
        "spl": spl,
        "search_url": splunk_search_url(spl, splunk_web),
        "studio_url": studio_url(record, splunk_web),
        "studio_note": (
            "Advanced and optional. The Studio workshop is not fully mouse-operable at 400% browser zoom (P1.3). "
            "The run.id prefill was observed to work on this deployment; it is not a documented Splunk guarantee."
        ),
    }


def provenance_text(record: RunRecord) -> str:
    if record.provenance == REPLAY:
        return (
            "REPLAY — a committed recording of a real historical run, re-indexed verbatim into Splunk at deployment. "
            "It is not a run you just launched and not a new measurement."
        )
    return (
        "LIVE — the runtime event record written by the AcmeBank runtime for a run this Attack Service launched. "
        "This view reads that local record; it does not prove Splunk has indexed it. Confirm in Splunk."
    )


def evidence_document(record: RunRecord, *, splunk_web: str, launch_body: dict | None = None) -> dict:
    facts = derive_facts(record)
    document = {
        "lab_id": LAB_ID,
        "run_id": record.run_id,
        "provenance": record.provenance,
        "provenance_text": provenance_text(record),
        "evidence_state": "AVAILABLE",
        "source": record.source,
        "source_sha256": record.sha256,
        "telemetry_schema_recorded": facts["schema_version_recorded"],
        "runtime_schema_expected": RUNTIME_SCHEMA,
        "external_evidence": {
            "contract_version": EXTERNAL_CONTRACT_VERSION,
            "applicable": False,
            "detail": (
                "LAB-MCP-001 evidence is runtime telemetry. It is not an ExternalEvidence "
                "finding, evaluation, inventory, or assessment record."
            ),
        },
        "facts": facts,
        "events": display_events(record),
        "splunk": splunk_links(record, facts, splunk_web),
        "not_authorization": True,
        "synthetic": False,
    }
    if record.provenance == LIVE and launch_body is not None:
        runtime = launch_body.get("runtime") if isinstance(launch_body.get("runtime"), dict) else {}
        count = runtime.get("handler_invoke_count")
        document["launch_response"] = {
            "mode": launch_body.get("mode"),
            "profile": launch_body.get("profile"),
            "runtime_handler_count": NOT_MEASURED if count is None else count,
            "note": "Reported by the runtime in the launch response; an independent source from the event record.",
        }
    return document


def _relation(a: str, b: str) -> str:
    if NOT_MEASURED in (a, b):
        return NOT_MEASURED
    return "SAME" if a == b else "DIFFERENT"


def compare_document(attack: RunRecord, retest: RunRecord, *, splunk_web: str) -> dict:
    """Side-by-side facts for two runs. States only what each record shows."""
    if attack.run_id == retest.run_id:
        raise EvidenceError("same_run", 400, "ATTACK and RETEST must be two different run.ids.")
    a = derive_facts(attack)
    r = derive_facts(retest)
    rows_spec = (
        ("Recorded mode", lambda f: f["testbed_mode"]),
        ("Security profile", lambda f: f["security_profile"]),
        ("Requested tool", lambda f: f["requested_tool"]["value"]),
        ("Requested scope", lambda f: f["requested_scope"]["value"]),
        ("Granted scope", lambda f: f["allowed_scope"]["value"]),
        ("CTRL-MCP-001 decision", lambda f: f["decision"]["value"]),
        ("Decision reason", lambda f: f["reason_code"]),
        ("Tool handler started (mcp.started)", lambda f: f["handler_started"]["value"]),
        ("Tool handler completed (mcp.completed)", lambda f: f["handler_completed"]["value"]),
        ("Pipeline stopped", lambda f: f["pipeline_stopped"]["value"]),
        ("LLM call events in record", lambda f: str(f["llm_event_count"])),
        ("Events in record", lambda f: str(f["event_count"])),
    )
    rows = []
    for label, getter in rows_spec:
        left, right = getter(a), getter(r)
        rows.append({"label": label, "attack": left, "retest": right, "relation": _relation(left, right)})

    warnings: list[str] = []
    if attack.provenance != retest.provenance:
        warnings.append("One run is LIVE and the other is REPLAY. They were not recorded as a pair; compare with care.")
    if a["testbed_mode"] not in ("ATTACK", NOT_MEASURED):
        warnings.append(f"The run in the ATTACK column recorded mode {a['testbed_mode']}.")
    if r["testbed_mode"] not in ("RETEST", NOT_MEASURED):
        warnings.append(f"The run in the RETEST column recorded mode {r['testbed_mode']}.")
    warnings.extend(f"ATTACK: {w}" for w in a["warnings"])
    warnings.extend(f"RETEST: {w}" for w in r["warnings"])

    observations = []
    for label, facts in (("ATTACK", a), ("RETEST", r)):
        decision = facts["decision"]
        if decision["source"] is not None:
            observations.append(
                f"{label}: CTRL-MCP-001 recorded {decision['value']} ({facts['reason_code']}) in event "
                f"{decision['source']['sequence']} at {decision['source']['timestamp']}."
            )
        started = facts["handler_started"]
        if started["source"] is not None:
            observations.append(
                f"{label}: agentsec.mcp.started is present (event {started['source']['sequence']}), so the tool handler started."
            )
        else:
            observations.append(f"{label}: no agentsec.mcp.started event is in the record; tool execution is NOT OBSERVED.")
        stopped = facts["pipeline_stopped"]
        if stopped["source"] is not None:
            observations.append(f"{label}: agentsec.pipeline.stopped is present (event {stopped['source']['sequence']}).")

    inferences = []
    if a["security_profile"] != r["security_profile"] and NOT_MEASURED not in (a["security_profile"], r["security_profile"]):
        inferences.append(
            f"The recorded configuration differs (profile {a['security_profile']} vs {r['security_profile']}) while the "
            "requested tool and scope are recorded as the same. The change in decision is consistent with that "
            "configuration difference. This is an inference from the records, not a measurement of cause."
        )
    inferences.append(
        "Absence of an execution event in this record means execution was not observed here. It is not proof that "
        "nothing happened anywhere else."
    )

    earliest, latest = pair_bounds(a, r)
    spl = run_spl([attack.run_id, retest.run_id], earliest, latest)
    return {
        "lab_id": LAB_ID,
        "evidence_state": "AVAILABLE",
        "synthetic": False,
        "external_evidence": {
            "contract_version": EXTERNAL_CONTRACT_VERSION,
            "applicable": False,
            "detail": "Comparison is of runtime telemetry, not ExternalEvidence records.",
        },
        "attack": {"run_id": attack.run_id, "provenance": attack.provenance, "source": attack.source},
        "retest": {"run_id": retest.run_id, "provenance": retest.provenance, "source": retest.source},
        "rows": rows,
        "observations": observations,
        "inferences": inferences,
        "warnings": warnings,
        "splunk": {"spl": spl, "search_url": splunk_search_url(spl, splunk_web)},
        "not_authorization": True,
    }


def replay_pack_inventory(root: Path | None = None) -> list[dict]:
    """Which committed packs this deployment can read, with their hashes."""
    rows = []
    for run_id, role in REPLAY_ROLES.items():
        path = replay_pack_path(run_id, root)
        if path.is_file():
            rows.append(
                {
                    "run_id": run_id,
                    "role": role,
                    "present": True,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        else:
            rows.append({"run_id": run_id, "role": role, "present": False, "sha256": None})
    return rows


__all__ = [
    "CONTROL_ID",
    "EvidenceError",
    "LAB_ID",
    "LIVE",
    "NOT_MEASURED",
    "NOT_OBSERVED",
    "OBSERVED",
    "REPLAY",
    "REPLAY_ROLES",
    "RUNTIME_SCHEMA",
    "SYNTHETIC",
    "UNAVAILABLE",
    "RunRecord",
    "compare_document",
    "derive_facts",
    "evidence_document",
    "is_run_id",
    "load_run",
    "replay_pack_inventory",
    "time_bounds",
]
