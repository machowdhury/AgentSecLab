"""C1 evidence-state contract: what a result is, and how far it has been verified.

`source` says where the evidence came from. `readiness` says whether Splunk has been
checked. They are independent: a LIVE run can be UNAVAILABLE (probe could not run), and a
REPLAY specimen can be EVIDENCE_READY. ALLOW is never execution, HEC 200 is never indexed,
and an unavailable probe is never zero rows.
"""

from __future__ import annotations

SOURCES = ("LIVE", "REPLAY", "SIMULATED", "INFERRED", "UNAVAILABLE")
READINESS = ("EVIDENCE_READY", "WAITING_FOR_EVIDENCE", "EVIDENCE_CHECK_UNAVAILABLE")
REASONS = (
    "docker_not_available", "probe_disabled", "probe_misconfigured", "tls_verification_failed",
    "probe_auth_failed", "splunk_probe_timeout", "splunk_probe_failed", "count_mismatch",
    "not_checked",
)
# Facts a learner may see rendered as LIVE only when they came from a runtime this service launched.
LIVE_ONLY_SOURCES = frozenset({"LIVE"})


class ContractError(ValueError):
    pass


def evidence_state(source: str, probe: dict | None = None) -> dict:
    """Build a C1 document from a source label and an optional readiness probe result."""
    if source not in SOURCES:
        raise ContractError(f"unknown evidence source {source!r}")
    if probe is None:
        return {"source": source, "readiness": "WAITING_FOR_EVIDENCE", "reason": "not_checked",
                "local_event_count": None, "splunk_count": None, "reconciled": False}
    readiness = probe.get("evidence_state")
    if readiness not in READINESS:
        raise ContractError(f"unknown readiness {readiness!r}")
    reconciled = bool(probe.get("completeness_ok"))
    reason = probe.get("probe_error")
    if readiness == "EVIDENCE_READY" and not reconciled:
        reason = "count_mismatch"  # searchable, but the indexed count is not the local count
    elif readiness == "EVIDENCE_READY":
        reason = None
    elif readiness == "EVIDENCE_CHECK_UNAVAILABLE" and reason not in REASONS:
        reason = "splunk_probe_failed"
    elif readiness == "WAITING_FOR_EVIDENCE":
        reason = reason if reason in REASONS else None
    doc = {"source": source, "readiness": readiness, "reason": reason,
           "local_event_count": probe.get("local_event_count"), "splunk_count": probe.get("splunk_count"),
           "reconciled": reconciled}
    validate(doc)
    return doc


def validate(doc: dict) -> None:
    """Reject documents that would let the UI overstate evidence."""
    if doc.get("source") not in SOURCES:
        raise ContractError("source")
    if doc.get("readiness") not in READINESS:
        raise ContractError("readiness")
    if doc.get("reason") is not None and doc["reason"] not in REASONS:
        raise ContractError("reason")
    if doc["readiness"] == "EVIDENCE_CHECK_UNAVAILABLE" and doc.get("splunk_count") is not None:
        raise ContractError("an unavailable probe cannot report a count")
    if doc["readiness"] == "EVIDENCE_CHECK_UNAVAILABLE" and doc.get("reconciled"):
        raise ContractError("an unavailable probe cannot be reconciled")
    if doc.get("reconciled") and doc["readiness"] != "EVIDENCE_READY":
        raise ContractError("reconciled requires EVIDENCE_READY")
    if doc.get("source") in ("SIMULATED", "INFERRED") and doc["readiness"] == "EVIDENCE_READY" and doc.get("reconciled"):
        raise ContractError("simulated or inferred evidence cannot be reconciled to Splunk")
