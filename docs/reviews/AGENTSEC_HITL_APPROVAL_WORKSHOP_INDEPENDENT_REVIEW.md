# HITL approval workshop — independent implementation review

Reviewed artifacts: packet, search, generated Studio definition, curriculum checkpoint, and `tests/splunk/test_hitl_approval_workshop.py`.

This review did not treat the design document's GO as proof of the implementation.

## Checks

- ATTACK and RETEST share `lookup_policy` / `executive-restricted` and binding MISMATCH.
- BASELINE submits `lending-basics` and binding MATCH.
- ATTACK ALLOW reason is the labeled teaching string and is absent from `authorize.py`.
- RETEST is DENY and tells the learner not to infer execution.
- BASELINE is ALLOW `tool_granted`.
- Approver authentication is labeled simulated. Approval authority is NOT PROVEN.
- Approver type is explicitly not schema `principal.type`.
- Approved tool and approved resource are named on the ledger.
- Schema remains 1.9.0. ExternalEvidence remains 1.0.0. `REQUIRE_APPROVAL` is absent from the schema.
- The lab is not in `known_lab_ids()`.
- Mode outcomes are on Path B. The AUTHORIZE tab states that MATCH is not ALLOW and MISMATCH is not DENY.

## Evidence classification

Packet: SIMULATED / REPLAYED. Claim strength: BOUNDED TO THE PACKET.

Historical contrast search: labels rows as historical resource decisions, not approvals. This review did not re-export Splunk. Counts: NOT MEASURED.

Browser and screen reader: NOT TESTED.

## Findings

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: browser behavior of the new view is not measured. That does not change the packet semantics and is deferred to the UI phase.

## Verdict

GO — HITL WORKSHOP VALIDATED FOR THE SIMULATED PACKET. Continue to short-lived credentials.
