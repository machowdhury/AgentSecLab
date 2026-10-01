# RAG purpose workshop — implementation and independent review

## Implementation

SIMULATED / REPLAYED packet. Reuses fixture id `doc.lending-policy.normal`. No vector database. View `ws_lab_purpose_authorization` avoids the reserved `*rag*` Studio filename contract.

ATTACK and RETEST: purpose `executive-decision`, relation NOT ALLOWED. ATTACK downstream use USED with packet reason `vulnerable_profile_fail_open:purpose_not_checked`. RETEST downstream use NOT USED, reason `purpose_not_allowed`. BASELINE purpose `applicant-education`, and the note says that is not a tool grant. CTRL-MCP-001 is NOT INVOKED.

Full offline suite after the view rename: 1056 passed, 3 deselected, 10.03s.

Browser and screen reader: NOT TESTED.

## Independent review

The packet does not convert retrieval into a tool ALLOW. Historical context-control search is labeled NOT A PURPOSE DECISION. `purpose_not_allowed` is absent from `authorize.py` by the workshop test. Schema and ExternalEvidence unchanged.

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured.

Verdict: GO — RAG PURPOSE WORKSHOP VALIDATED FOR THE SIMULATED PACKET.
