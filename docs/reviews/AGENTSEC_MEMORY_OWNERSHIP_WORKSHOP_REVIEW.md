# Memory ownership workshop — implementation and independent review

SIMULATED / REPLAYED. Reuses `mem.lending-preference.normal`. View `ws_lab_recall_isolation` avoids the reserved `*memory*` Studio filename.

ATTACK and RETEST reader `user-b`. ATTACK recall RETURNED, isolation CROSSED. RETEST recall ISOLATED. BASELINE reader `user-a`. CTRL-MCP-001 NOT INVOKED. Deletion and retention NOT MEASURED.

Focused contracts: 56 passed including the existing memory filename guard. Full offline suite: 1057 passed, 3 deselected, 11.19s.

## Independent review

The packet does not claim secure deletion. Cross-user recall is the same request in ATTACK and RETEST. Owner access is a different request. Schema and ExternalEvidence unchanged. `cross_user_recall_denied` is not in `authorize.py`.

BLOCKER 0. HIGH 0. MEDIUM 0. LOW 1: UI not measured.

Verdict: GO — MEMORY ISOLATION WORKSHOP VALIDATED FOR THE SIMULATED PACKET.
