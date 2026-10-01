# HITL approval workshop — implementation

Status: implemented as one SIMULATED / REPLAYED workshop.

Baseline before this phase: `8272c03f91eb6c1e17adf3cd7d3a773f4d8f86b8`.

## What was built

- `learning/level_1/LAB-HITL-APPROVAL/evidence.packet.json`
- `learning/level_1/LAB-HITL-APPROVAL/searches/Q-APPROVAL-CONTRAST.spl`
- Studio view `ws_lab_hitl_approval`
- Curriculum checkpoint `HITL-APPROVAL` after A2A and before L8

No runtime approval service. No schema change. No ExternalEvidence change. No detector. `approval_binding_mismatch` is not in `authorize.py`.

## Semantics

ATTACK and RETEST submit `lookup_policy` / `executive-restricted` against approval `lookup_policy` / `lending-basics`. Binding is MISMATCH. ATTACK ALLOW uses the packet-only reason `vulnerable_profile_fail_open:stale_approval_accepted`. RETEST is DENY with no inferred execution. BASELINE matches and is ALLOW `tool_granted`.

Approver type is a packet label and is not schema `principal.type`.

## Tests

Focused workshop, UI shell, threat-modeling nav, and academy contract tests: 23 passed after the Path B wording change.

Full offline suite before that wording change: 1051 passed, 3 deselected, 9.79s. The wording change was regenerated and the focused contracts were rerun: 23 passed. The full suite was not rerun after the wording-only regeneration.

## Not measured

Browser layout, keyboard traversal, zoom, and screen reader: NOT TESTED for this view. Scheduled for the later UI and accessibility phases.
