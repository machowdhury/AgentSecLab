# Splunk engineering governance 101

**Status:** Process implemented after LAB-MCP-006 workshop validation. Not a new attack lab.  
**Parents:** `docs/SPLUNK_ENGINEERING_GOVERNANCE.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

---

## WHAT IS IT?

A Cursor workflow so Splunk knowledge objects (hunts, detections, Studio data sources, app config) are designed from evidence, reviewed against official Splunk Agent Skills, and inventoried — instead of writing SPL first.

## WHY DOES IT EXIST?

AgentSec already had `/spl-validate`, Dashboard Studio rules, and `/ui-review`. Those did not classify KO type, CIM honesty, detection readiness, or official Splunk skill mapping. Future phases would otherwise skip KO review.

## HOW DOES IT WORK?

Question → evidence → indexed fields → field contract → KO design → SPL → correctness → performance → live validation → consumer. `/splunk-ko-review` emits a fixed review block. Hunts do not automatically become detections.

## WHERE DOES IT SIT IN AGENTSEC?

Process layer beside `.cursor/rules/31-spl-validation.mdc` and `.cursor/rules/32-ui-design-system.mdc`. It does not authorize MCP calls and does not change schema 1.4.0.

## WHAT IS THE TRUST BOUNDARY?

Splunk remains the investigation plane. Runtime remains the authorization plane.

## WHAT COULD AN ATTACKER CONTROL?

Not this process. An engineer could still publish a detector on a telemetry gap; the gate is meant to stop that.

## WHAT CAN GO WRONG?

- Inventing fields for a dashboard
- Treating zero rows as safe
- Creating DET-MCP-00N because the phase number exists
- Forcing CIM mappings that lie
- Mass-rewriting validated SPL for style

## WHAT TELEMETRY SHOULD EXIST?

Whatever the security question requires, **discovered on indexed events**, not assumed from schema docs alone.

## HOW WILL SPLUNK SHOW IT?

Unchanged. Governance does not add dashboards.

## WHAT CONTROL COULD CHANGE THE RESULT?

None. This is review process, not CTRL-*.

## WHAT TEST PROVES THE LOGIC?

`tests/unit/test_splunk_governance.py` checks rule/skill/inventory/discoverability files exist and contain the required gates. It does not execute SPL.

---

## What I should now be able to explain

1. Why writing SPL first is forbidden.
2. The ten field-contract questions.
3. When to record `TELEMETRY GAP — QUERY NOT DEFENSIBLE`.
4. Why a hunt is not a detection.
5. Why AgentSec fields may be CIM NOT APPLICABLE.
6. Which official Splunk skills apply to hunts vs HEC vs app packaging.
7. The dashboard gate order including `/ui-review` and `/logic-proof`.
8. Why Q-RUN/Q-DENY placeholders are not learner hunts.
9. Why this task must not rewrite Q-MCP-DELEGATION.
10. What a future phase prompt must say about splunk-ko-review.
