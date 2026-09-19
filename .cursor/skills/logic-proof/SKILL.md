---
name: logic-proof
description: Prove that AgentSec security logic behaves correctly and fails safely.
disable-model-invocation: true
---

# Logic Proof

Do not implement new features.

For the target implementation identify:

SECURITY PROPERTY

ASSUMPTIONS

ATTACKER-CONTROLLED INPUT

TRUST BOUNDARY

CODE PATH

DECISION POINTS

DANGEROUS OPERATION

WHERE VALIDATION OCCURS

FAILURE PATH

FAIL-OPEN POSSIBILITY

TELEMETRY

UNIT TEST

NEGATIVE TEST

INTEGRATION TEST

BYPASS TEST

Answer:

Could the dangerous operation happen before validation?

Could missing context become ALLOW?

Could one agent silently inherit another agent's authority?

Could telemetry report DENY after the operation already happened?

Which security assertion currently lacks a test?

Run relevant tests.

Report actual results.

Do not modify code until the proof is complete.
