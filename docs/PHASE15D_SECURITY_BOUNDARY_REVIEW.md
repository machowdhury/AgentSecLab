# Phase 15D — Goal Integrity security boundary review

**Invariants:** INV-002 (data cannot independently authorize) and INV-006 (privileged workflow transitions require authorized state).

## Path

SERVER-OWNED TaskContract → untrusted instruction → ProposedTaskChange → CTRL-GOAL-INTEGRITY-001 → effective action → lookup_policy request → CTRL-MCP-001 → ALLOW tool_granted → handler (in-task or wrong-goal) → OTel → HEC → Splunk.

## Trust boundary

Untrusted instructions may influence a proposal. They must not redefine the authoritative task. Tool grant and task grant are different planes.

CTRL-GOAL-INTEGRITY-001 evaluates task/goal integrity. It is not a tool PDP.

CTRL-MCP-001 is the only tool PDP. lookup_policy remains granted on BASELINE, ATTACK, and RETEST.

The ATTACK overlay reason `vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority` is a labeled lab fail-open on a server-owned ExperimentContext. It does not mutate `coded_policy()`. It does not mutate the authoritative TaskContract. It must not survive into RETEST.

MEASURED after the official LIVE pair: AcmeBank `/health` still reports `security.profile=defended` and `testbed.mode.override=null`. ATTACK did not leak profile into process env. RETEST remained defended.

`extract_full_policy` is not an MCP tool. It labels how granted `lookup_policy` is used.

## What the attacker / learner controls

The closed malicious fixture bytes (`goal.instruction.malicious`). Not profile, grants, task contract, goal decision, tools, scopes, Python, shell, SPL, or environment.

## What ATTACK vs RETEST changes

Server-owned ExperimentContext (vulnerable vs defended) and therefore the GOAL decision and effective action.

## What does not change

Task fingerprint, malicious instruction bytes, proposed extract_full_policy, lookup_policy, policy:read, lending-basics, CTRL-MCP-001 ALLOW tool_granted.

## Incorrect claims (do not teach)

- MCP ALLOW means the goal was authorized.
- Tool authorization and task authorization are the same thing.
- Goal DENY means lookup_policy was denied.
- Splunk is the enforcement point.
- MCP prevented the RETEST attack.
- Block lookup_policy / sanitize every prompt / trust a scanner / let an LLM decide authorization.
