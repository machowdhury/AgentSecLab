# Phase 15C — Memory security boundary review

**Invariant:** INV-003 Untrusted memory cannot silently become trusted instruction. Compose INV-002: content may influence a request but cannot independently create authority.

## Path

WRITE RUN → MEMORY STORE (persistent boundary) → LATER RECALL RUN → AGENT CONTEXT (`trust=untrusted_data`) → CTRL-MEMORY-CONTEXT-001 OBSERVE → FOLLOW-ON REQUEST → CTRL-MCP-001 → ALLOW / DENY → HANDLER → OTLP → HEC → SPLUNK.

## Trust boundary

Persisted bytes cross into a later run as **untrusted data**. Provenance (`agentsec.memory.fixture`) is source identity, not trust. Frozen MemoryRecord check/use: the object classified is the object used to form the follow-on request.

CTRL-MEMORY-CONTEXT-001 classifies. It does not grant tools.

CTRL-MCP-001 is the only tool PDP. The ATTACK overlay reason `vulnerable_profile_fail_open:memory_derived_authority` is a labeled lab fail-open on a server-owned recall ExperimentContext. It is not stored in memory. It is not coded_policy. It must not survive into RETEST.

## What the attacker controls

The closed malicious fixture bytes (catalog `mem.lending-preference.malicious`).

## What the attacker / learner does not control

profile, allowed_tools, allowed_scope, grants, policy, trust labels, arbitrary memory body via HTTP, Python, shell, SPL, environment variables.

## What ATTACK vs RETEST changes

Server-owned experiment/authorization configuration only.

## What does not change

malicious memory, `memory.id`, `content.hash`, provenance, requested tool, requested scope, Splunk search, coded grants.

## Incorrect claims (do not teach)

- Splunk prevented the attack.
- Stored memory is trusted.
- Recalled bytes authorized the tool.
- `untrusted_data` means malicious.
- No `mcp.started` means prevention by itself.
- DET-MCP-001 returned zero so the run was safe.
- Sanitize all memory and the invariant is satisfied.
- One RETEST proves memory poisoning is solved.

## Schema / detector

Schema remains 1.9.0. No new field. No DET-MEMORY. Existing ATLAS mappings unchanged. No certification claim.
