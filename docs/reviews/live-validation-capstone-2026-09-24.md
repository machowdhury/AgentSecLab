# LIVE validation — Capstone integration

**Date:** 2026-09-24  
**Lab:** `LAB-AGENTSEC-CAPSTONE-001`  
**Schema:** 1.9.0 unchanged  
**Evidence:** MEASURED fresh local LIVE runtime and Splunk search

## ATTACK

- RETRIEVE run: `98c160d8-e54e-4af4-962f-fc48dcb194a0`
- WRITE run: `f75a7e0c-beb4-4273-af96-ef120f033c01`
- Primary RECALL run: `6cf91471-96a0-4505-9e67-fca41f6af2af`
- Document: `doc.lending-policy.malicious`
- Memory: `mem.capstone.retrieved.malicious`
- Exact document-byte fingerprint: `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`
- RAG control: `CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data`
- Memory control: `CTRL-MEMORY-CONTEXT-001 OBSERVE memory_context_is_data`
- Request: `lookup_customer_tier` / `customer:read` / `cust-001`
- Tool PDP: `CTRL-MCP-001 ALLOW vulnerable_profile_fail_open:memory_derived_authority`
- Operation-specific execution: `lookup_customer_tier` handler count 1; started and completed
- Security-sensitive outcome: customer-tier access occurred

## RETEST

- RETRIEVE run: `c8e886e5-6de5-4362-ac0c-b9f6d2cca5ab`
- WRITE run: `c71fd015-bebf-4298-8f4d-918797029478`
- Primary RECALL run: `16bfb73c-0fdb-4aab-881a-99efa34fd049`
- Document, memory, fingerprint, RAG OBSERVE, memory OBSERVE, and requested operation: same as ATTACK
- Tool PDP: `CTRL-MCP-001 DENY tool_not_granted`
- Operation-specific execution: `lookup_customer_tier` handler count 0
- Security-sensitive outcome: customer-tier access did not execute

## ATTACK ↔ RETEST proof

**Identical evidence**

- malicious document ID and exact document bytes
- persisted memory ID and bytes
- exact SHA-256 fingerprint
- requested tool, scope, and resource
- RAG and memory OBSERVE decisions

**Changed server-owned security state**

- ATTACK profile `vulnerable`
- RETEST profile `defended`

**Changed control result**

- ATTACK MCP ALLOW with explicit lab fail-open reason
- RETEST MCP DENY `tool_not_granted`

**Changed execution and outcome**

- ATTACK handler 1; customer-tier access occurred
- RETEST handler 0; customer-tier access did not execute

## Multi-run correlation

- RETRIEVE, WRITE, and RECALL use distinct UUIDs.
- Each primary launch ID is its RECALL ID.
- Recall `source_run_id` equals the corresponding WRITE run ID.
- Exact content-hash equality links RETRIEVE→WRITE→RECALL.
- Schema 1.9.0 has no direct retrieve-to-write correlation field; none was invented.

## Completeness

- ATTACK RETRIEVE: local 5; Splunk `dc(_raw)` 5
- ATTACK WRITE: local 5; Splunk `dc(_raw)` 5
- ATTACK RECALL: local 11; Splunk `dc(_raw)` 11
- RETEST RETRIEVE: local 5; Splunk `dc(_raw)` 5
- RETEST WRITE: local 5; Splunk `dc(_raw)` 5
- RETEST RECALL: local 10; Splunk `dc(_raw)` 10

All six sibling comparisons matched. This is measured completeness for these run IDs, not a universal transport guarantee.

## Splunk reconstruction

Validated existing hunts returned evidence for:

- RAG influence on each RETRIEVE run
- memory WRITE→RECALL linkage and influence
- MCP request and authorization on each RECALL run
- operation-specific execution state

Goal Integrity and Identity/Delegation hunts returned zero rows across all six run IDs. This is instrumented absence in this packet, not proof those domains never fail.

Splunk corroborated emitted evidence. It did not authorize, deny, execute, or prevent the operation.

## Identity assurance

- **CLAIMED:** no Identity/Delegation claim packet is active in this experiment.
- **ESTABLISHED IN LAB:** closed fixture IDs, server-owned ExperimentContext, coded policy, control outputs, run linkage, and handler counts.
- **NOT MODELED:** cryptographic authentication, OAuth/OIDC, signed delegation, mTLS/PKI, workload identity, and production IAM.

## Limitations

- localhost educational environment
- deterministic closed fixtures
- one RETEST does not prove universal RAG/memory resistance
- runtime records initially report `WAITING_FOR_EVIDENCE`; independent search measured completeness
- HEC booleans are not used as completeness proof
- Splunk CLI warned that server certificate hostname validation is disabled in this local environment; no certificate material was committed

Reproducible machine-readable evidence:

- `docs/screenshots/lab-agentsec-capstone/capstone-integration_validation.json`
- `docs/screenshots/lab-agentsec-capstone/capstone-integration_splunk_validation.json`
