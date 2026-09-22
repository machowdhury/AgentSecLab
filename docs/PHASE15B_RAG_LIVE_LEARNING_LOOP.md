# Phase 15B — migrate RAG / context security into the AgentSec LIVE purple-team loop

**Date:** 2026-09-19  
**Mode:** IMPLEMENTATION + VALIDATION  
**Schema:** **1.9.0** unchanged. No DET-RAG. Runtime authorization **UNCHANGED**.  
**Do not start Phase 15C from this file.** Do not migrate Memory, Goal Integrity, or Identity. Do not add vector DBs, LangChain, MLTK, or a RAG detector.

Predecessor: Phase 15A PASS (DESIGN). Locked 14E reference labs: `LAB-PI-001`, `LAB-MCP-001`. This phase migrates **existing** `LAB-RAG-CONTEXT` only.

## Security property (unchanged)

Can retrieved content cause an agent to acquire or exercise authority that server-owned policy did not grant?

**Defended answer: NO.**

Retrieved content may influence reasoning and may cause a REQUEST. It cannot independently mint tools, scopes, resources, identity, delegation, approvals, profiles, or authorization configuration.

Teaching statements:

- RETRIEVED CONTENT = DATA
- REQUEST != GRANT
- OBSERVE != ALLOW
- ALLOW != EXECUTION
- SPLUNK != ENFORCEMENT

CTRL-RAG-CONTEXT-001 remains an **OBSERVATION** control (`retrieved_context_is_data`). CTRL-MCP-001 remains the tool PDP.

## What 15B implemented

The Phase 14 ExperimentDefinition / ExperimentContext / LaunchCatalog / Search-handoff / Path A-B Studio pattern now has a third runtime route: `POST /rag/retrieve`.

| Mode | Specimen | Document | Profile | Expected follow-on |
|------|----------|----------|---------|--------------------|
| BASELINE | RAG-BASELINE | `doc.lending-policy.normal` | defended | no privileged follow-on |
| ATTACK | RAG-001 | `doc.lending-policy.malicious` | vulnerable | ALLOW `vulnerable_profile_fail_open:retrieved_context_derived_authority`; handler 1 |
| RETEST | RAG-001 | **same malicious bytes** | defended | DENY `tool_not_granted`; handler 0 |

Fingerprint is `content.hash` of the document bytes, not the hop-1 MCP request hash.

ATTACK and RETEST are independent, concurrency-safe experiments. Process env is not mutated. Coded `allowed_tools` stays `{lookup_policy}`.

## LIVE vs REPLAY

**LIVE:** Attack Service `POST /api/launch` mints a fresh `run.id`. The learner copies it and hunts in Splunk Search.

**REPLAY:** Canonical Phase 10C specimens remain the Studio Investigate specimen dropdown:

- BASELINE `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`
- ATTACK `3a43d24f-9281-42f6-8375-1fb2efaa80ac`
- RETEST `bea97bae-491b-4b36-b52f-1417d2bad01b`

Never relabel those ids as a fresh LIVE launch.

Official LIVE pair (MEASURED, not the REPLAY dropdown):

- ATTACK `41b1dbf5-f1b6-4cbc-8758-dac83633c89a` (10=10)
- RETEST `403319da-8a8a-4064-97ce-aa1b4234eb1f` (9=9)
- fingerprint `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`

## Evidence readiness

Launch returns `WAITING_FOR_EVIDENCE`. HEC HTTP 200 is not searchable. Timeout is not attack failure. Missing Splunk rows are not prevention. If the in-container Splunk probe limitation still exists, it is documented rather than faked.

## Detection

**DETECTION ANALYZED — NO NEW RAG DETECTOR.** DET-MCP-001 is unchanged (DENY-then-start). LIVE RAG ATTACK is ALLOW, so DET-MCP-001 is 0. RETEST DENYs and does not start, so DET-MCP-001 is 0. `0 rows != SAFE`.

## Limitations

- Exact-id fixture retriever. Not a vector database.
- Overlay fail-open is a labeled lab artifact, not a production grant.
- One RETEST is not universal RAG resistance.
- Learning metadata is not policy.
- Studio tokens are not auto-bound to a fresh LIVE `run.id`.
- Missing `mcp.started` is corroborative only. Runtime handler count is authoritative.

## Stop

Phase 15B stops here. Do not start Memory LIVE migration, Goal Integrity LIVE, Identity LIVE, MLTK, or Phase 15C from this file.
