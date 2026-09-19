# LAB-MEMORY-001 Persistent-memory investigation

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.7.0  
**Invariant:** INV-003 (Untrusted memory cannot silently become trusted instruction)  
**Supporting:** INV-002 (content may influence a request but cannot independently create authority)  
**Attack:** MEMORY-001 (malicious persisted memory used as memory-derived authority on a later run)  
**Control:** CTRL-MEMORY-CONTEXT-001 (classify only; OBSERVE) + CTRL-MCP-001 (follow-on tool grant)  
**Status:** Phase 11E Dashboard Studio workshop (`ws_lab_memory_security`). DET-MCP-001 reused, disabled. **No DET-MEMORY.** Detection: **DETECTION ANALYZED — NO NEW MEMORY DETECTOR**.

This lab teaches one idea: **persisted memory is data that survives into a later run**. Recalled text may influence a REQUEST. It does not become a GRANT. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a follow-on tool.

LAB-RAG-CONTEXT asked: **Can retrieved knowledge-base content independently authorize a privileged tool?**  
LAB-MEMORY-001 asks: **Can persisted agent memory independently authorize a privileged tool on a later run?**

PERSISTED MEMORY != TRUSTED INSTRUCTION  
MEMORY RECALL != AUTHORIZATION  
REQUEST != GRANT  
OBSERVE != ALLOW  
ALLOW != EXECUTION  
DENY != INDEPENDENT PROOF OF PREVENTION  
MISSING SPLUNK EVENT != BLOCKED  
ANOMALY != INCIDENT  
SPLUNK != ENFORCEMENT  
ML != AUTHORIZATION

## Learner objectives

After this lab you should be able to:

1. Reconstruct WRITE RUN → store → later RECALL RUN → classify → request → authorize → execute as five evidence planes.
2. Treat write `run.id` and recall `run.id` as different identities linked by `source_run_id`.
3. Treat provenance as source identity, not trust.
4. Explain why `untrusted_data` is classification, not malice.
5. Explain why ATTACK follow-on ALLOW is a labeled lab overlay, not a server grant.
6. Explain why RETEST DENYs the same follow-on against the same memory hash.
7. Treat runtime handler count as authoritative non-execution proof.
8. Treat missing Splunk `mcp.started` as corroboration only.
9. Explain why DET-MCP-001 is empty on BASELINE, ATTACK, and RETEST — correctly, and not SAFE.
10. Name the telemetry gaps that block a stronger memory detector (`allowed_tools`, tenant, writer≠reader).

## Prerequisite knowledge

- LAB-PI-001 (`ws_lab_pi_001`)
- LAB-MCP-001 / 005 workshops
- LAB-RAG-CONTEXT (`ws_lab_rag_context`) — contrast, not a copy
- Phase 11B runtime (`docs/PHASE11B_MEMORY_RUNTIME_VALIDATION.md`)
- Phase 11C Splunk (`docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`)
- Phase 11D analysis (`docs/PHASE11D_MEMORY_DETECTION_ANALYSIS.md`)

Not required: embeddings, LangChain, vector DB, A2A, rug-pull, identity chapter.

## Lab architecture

```text
WRITE RUN
 → MEMORY STORE
 → LATER RECALL RUN
 → CTRL-MEMORY-CONTEXT-001 OBSERVE (memory_context_is_data)
 → AGENT MAY FORM REQUEST
 → CTRL-MCP-001
 → HANDLER (only if granted)
 → OTel
 → Splunk (observe only)
```

## Validated LIVE specimens (Phase 11C)

Do **not** use Phase 11B local IDs.

- BASELINE WRITE `a8407246-7992-4ad8-bd02-cb701e150f30` / RECALL `914c41ce-5123-49eb-892c-c948295dbc46` — NORMAL, OBSERVE, no follow-on, handler 0
- ATTACK WRITE `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / RECALL `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` — MALICIOUS, overlay ALLOW, handler 1
- RETEST WRITE `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / RECALL `5d5b9d1b-092d-4ddb-8422-4092d289cd49` — **same MALICIOUS hash**, DENY `tool_not_granted`, handler 0

MALICIOUS hash (ATTACK = RETEST): `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`

NORMAL hash: `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`

memory.id ATTACK=RETEST: `mem.lending-preference.malicious`

## How to run the workshop

Open Splunk → AgentSec → **LAB-MEMORY-001 Persistent-memory investigation**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

Hunt write + Hunt recall default to the BASELINE pair. Q-MCP tables bind the **recall** run.

## Files

| File | Role |
|------|------|
| `README.md` | This overview |
| `workshop.md` | Ten-stage flow |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.md` | How to use `ws_lab_memory_security` |
| `dashboard.definition.json` | Studio source |
| `searches/Q-MEMORY-CONTEXT-AUTHORITY.spl` | Primary hunt (11C) |

Rebuild: `python3 scripts/build_lab_memory_security_dashboard.py`

No DET-MEMORY. Phase 12 not started. No A2A. No rug-pull. No vector memory.
