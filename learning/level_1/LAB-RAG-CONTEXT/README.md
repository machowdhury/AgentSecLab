# LAB-RAG-CONTEXT Retrieved-context investigation

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.9.0 (RAG context fields introduced in 1.6.0; emitters were not bumped for Phase 15B)  
**Invariant:** INV-002 (Data Cannot Grant Authority)  
**Attack:** RAG-001 (malicious retrieved document used as retrieved-context-derived authority)  
**Control:** CTRL-RAG-CONTEXT-001 (classify only; OBSERVE) + CTRL-MCP-001 (follow-on tool grant)  
**Status:** Phase 15B LIVE purple-team loop on the existing Phase 10E workshop (`ws_lab_rag_context`). DET-MCP-001 reused, disabled. **No DET-RAG.** Detection: **DETECTION ANALYZED — NO NEW RAG DETECTOR**. Canonical specimen ids below are **REPLAY**. Fresh LIVE run.ids come from Attack Service.

This lab teaches one idea: **retrieved content is data**. A document may influence a REQUEST. It does not become a GRANT. Splunk is where you hunt a copy of the telemetry. Splunk does not ALLOW or DENY a follow-on tool.

LAB-PI-001 asked: **Did untrusted user input reach the model?**  
LAB-MCP-001–004 asked: **May the agent call this tool / scope / resource?**  
LAB-MCP-005 asked: **Can a tool result alter future authority?**  
LAB-MCP-CATALOG asked: **Can tool metadata alter future authority?**  
LAB-RAG-CONTEXT asks: **Can retrieved knowledge-base content independently authorize a privileged tool?**

RETRIEVED CONTENT IS DATA  
REQUEST != GRANT  
OBSERVE != ALLOW  
MALICIOUS-LOOKING CONTENT != AUTHORIZATION BYPASS  
ALLOW != EXECUTION  
SPLUNK != ENFORCEMENT

## Learner objectives

After this lab you should be able to:

1. Reconstruct retrieve → classify → request → authorize → execute as four evidence planes.
2. Treat provenance as source identity, not trust.
3. Explain why `untrusted_data` is classification, not malice.
4. Explain why ATTACK follow-on ALLOW is a labeled lab overlay, not a server grant.
5. Explain why RETEST DENYs the same follow-on against the same document hash.
6. Treat runtime handler count as authoritative non-execution proof.
7. Treat missing Splunk `mcp.started` as corroboration only.
8. Explain why DET-MCP-001 is empty on BASELINE, ATTACK, and RETEST — correctly, and not SAFE.
9. Explain why instruction-like retrieved text is not a production detector.
10. Name the telemetry gap that blocks a stronger RAG detector (`allowed_tools`).

## Prerequisite knowledge

- LAB-PI-001 (`ws_lab_pi_001`)
- LAB-MCP-001 / 005 / catalog workshops
- Phase 10B runtime (`docs/PHASE10B_RAG_RUNTIME_VALIDATION.md`)
- Phase 10C Splunk (`docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`)
- Phase 10D analysis (`docs/PHASE10D_RAG_DETECTION_ANALYSIS.md`)

Not required: embeddings, LangChain, memory poisoning, A2A, rug-pull.

## Lab architecture

```text
USER QUESTION
 → RETRIEVER
 → DOCUMENT / CHUNK
 → AGENT CONTEXT
 → CTRL-RAG-CONTEXT-001 OBSERVE (retrieved_context_is_data)
 → AGENT MAY FORM REQUEST
 → CTRL-MCP-001
 → HANDLER (only if granted)
 → OTel
 → Splunk (observe only)
```

## Canonical REPLAY specimens (Phase 10C, still the Investigate specimen ids)

- BASELINE `51f70fb9-994e-4dd4-9b36-cac6fb1e8232` — defended, NORMAL, OBSERVE, no follow-on, handler 0
- ATTACK `3a43d24f-9281-42f6-8375-1fb2efaa80ac` — vulnerable, MALICIOUS, overlay ALLOW, handler 1
- RETEST `bea97bae-491b-4b36-b52f-1417d2bad01b` — defended, **same MALICIOUS hash**, DENY `tool_not_granted`, handler 0

MALICIOUS hash (ATTACK = RETEST): `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`

NORMAL hash: `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`

## How to run the workshop

Open Splunk → AgentSec → **LAB-RAG-CONTEXT Retrieved-context investigation**. Tabs match LEARN → PROVE. See `workshop.md` and `dashboard.md`.

## Files

| File | Role |
|------|------|
| `README.md` | This overview |
| `workshop.md` | Ten-stage flow |
| `evidence.md` | Evidence hierarchy |
| `knowledge-check.md` | Questions and answers |
| `dashboard.md` | How to use `ws_lab_rag_context` |
| `dashboard.definition.json` | Studio source |
| `searches/Q-RAG-CONTEXT-AUTHORITY.spl` | Primary hunt (10C) |

Rebuild: `python3 scripts/build_lab_rag_context_dashboard.py`

No DET-RAG. Phase 11 not started. No embeddings. No A2A. No rug-pull.
