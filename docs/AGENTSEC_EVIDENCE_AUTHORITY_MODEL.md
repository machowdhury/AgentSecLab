# AgentSec evidence authority model

**Status:** Phase 17C canonical (supersedes Phase 1B `/process`-only wording in `docs/EVIDENCE_MODEL.md` for academy teaching). Schema **1.9.0**.  
**The 1B file remains a historical `/process` contract.** Do not rewrite it to pretend it always covered two-run memory or three-run capstone.

**Do not start Phase 17D from this file.**

## Hierarchy

```text
AUTHORITATIVE RUNTIME STATE
  → LOCAL RUN EVIDENCE (artifacts/<run-id>/ when complete)
  → EXPORTED TELEMETRY (OTLP / HEC — lossy)
  → SPLUNK INDEXED COPY
  → HUNT / DETECTION RESULT
```

Splunk is never the security enforcement authority.

## Who is authoritative for what

| Question | Authoritative source | Splunk role | What absence means |
|----------|----------------------|-------------|--------------------|
| Did the LLM run (PI)? | Runtime invoke / hop executed count | Corroborates `llm.started` on a complete copy | Missing `llm.*` is not prevention unless completeness is established |
| Was the input denied (PI)? | CTRL-INPUT-001 `control.decision` | Reconstructs the decision event | Missing control row is not DENY |
| Was the tool granted? | CTRL-MCP-001 decision | Reconstructs AUTHZ | Missing AUTHZ is not DENY |
| Did the handler run? | Runtime `handler_invoke_count` | Corroborates `mcp.started` on a complete copy | Missing `mcp.started` is not independent non-execution |
| Was retrieved content data? | CTRL-RAG-CONTEXT-001 OBSERVE | Reconstructs classifier output | OBSERVE is not ALLOW |
| Was recalled memory data? | CTRL-MEMORY-CONTEXT-001 OBSERVE at recall | Reconstructs classifier; needs write+recall ids | Write-run `memory.trust` is empty by design |
| Was the proposed goal accepted? | CTRL-GOAL-INTEGRITY-001 | Reconstructs goal decision | Goal DENY ≠ MCP DENY |
| Was the caller authenticated? | **NOT MODELED** | Cannot prove authentication | OBSERVE ≠ authenticated |
| Is evidence searchable? | Splunk `dc(_raw)` vs local event count after wait | Completeness measurement | HEC 200 is not searchable-evidence proof |
| Did DET-MCP-001 fire? | Hunt/detector on indexed DENY-then-start | Reconstructs that invariant | 0 rows ≠ SAFE |

## Attack Service vs runtime vs Splunk

| Signal | Means | Does not mean |
|--------|-------|---------------|
| HTTP 200 from launch | Request accepted by launcher | Execution, DENY, or searchable evidence |
| HEC 200 | Collector accepted a batch | Completeness or EVIDENCE READY |
| EVIDENCE READY | Searchable copy measured for that run.id | Prevention |
| WAITING_FOR_EVIDENCE | Honest default until completeness | Failure of the control |
| Studio bound table | Canonical REPLAY (or official 16B for capstone) | Fresh LIVE launch |

## Completeness

Completeness = local event count vs Splunk `dc(_raw)` for the same `run.id` (and the same sourcetype). Index presence ≠ completeness.

## Two-run and three-run labs

Memory: WRITE `run.id` ≠ RECALL `run.id`. `source_run_id` on recall points at write.  
Capstone: retrieve / write / recall are three UUIDs. There is no retrieve-to-write field; hash equality is the honest join.

## Evidence classes (do not upgrade)

MEASURED · OBSERVED · DOCUMENTED · SIMULATED · CORROBORATED · REPLAYED · NOT PROVEN · NOT MODELED · INCORRECT · PARTIALLY SUPPORTED
