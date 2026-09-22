# LAB-AGENTSEC-CAPSTONE-001 — Lending Assistant Investigation

Integrated capstone. Not a new security domain.

**Security question:** A lending-policy assistant accessed customer-tier information during a workflow that was expected to summarize lending policy. Determine what happened from evidence.

Do not title this lab “RAG Memory MCP Authorization Failure.” The learner discovers the chain.

## Architecture

retrieved content → CTRL-RAG-CONTEXT-001 OBSERVE → memory WRITE → later memory RECALL → CTRL-MEMORY-CONTEXT-001 OBSERVE → follow-on request → CTRL-MCP-001 → tool handler → telemetry → Splunk

CTRL-MCP-001 is the sole tool PDP. RAG does not grant. Memory does not grant. Splunk does not grant.

## Runs

Each LIVE launch mints three run.ids: RETRIEVE, WRITE, later RECALL. Correlation:

- retrieve content.hash = write content.hash = recall content.hash
- recall source_run_id = write run.id

Schema 1.9.0 is unchanged. No retrieve-to-write field was invented.

## Specimens

| Mode | Profile | Privileged handler |
|------|---------|--------------------|
| BASELINE | defended | 0 — do not label SAFE |
| ATTACK | vulnerable lab overlay | 1 |
| RETEST | defended, same adversarial bytes | 0 |

## Hunts

Reuse only. No Q-CAPSTONE. No DET-CAPSTONE.

Studio = syllabus. Search = notebook. Attack Service = launcher. Runtime = enforcement. Splunk = evidence.
