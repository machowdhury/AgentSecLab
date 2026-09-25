# AgentSec learner journey (Phase 17B)

This is the academy path. It is not the only possible order and not the order the software was built.

Operator tasks (`./scripts/lab-up.sh`, container health) are **not** part of this journey.

## Roles

- **Studio** — syllabus
- **Attack Service** — closed LIVE launcher
- **AcmeBank** — enforcement
- **Splunk Search** — notebook
- **Mastery Check** — reasoning validation, not a certificate

Schema remains **1.9.0**. Learning metadata is not policy.

## Loop

ORIENT → LEARN → PREDICT → ATTACK → OBSERVE → HUNT → DEFEND → RETEST → COMPARE → PROVE → CONNECT → MASTERY

Before each important action the product should already have answered WHY, WHAT AM I TESTING, and WHAT DO I EXPECT.

## Persona routes

**A — security beginner.** Home START → ORIENT → SPLUNK bootcamp → Direct Prompt Injection. Stay on Path A. Open Path B only after trying Search.

**B — SOC / Splunk practitioner.** Home START → SPLUNK (confirm index/sourcetype) → Tool Authorization or skip PI if input inspection is already familiar — but still do PI once so CTRL-INPUT-001 is not confused with CTRL-MCP-001.

**C — AI / security engineer.** Home START skip line → lab ATTACK → copy run.id → Search → control vs execution → COMPARE → PROVE. Do not skip RETEST. Mastery Check after Capstone.

## Journey 1 — Direct Prompt Injection (first LIVE lab)

Home → LEARN (untrusted input, CTRL-INPUT-001 before Ollama) → PREDICT hop 0 ALLOW vs DENY → Attack Service WHY then launch → copy run.id → wait EVIDENCE READY → Search Path A (`index=agentsec_telemetry sourcetype=otel:agentic:json` + quoted `agentsec.run.id`) → interpret ALLOW ≠ execution → DEFEND (server-owned profile) → LIVE RETEST → COMPARE same fingerprint → PROVE → CONNECT to tool authorization.

## Journey 2 — Tool Authorization

Different property: REQUEST != GRANT. CTRL-MCP-001 is the tool PDP. Input inspection is not this lab. ALLOW ≠ execution. Hunt mcp.started separately.

## Journey 3 — RAG / Retrieved Context

Retrieved content is data. Provenance != trust. CTRL-RAG-CONTEXT-001 OBSERVE != authorization. CTRL-MCP-001 remains the PDP.

## Journey 4 — Persistent Memory (two run.ids)

WRITE persists bytes. RECALL is a later run. `source_run_id` is the writer. Hunt authorization and execution on the RECALL run.id. Same fingerprint proves the same bytes. Memory is not RAG.

## Journey 5 — External Security Evidence (REPLAY)

Scanner + Runtime Evidence teaches static Cisco catalog findings and the
description-hash relationship. External Security Toolbox then introduces garak
adversarial model evaluation and the identity tuple. The learner runs the
multi-plane SPL, challenges what each result establishes, and completes a
bounded threat model. Neither external source influences CTRL-MCP-001.

This path is:

```text
Academy Home
→ Scanner + Runtime Evidence
→ External Security Toolbox
→ Splunk investigation
→ knowledge check
→ return to Home / continue to Agent Intent
```

No completion state is persisted. A curriculum row is learning metadata, not
proof that either upstream tool ran.

## Journey 6 — Goal / Instruction Integrity

AUTHORIZED TOOL != AUTHORIZED GOAL. CTRL-MCP-001 ALLOW on ATTACK **and** RETEST does not mean both goals were authorized. Hop 0 is goal integrity; hop 1 is the tool grant.

## Journey 7 — Identity / Delegation

IDENTITY CLAIM != AUTHENTICATION. CALLER ID != GRANT. WHO AUTHENTICATED is not modeled. No OAuth, OIDC, JWT, or SPIFFE in this lab.

## Capstone

Synthesis, reduced scaffolding. Multiple influence planes (retrieve → write → later recall → request). Authority still requires CTRL-MCP-001. Then Mastery Check.

## Mastery Check

FOUNDATIONAL (no Search required on NONE cards) → PRACTITIONER → INVESTIGATOR → ADVANCED → PURPLE TEAM. Not a score. Not a new control.

## Unstated knowledge that 17B removed

Repository paths, phase numbers as curriculum, pytest as proof, artifacts directory as the next click, LAB-* lists in CONNECT, LIVE EVIDENCE headers on REPLAY workshops.
