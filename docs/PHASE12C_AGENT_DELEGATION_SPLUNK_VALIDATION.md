# Phase 12C — Agent identity / delegation live Splunk validation

**Date:** 2026-09-18  
**Schema:** `agentsec.security_event` **1.8.0**  
**Lab:** LAB-AGENT-DELEGATION-001 / A2A-001  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; existing Q-MCP revalidation; one hunt `Q-AGENT-DELEGATION-AUTHORITY`; DET-MCP-001 compatibility; detection analysis without implementing a detector. **No Dashboard Studio.** **No DET-A2A / DET-DELEGATION.** **No live A2A transport.** Runtime, authorization architecture, and schema **unchanged** in this phase (12B runtime reused).

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. DET-MCP-001 0-row check: **MEASURED** on these run IDs (not a SIMULATED positive control). Phase 12B local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

Companion: `docs/AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md`, `docs/AGENT_DELEGATION_SEARCH_CONTRACT.md`, `docs/reviews/splunk-ko-review-agent-delegation-2026-09-18.md`.

**Phase 12D not started.**

---

## Schema 1.8.0 SPL compatibility

Inspected all `learning/level_1/LAB-MCP-001/searches/Q-MCP-*.spl` and `DET-MCP-001.spl`.

**None** hardcode `schema.version`. Searches filter `index`, `sourcetype`, `agentsec.run.id`, and `event.name`. Indexed events on these specimens are **1.8.0**. Existing Q-MCP files were **not rewritten**. DET-MCP-001 was **not modified**. Q-MCP-DELEGATION was **not rewritten** (NOT APPLICABLE; zero rows).

---

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | container `agentsec_splunk` |
| Execution | `splunk search` CLI as user `splunk`, `-output csv` |
| Auth | password stays inside the container (`admin:${SPLUNK_PASSWORD}`). Not passed on the host argv. |
| Lab | `lab-ready.sh` READY after HEC HTTP restore (`enableSSL=0`) |

Specimens ran with OTEL on (`scripts/run_lab_agent_delegation_live_specimens.py`) against the published collector `http://127.0.0.1:4318/v1/logs`. `OTEL_SERVICE_NAME=acmebank`. The running AcmeBank image was still schema **1.7.0**; host Python used the 1.8.0 identity runtime so the telemetry path remained **runtime → OTLP → collector → HEC → Splunk**. Profile switched in-process (`AGENTSEC_SECURITY_PROFILE`). `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI. Do **not** rewrite `splunk.verified` because CLI succeeded.

Official Splunk Agent Skills consulted (read-only, after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search (CLI execution path), Search Performance Optimizer (notes only; no rewrite), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings are in the hunt `.md`. AgentSec evidence semantics remain authoritative.

---

## Fresh live run IDs

Do not reuse Phase 12B local-only IDs (`c4001dd2-…`, `e5d76432-…`, `73f10e49-…`).

| Spec | Profile | Mode | Request | Identity | MCP | Runtime `lookup_policy` | Runtime `lookup_customer_tier` | `run.id` |
|------|---------|------|---------|----------|-----|------------------------:|-------------------------------:|----------|
| **A BASELINE** | defended | BASELINE | `lookup_policy` / `policy:read` / `lending-basics` | OBSERVE | ALLOW `tool_granted` | **1** | **0** | `b419465c-84d8-4639-8449-34dd99841ba9` |
| **B ATTACK** | vulnerable | ATTACK | `lookup_customer_tier` / `customer:read` / `cust-001` | OBSERVE | ALLOW overlay reason | **0** | **1** | `f846be88-1f9d-4dde-ac80-193c01b47660` |
| **C RETEST** | defended | RETEST | **same adversarial request as B** | OBSERVE | DENY `tool_not_granted` | **0** | **0** | `271695f5-4739-44f2-8bf4-0749d04f4b03` |

Principal `applicant-web`. Caller `acme-agent-advisor-005`. Callee `acme-agent-fulfillment-006`. Workflow `identity_delegation_lab` / `/identity/delegate`. Attack id `A2A-001`. Schema **1.8.0**. Coded server-owned tools remain `{lookup_policy}`.

ATTACK/RETEST identity claim hash (CTRL-IDENTITY-001 `agentsec.content.hash`): `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`. BASELINE: `sha256:93f1e257a7d6c7660aa8b1d1b980f1509b7da69e215b385ac79c222e1058b3eb`.

Do **not** summarize A as SAFE / AUTHENTICATED / TRUSTED / APPROVED. Zero suspicious follow-on is an observation, not proof of safety. OBSERVE is classification, not a grant.

B is an **INTENTIONALLY VULNERABLE LAB PROFILE**. The identity claim did not authorize the tool. CTRL-MCP-001 overlay did.

Teaching: **SAME DELEGATION REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

---

## Transport completeness

| Layer | Status | Class |
|-------|--------|--------|
| Runtime (host 1.8.0 identity pipeline, OTLP on) | Decisions and handler counts as table above | OBSERVED in specimen JSON / `manifest.json` |
| Local `events.jsonl` | A 10; B 10; C 9 | MEASURED |
| OTLP SDK | `otlp.ok=true` all three packs | OBSERVED in `export.json` |
| HEC → index | `lab-ready.sh` READY; HEC health HTTP 200 | OBSERVED |
| Splunk `dc(_raw)` | equals local unique event count for every run.id | MEASURED |

| Spec | Local | Splunk `dc(_raw)` | `stats count` | Difference | Terminal | Class |
|------|------:|------------------:|--------------:|-----------:|----------|--------|
| A BASELINE | 10 | 10 | 10 | **0** | `run_completed` | **COMPLETE** |
| B ATTACK | 10 | 10 | 10 | **0** | `run_completed` | **COMPLETE** |
| C RETEST | 9 | 9 | 9 | **0** | `run_completed` | **COMPLETE** |

`stats count` is **not** used as completeness proof (Phase 2C.1 multivalue duplication). On these three runs `stats count` happened to equal `dc(_raw)`. Event-name sequences in Splunk matched local `events.jsonl` (including B `mcp.started` then `mcp.completed`, and C `pipeline.stopped` with **no** `mcp.started`). Missing hop-1 `mcp.started` on C is **not** inferred solely from Splunk; local `lookup_customer_tier` handler count is **0**.

---

## Duplicate extraction finding

Phase 2C.1 / 3C–11C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local count.

On ATTACK IDENTITY-001: `mvcount('agentsec.run.id')=3`, `mvcount('event.name')=3`, `mvcount('service.name')=3`, `mvcount('gen_ai.agent.id')=3`, `mvcount('agentsec.control.decision')=3`, `mvcount('agentsec.identity.caller_agent_id')=2`, `mvcount('agentsec.identity.claim.trust')=2`.

Normalize with `mvindex(mvdedup('field'),0)`. **Do not change `props.conf`.**

---

## Field discovery (actual indexed names)

Verified on live A/B/C. Conceptual names that exist **do** appear as expected. See `docs/AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md`. No eval aliases were invented to hide a name mismatch. Schema 1.8.0 identity field names **match** indexed names.

| Conceptual | Indexed name | Status |
|------------|--------------|--------|
| schema version | `agentsec.schema.version` | OBSERVED **1.8.0** |
| run identity | `agentsec.run.id` | OBSERVED |
| sequence | `agentsec.sequence` | OBSERVED |
| event name | `event.name` | OBSERVED (not `agentsec.event.name`) |
| service | `service.name` | OBSERVED `acmebank` |
| principal | `agentsec.principal.id` | OBSERVED `applicant-web` |
| caller Agent A | `agentsec.identity.caller_agent_id` | OBSERVED `acme-agent-advisor-005` |
| callee Agent B | `agentsec.identity.callee_agent_id` | OBSERVED `acme-agent-fulfillment-006` |
| claim trust | `agentsec.identity.claim.trust` | OBSERVED `untrusted_claim` on CTRL-IDENTITY-001; **NOT APPLICABLE** on hop-1 CTRL-MCP-001 |
| claimed scope | `agentsec.delegation.claimed_scope` | OBSERVED |
| prior hop / delegator | `agentsec.delegator.agent.id` | OBSERVED hop ≥ 1 as caller; **NOT APPLICABLE** hop 0 |
| acting agent this hop | `gen_ai.agent.id` | OBSERVED callee `acme-agent-fulfillment-006` on both hops |
| control id / type / decision / reason | `agentsec.control.*` | OBSERVED including `CTRL-IDENTITY-001` / `identity_claim_trust` / OBSERVE |
| tool | `gen_ai.tool.name` | OBSERVED |
| MCP method | `mcp.method.name` | OBSERVED `tools/call` on hop-1 CTRL-MCP-001; **empty** on IDENTITY-001 |
| requested / allowed scope | `agentsec.mcp.requested_scope` / `agentsec.mcp.allowed_scope` | OBSERVED on CTRL-MCP-001; requested also on IDENTITY-001; allowed **empty** on IDENTITY-001 |
| resource | `agentsec.mcp.resource.id` | OBSERVED BASELINE hop-1 `lending-basics`; **NOT INDEXED** on privileged ATTACK/RETEST CTRL-MCP-001 hop |
| attempted / executed / outcome | `agentsec.operation.*` | OBSERVED; booleans are Splunk strings `"true"`/`"false"`; control-event `executed` is not `mcp.started` |
| claim fingerprint | `agentsec.content.hash` on CTRL-IDENTITY-001 | OBSERVED |
| attack / workflow | `agentsec.attack.id` / `gen_ai.workflow.name` / `agentsec.workflow.entry` | OBSERVED `A2A-001` / `identity_delegation_lab` / `/identity/delegate` |

### NOT INDEXED / NOT EXTRACTED

`authenticated`, `verified_identity`, `trusted_identity`, `cryptographic_passport_valid`, `session.id`, `invocation.id`, `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agentsec.event.name`, `delegation.id`.

WHO AUTHENTICATED = **NOT PROVEN / NOT MODELED**.

---

## BASELINE Splunk result

COMPLETE. CTRL-IDENTITY-001 OBSERVE `identity_claim_is_not_grant` / `untrusted_claim`. CTRL-MCP-001 ALLOW `tool_granted`. `lookup_policy` `mcp.started` then `mcp.completed`. Runtime handler: policy 1, tier 0.

## ATTACK Splunk result

COMPLETE. CTRL-IDENTITY-001 OBSERVE. CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority`. Privileged `mcp.started` then `mcp.completed`. Runtime handler: tier 1. INTENTIONALLY VULNERABLE LAB PROFILE.

## RETEST Splunk result

COMPLETE. Same claim hash as ATTACK. CTRL-IDENTITY-001 OBSERVE. CTRL-MCP-001 DENY `tool_not_granted`. `pipeline.stopped`. Hunt `execution_observation=no_indexed_followon_execution_event`. No privileged `mcp.started` on this COMPLETE copy. Runtime handler: tier 0 (authoritative).

## Identity claim result

CTRL-IDENTITY-001 is **OBSERVE** on A/B/C. It is not ALLOW, DENY, AUTHENTICATED, VERIFIED, or TRUSTED. Indexed `claim.trust=untrusted_claim`. Empty `authenticated` / `verified_identity`.

## ATTACK / RETEST equivalence proof

**SUPPORTED** for the canonical claim: identical principal, caller, callee, requested tool, requested scope, claimed scope, and CTRL-IDENTITY-001 `content.hash`.

**PARTIALLY SUPPORTED BY TELEMETRY** for first-class resource: `agentsec.mcp.resource.id` is not indexed on the privileged control hop. Resource is inside the hashed canonical claim (`claimed_resource` in IDENTITY preview). No invented `delegation.id`. Hop-1 MCP hashes differ (different control payload) and must not be compared as the request fingerprint.

## Authority ownership / TELEMETRY GAP

Runtime `coded_policy()` / `server_owned_allowed_tools=lookup_policy` proves neither agent is coded `customer:read`. Indexed hop-1 `allowed_scope=policy:read` vs `requested_scope=customer:read` shows a **coded-scope mismatch on the callee hop**. Splunk still cannot independently prove Agent A’s grant set. Grant snapshot `allowed_tools` remains a **TELEMETRY GAP**. Do not manufacture it in SPL.

## Existing Q-MCP compatibility

| Search | Classification | Live result |
|--------|----------------|-------------|
| Q-MCP-WHO | **REUSE WITH DOCUMENTED LIMITATION** | Extra IDENTITY row (empty `mcp.method.name`). `agent` is callee, not caller-vs-callee. |
| Q-MCP-AUTHZ | **REUSE WITH DOCUMENTED LIMITATION** | IDENTITY OBSERVE + hop-1 ALLOW/DENY. No caller/callee/claim.trust columns. Control-event `executed=false` even when `mcp.started` exists. |
| Q-MCP-TOOL | **REUSE AS-IS** | A `lookup_policy` started; B `lookup_customer_tier` started; C empty. |
| Q-MCP-EXECUTED | **REUSE WITH DOCUMENTED LIMITATION** | Extra OBSERVE row grouped by tool; OBSERVE inherits hop-1 start flags on A/B. C: `no_mcp_execution_event`. |
| Q-MCP-AFTER-DENY | **REUSE AS-IS** | 0 / 0 / 0 |
| Q-MCP-DELEGATION | **NOT APPLICABLE** | 0 rows (requires CTRL-DELEGATION-001). Do not rewrite. |

## Identity / delegation security question matrix

| Q | Question | Classification |
|---|----------|----------------|
| Q1 | Who was the principal? | **SUPPORTED** (`agentsec.principal.id`) |
| Q2 | Who was caller Agent A? | **SUPPORTED** (`agentsec.identity.caller_agent_id`) |
| Q3 | Who was callee Agent B? | **SUPPORTED** (`agentsec.identity.callee_agent_id`; `gen_ai.agent.id` is also callee) |
| Q4 | What scope did the caller claim? | **SUPPORTED** (`agentsec.delegation.claimed_scope`) |
| Q5 | How was the claim classified? | **SUPPORTED** (`untrusted_claim` / OBSERVE `identity_claim_is_not_grant`) |
| Q6 | What privileged tool/scope/resource was requested? | **PARTIALLY SUPPORTED** (tool + scope OBSERVED; first-class resource **NOT INDEXED** on privileged MCP hop; hash covers canonical resource) |
| Q7 | What did CTRL-IDENTITY-001 decide? | **SUPPORTED** (OBSERVE) |
| Q8 | What did CTRL-MCP-001 decide? | **SUPPORTED** / **REDUNDANT WITH EXISTING Q-MCP** (Q-MCP-AUTHZ hop-1 row) |
| Q9 | Did execution begin? | **SUPPORTED** / **REDUNDANT WITH EXISTING Q-MCP** (Q-MCP-TOOL) |
| Q10 | Did execution complete/fail? | **SUPPORTED** / **REDUNDANT WITH EXISTING Q-MCP** (Q-MCP-EXECUTED) |
| Q11 | Same delegation request ATTACK vs RETEST? | **SUPPORTED** via identity claim hash + caller/callee/tool/scope; resource first-class **PARTIALLY SUPPORTED** |
| Q12 | Prove neither agent owned `customer:read` from indexed telemetry alone? | **REQUIRES NEW TELEMETRY** / **TELEMETRY GAP** (`allowed_tools`). Runtime proof is separate. |
| Q13 | Distinguish attribution from authentication? | **SUPPORTED** (untrusted_claim; authenticated fields NOT INDEXED; WHO AUTHENTICATED NOT MODELED) |
| Q14 | Prove Splunk did not authorize the operation? | **SUPPORTED** as investigation-plane teaching (Splunk indexes CTRL-MCP-001; Splunk is not the PDP) |

## New hunt decision

**PUBLISH ONE:** `Q-AGENT-DELEGATION-AUTHORITY`.

Justified: Q-MCP cannot table caller vs callee, claim trust, claimed scope, and identity claim hash as a single reconstruction. Multiple tiny Q-A2A searches were **REJECTED**. Q-MCP-DELEGATION was **not** reused as the identity hunt.

## DET-MCP-001 result

Measurement wrapper (published DET body unchanged) constrained to the three fresh run IDs: **0 rows**.

| Spec | Rows | Why |
|------|-----:|-----|
| A BASELINE | 0 | No DENY |
| B ATTACK | 0 | ALLOW path; no DENY before start |
| C RETEST | 0 | DENY occurred; no later `mcp.started` |

DET-MCP-001 silence is **not** SAFE. It does not detect identity claims, overlay ALLOW, or authority amplification.

## Detection analysis (no detector implemented)

| Candidate | Classification |
|-----------|----------------|
| A untrusted identity/delegation claim | **CONTEXT** (every IDENTITY hop is `untrusted_claim`) |
| B privileged delegation request | **HUNT** |
| C claimed authority neither agent owns | **TELEMETRY GAP** |
| D identity claim + CTRL-MCP-001 ALLOW | **HUNT** / **CONTEXT** (also BASELINE ALLOW) |
| E privileged delegated request + execution | **HUNT**; **LAB-ONLY SIGNAL** if keyed on overlay |
| F overlay reason string | **LAB-ONLY SIGNAL** / **REJECT** as production IOC |
| G unknown caller/callee | **CONTEXT** (lab closed ids) |
| H identity/delegation mismatch vs coded scope | **HUNT** |

**DETECTION ANALYZED — NO NEW DETECTOR.** Do not create DET-A2A or DET-DELEGATION. Phase 12D not started.

## CIM review

**CIM NOT APPLICABLE.** Identity-claim fields are AgentSec-specific. Do not map `principal.id` or agent ids to CIM Authentication, Change, Web, IDS, or Endpoint.

## Security semantics review

Verified: no published SPL/docs claim identity string = authenticated identity; claim = verified identity; authenticated = authorized; delegation = grant; requested scope = allowed scope; OBSERVE = ALLOW; ALLOW = execution; `mcp.started` = success; `mcp.failed` = prevention; DENY alone = non-execution; missing Splunk event = prevented; ATTACK label = compromise; DET-MCP-001 silence = safe; Splunk = authorization authority; lab overlay reason = production IOC; runtime policy proof = indexed Splunk proof.

## Required live proofs

A–C fresh runs reached Splunk. D completeness MATCHED. E schema 1.8.0 identity fields OBSERVED. F IDENTITY OBSERVE. G ATTACK overlay ALLOW. H ATTACK execution started. I RETEST DENY `tool_not_granted`. J RETEST handler 0. K equivalence proven to indexed extent. L Q-MCP measured. M DET-MCP-001 measured 0. N no detector. O no Studio. P no authorization/runtime/schema change.

## PHASE 12C VERDICT

**PASS — AGENT IDENTITY / DELEGATION SPLUNK VALIDATED**

LAB-AGENT-DELEGATION-001: IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED

Schema: 1.8.0  
Identity control: CTRL-IDENTITY-001 OBSERVE ONLY  
Authorization: CTRL-MCP-001 UNCHANGED  
Detection: ANALYZED — NO NEW DETECTOR  
Workshop: NOT STARTED  
A2A transport: NOT IMPLEMENTED
