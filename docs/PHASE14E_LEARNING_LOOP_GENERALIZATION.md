# Phase 14E — generalize the AgentSec learning loop + LAB-MCP-001 second reference

**Date:** 2026-09-19  
**Mode:** IMPLEMENTATION + LIVE VALIDATION + UI REVIEW  
**Schema:** **1.9.0** unchanged. Runtime authorization **UNCHANGED**.  
**Do not start Phase 15 from this file.** Do not convert remaining labs automatically. Do not create DET-MCP-NEW.

Predecessor: `docs/PHASE14D_LIVE_DEFEND_RETEST_COMPARE.md` (PASS). Historical PI LIVE pair is unchanged:

- ATTACK `7eb9176a-5270-441f-a48a-cf15643e98fc`
- RETEST `397f10ac-0946-41bd-8441-b66b3b3fab28`
- fingerprint `sha256:88a1ceab989683389193e0aa5f27e7d5ba34fb64a8dd2b5f4af8e4a6caf4b5a5`

## Design analysis (written before the refactor)

PI-001 proved a learner loop, not a new authorization engine. The pieces that are actually reusable across labs:

| Object | Reuse? | Why |
|--------|--------|-----|
| LabManifest JSON | YES | Learning metadata: title, property, prediction, specimens, limitations |
| investigations.json | YES | Security-question Path A/B; `not_authorization=true` |
| ExperimentDefinition / ExperimentContext | YES | Server-owned specimen + profile + fingerprint. Not grants. |
| LaunchCatalog + closed `/api/launch` | YES | Browser sends lab/specimen/mode/execution only |
| Search handoff | YES | Fresh run.id → Splunk Search; Studio tokens stay REPLAY |
| Studio stacked Path A/B notebook | YES | Syllabus, not enforcement |
| CTRL-* / coded_policy / detectors | NO | Lab-specific security semantics |
| `/process` vs `/mcp/invoke` | NO | Different runtime routes |
| Q-LLM-* vs Q-MCP-* | NO | Different evidence questions |

Rejected as authority:

- client profile / grants / tools / scope / resource
- learning-metadata ALLOW/DENY
- Studio or Splunk as PDP
- arbitrary SPL/Python/shell proxy

`learning metadata != policy` is an invariant of this phase.

## Product model (preserved)

Studio = syllabus / guide / evidence explainer.  
Search = hands-on notebook.  
Attack Service = closed experiment launcher.  
AgentSec runtime = enforcement.  
Splunk is not enforcement.

## MCP-001 second reference (honest LIVE)

Same known-ungranted request:

- `tool=lookup_customer_tier`
- `requested_scope=customer:read`
- `arguments={customer_id: cust-001}`

ATTACK: server-owned `profile=vulnerable` → labeled fail-open ALLOW → handler starts.  
RETEST: same request bytes, `profile=defended` → DENY `tool_not_granted` → handler 0.

CTRL-MCP-001 remains the tool PDP. DET-MCP-001 is unchanged. No new hunt.

## PI-001 PROVE closure (OBSERVED)

Restaged app. PROVE at 1440 / 1280 / 1024 shows the four evidence blocks, LIVE RUN PAIR checklist, knowledge check, connect-the-concepts ladder, and **Limitations that still apply**. No HTTP 400. No overlapping panels. Chrome description clipping at 1024 is known Studio chrome (LOW). Screenshots: `docs/screenshots/lab-pi-001/pass2_prove_*.png`.

## Live MCP results (MEASURED separately from pytest)

Official 14E pair (Attack Service `POST /api/launch`, no profile/tool/scope in the body):

| Check | Class | Result |
|-------|-------|--------|
| LIVE ATTACK `bf5109de-bcc0-4ca0-9916-cf4b63e77ef4` | OBSERVED | `experiment_id=LAB-MCP-001:ATTACK`, profile=vulnerable, hop 0 ALLOW fail-open, `handler_invoke_count=1`, `mcp.started` + `mcp.completed`, 7 local events, schema 1.9.0 |
| LIVE RETEST `0cd82b2a-cefe-4fe5-86f3-4751929c3d1f` | OBSERVED | `experiment_id=LAB-MCP-001:RETEST`, profile=defended, hop 0 DENY `tool_not_granted`, `handler_invoke_count=0`, no `mcp.started`, 6 local events, schema 1.9.0 |
| Request fingerprint | MEASURED | `sha256:431e7baaa0e7206b8671e6f81613e16848ccbcaf0f16d90d0e0da4c3b3fcc70d` on launch JSON **and** both hop-0 `control.decision` events |
| ATTACK extra hash | OBSERVED | `sha256:c3387777…` on `mcp.completed` (result payload). Not the request. Equivalence is the request fingerprint, not every event hash |
| Client `tool` on launch | MEASURED | HTTP 400 `unknown_fields` |
| AcmeBank `/health` after pair | OBSERVED | `security.profile=defended`, `testbed.mode.override=null` |
| Host Splunk ATTACK | LIVE SPLUNK | `dc(_raw)=7`, schema 1.9.0 |
| Host Splunk RETEST | LIVE SPLUNK | `dc(_raw)=6`, schema 1.9.0 |
| Q-MCP-WHO / AUTHZ / EXECUTED | LIVE SPLUNK | 1 row each on both runs; ATTACK AUTHZ ALLOW fail-open; RETEST AUTHZ DENY `tool_not_granted` |
| Q-MCP-TOOL | LIVE SPLUNK | ATTACK 1 `mcp.started`; RETEST 0 rows (corroborative; runtime handler 0 is authoritative) |
| Q-MCP-AFTER-DENY | LIVE SPLUNK | 0 rows both runs (ATTACK had no DENY; RETEST had no mcp after DENY) |
| Playwright Attack Service extra pair | OBSERVED UI | `c82b0c62-…` / `6b04cf47-…` (not the official evidence pair) |

Q-MCP-AUTHZ ATTACK still shows control-event `executed=false` on ALLOW. Q-MCP-EXECUTED `has_started=1` / `execution_state=mcp.completed` is the copy of handler start. ALLOW != EXECUTION is taught, not a field bug.

Missing Splunk `mcp.started` on RETEST is **CORROBORATED** by a complete 6=6 copy. Non-execution is **SUPPORTED** by runtime `handler_invoke_count=0` / `handler.invoked=false`. Absence of a Splunk row is not independently prevention.

## Evidence classes (do not mix)

| Class | What 14E claims |
|-------|-----------------|
| OFFLINE | pytest of manifests, ExperimentContext, launch contract, Path A/B, dashboard bind |
| LOCAL runtime | Flask `/mcp/invoke` + `/api/launch` with catalog body |
| LIVE ATTACK / RETEST | restaged containers, fresh `run.id` |
| LIVE SPLUNK | independent `dc(_raw)` + reused Q-MCP hunts |
| UI / Playwright | Home, PI PROVE, MCP LEARN–PROVE, Attack Service |

HEC 200 is not EVIDENCE READY. Missing Splunk rows are not prevention.

## Verdict

**PASS.** Two materially different security domains now share the same educational architecture: Direct Prompt Injection and MCP Tool Authorization. Learning metadata is not policy. Splunk remains observability.

**Do not start Phase 15.**
