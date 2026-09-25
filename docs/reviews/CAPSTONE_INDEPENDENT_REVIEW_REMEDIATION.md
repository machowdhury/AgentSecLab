# Capstone independent-review remediation

**Date:** 2026-09-24  
**Starting commit:** `d33e6609a01120a5878f699a461ae667cb06aa49`  
**Branch:** `develop`  
**Scope:** precision/correctness remediation only  
**Schema:** 1.9.0 unchanged  
**Detector:** none added  
**Independent review:** `docs/reviews/CAPSTONE_INDEPENDENT_REVIEW.md` (preserved unchanged)

## Remediation summary

The Capstone now states the implemented persistence and runtime evidence semantics precisely:

- the memory store loads fixture-equivalent bytes and hash equality verifies equality of the compared bytes
- hash equality does not prove a direct retrieve-output → persist copy
- ToolRegistry count is process-local invocation-begin evidence
- `mcp.completed` / `mcp.failed` plus hop/outcome distinguishes completion from failure
- Q-MCP-AUTHZ is event-local authorization evidence, not reconstructed execution
- `hec.ok` is transport/health state, not searchable-event completeness
- REQUEST != ALLOW != INVOKED != COMPLETED != OUTCOME

The 32 validated Capstone SPL query strings were not changed.

## Finding disposition

| Finding | Review severity | Reproduction classification | Status | Resolution |
| ------- | --------------- | --------------------------- | ------ | ---------- |
| F-01 | MEDIUM | CONFIRMED | MITIGATED | Corrected direct-copy language to fixture-equivalent persistence + canonical hash equality |
| F-02 | MEDIUM | CONFIRMED | MITIGATED | Renamed handler-count claims to ToolRegistry invocation count and exposed completion/failure separately |
| F-03 | MEDIUM | CONFIRMED | MITIGATED | Preserved correct SPL; clarified event-local `executed=false` and directed learners to execution reconstruction |
| F-04 | MEDIUM | NOT REPRODUCED | NOT REPRODUCED | Explicit answers were already in Path B, not MISSION; added layout-aware regression test |
| F-05 | LOW | CONFIRMED | RESOLVED | Replaced “official LIVE triple” with published BASELINE/ATTACK/RETEST specimen terminology |
| F-06 | LOW | CONFIRMED | RESOLVED | Retired unreproducible 47-test claim; records exact commands and counts below |
| F-07 | LOW | PARTIALLY CONFIRMED | MITIGATED | Copy controls now name Primary, Retrieve, Write, Recall, and Source IDs explicitly |
| F-08 | LOW | CONFIRMED | ACCEPTED | Classified optional Splunk Web/app-chrome failures; no workshop dependency failure |
| F-09 | LOW | PARTIALLY CONFIRMED | MITIGATED | Existing caution retained and made explicit in workbench and learning note |
| F-11 | INFORMATIONAL | NOT REPRODUCED in this run | ACCEPTED | No production TLS change; historical localhost CLI warning remains informational |

## F-01 — persistence wording

**FINDING:** Persist is fixture-equivalent bytes plus a hash check, not a direct retrieve-output copy.  
**STATUS:** MITIGATED.  
**ROOT CAUSE:** `InProcessMemoryStore.write_fixture()` loads `FIXTURES[memory_id]`; `_launch_capstone()` compares retrieve, write, and experiment hashes. Previous teaching language collapsed equality into data flow.  
**CHANGE:** Updated the workbench, Studio builder/generated view, investigations, learning note, logic proof, and validation/review wording.  
**VALIDATION:** Fresh ATTACK/RETEST retrieve, write, and recall hashes all equal `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.  
**REMAINING LIMITATION:** Schema 1.9.0 has no direct retrieve→write correlation field. Hash equality can be ambiguous across multiple identical fixtures.

## F-02 — ToolRegistry execution semantics

**FINDING:** Counter increments before the handler body.  
**STATUS:** MITIGATED.  
**ROOT CAUSE:** `ToolRegistry.call_handler()` increments `invoke_counts[name]`, then calls the handler. `mcp.started` is emitted before `server.execute()`. `mcp.completed` or `mcp.failed` is emitted after return or exception.  
**CHANGE:** Replaced “authoritative execution count” with “ToolRegistry invocation count”; added separate invocation, completion, failure, and outcome presentation. The module docstring now says invocation-begin count.  
**VALIDATION:** Fresh ATTACK: count 1, `mcp.started=true`, `mcp.completed=true`, `mcp.failed=false`, outcome success. Fresh RETEST: count 0, no start/completion/failure, outcome prevented.  
**REMAINING LIMITATION:** Count 1 alone does not prove handler completion. Count 0 is process-local evidence for the governed path, not a universal non-execution proof.

## F-03 — Q-MCP-AUTHZ semantics

**FINDING:** ATTACK ALLOW control row contains `executed=false`.  
**STATUS:** MITIGATED; SPL accepted unchanged.  
**ROOT CAUSE:** Q-MCP-AUTHZ selects `agentsec.control.decision`. Its attempted/executed fields are event-local. The authorization event precedes runtime execution.  
**CHANGE:** Studio copy now explains that Q-MCP-AUTHZ proves decision/reason/scope. Q-MCP-TOOL proves indexed start. Q-MCP-EXECUTED reconstructs start/completion/failure. Runtime JSON supplies invocation count and hop/outcome.  
**VALIDATION:** Fresh ATTACK Q-MCP-AUTHZ returned ALLOW with `executed=false`; Q-MCP-EXECUTED returned `has_started=1`, `has_completed=1`, `has_failed=0`; Q-MCP-RESULT returned the successful tier result.  
**REMAINING LIMITATION:** Learners must not interpret an event-local field as a later-event reconstruction.

## F-04 — MISSION answer leakage

**FINDING:** Review reported expected ALLOW and handler 1 in MISSION.  
**STATUS:** NOT REPRODUCED.  
**ROOT CAUSE:** Dashboard-wide text contains explicit ATTACK answers, but the layout places `viz_attack_md` in `layout_path_b`. MISSION contains `viz_predict_attack`, which asks questions without ALLOW/DENY/count answers.  
**CHANGE:** Added `test_mission_does_not_leak_capstone_answers()` to inspect only MISSION block IDs. No answer was moved from MISSION because it was not there.  
**VALIDATION:** MISSION contains none of `vulnerable_profile_fail_open`, `tool_not_granted`, handler/invocation count 1, explicit CTRL-MCP-001 ALLOW, or explicit CTRL-MCP-001 DENY.  
**REMAINING LIMITATION:** Path B intentionally contains the validated answer key.

## F-05 — specimen terminology

**FINDING:** INVESTIGATE said “official LIVE triple” while selectors defaulted to BASELINE.  
**STATUS:** RESOLVED.  
**ROOT CAUSE:** Generic notebook copy did not distinguish selected published specimens from fresh LIVE launches.  
**CHANGE:** Selectors are described as published BASELINE/ATTACK/RETEST specimen triples. Fresh LIVE IDs remain a manual Search handoff.  
**VALIDATION:** Generated dashboard and automated tests contain “published BASELINE specimen triple” and no “official LIVE triple”.

## F-06 — focused test count

**FINDING:** No reproducible command produced 47 focused tests.  
**STATUS:** RESOLVED.  
**ROOT CAUSE:** The historical summary cited an aggregate without its command.  
**CHANGE:** The 47 claim is retired. This record reports only explicit commands.  
**VALIDATION:** See Test results.

## F-07 — multi-run copy risk

**FINDING:** Generic Copy buttons made wrong-ID selection easier.  
**STATUS:** MITIGATED.  
**ROOT CAUSE:** Nearby role labels were descriptive, but button text was only “Copy”.  
**CHANGE:** Buttons now read Copy Primary Run ID, Copy Retrieve Run ID, Copy Write Run ID, Copy Recall Run ID, and Copy Source Run ID.  
**VALIDATION:** Browser clipboard test clicked all five independently and each copied the corresponding visible ID.  
**REMAINING LIMITATION:** Studio cannot receive arbitrary fresh IDs automatically. Mixing IDs remains possible if the learner ignores labels.

## F-08 — Splunk platform/app-chrome failures

**FINDING:** Three 404 console messages.  
**STATUS:** ACCEPTED.  
**ROOT CAUSE:** Splunk Web requested optional endpoints/resources:

- platform structured-data-service config: 404
- optional app chrome `agentsec/static/appLogo.png`: 404
- platform tenant info: 404

This run also observed optional platform orchestrator SPL2 capability endpoint: 502 connection refused.

**CHANGE:** No risky AgentSec workaround. This record does not call the browser console clean.  
**VALIDATION:** All four workshop tabs loaded; no JavaScript page errors; queries and workshop content remained functional.  
**REMAINING LIMITATION:** Optional Splunk Web/app-chrome resource failures remain visible in the console. No AgentSec workshop data source or view resource failed.

## F-09 — HEC semantics

**FINDING:** `hec.ok` could be mistaken for completeness.  
**STATUS:** MITIGATED.  
**ROOT CAUSE:** The HTTP response exposes per-transport health while searchable completeness is a separate measurement.  
**CHANGE:** Workbench and learning note state that HEC state is transport/health only. Completeness remains local event count vs Splunk `dc(_raw)`.  
**VALIDATION:** Both fresh launches reported `hec.ok=false`, `otlp.ok=true`; all six local/Splunk counts matched.  
**REMAINING LIMITATION:** A transport boolean never proves indexing completeness.

## F-11 — CLI hostname validation

**FINDING:** Historical local Splunk CLI hostname-validation warning.  
**STATUS:** ACCEPTED informational.  
**ROOT CAUSE:** Local development Splunk CLI configuration.  
**CHANGE:** None to TLS or production configuration.  
**VALIDATION:** Current CLI reconstruction emitted no hostname warning. No certificate/private-key material entered the diff.  
**REMAINING LIMITATION:** Historical local warning remains documented; it is not evidence of production TLS assurance.

## Execution evidence model

- **REQUESTED** — request fields identify tool, scope, and resource.
- **AUTHORIZED** — CTRL-MCP-001 returns ALLOW. DENY is an authorization result, not execution evidence.
- **INVOKED** — the process-local ToolRegistry invocation count increments and `mcp.started` may corroborate on a complete indexed copy.
- **COMPLETED** — `mcp.completed`, no `mcp.failed`, and a successful hop/outcome exist.
- **FAILED** — `mcp.failed` and error hop/outcome exist after invocation.
- **OUTCOME** — result evidence supports the application-specific security-sensitive result.

`REQUESTED != AUTHORIZED != INVOKED != COMPLETED != OUTCOME`.

## Fresh LIVE validation

### ATTACK

- RETRIEVE: `c503dae2-7dfb-4530-a30d-1374ffd655cc`
- WRITE: `74917168-382a-472e-a3a9-a853bc8483f1`
- RECALL: `e380ef26-abec-4316-8ae3-6e5fa9a264fc`
- fingerprint: `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`
- RAG OBSERVE; Memory OBSERVE
- CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:memory_derived_authority`
- ToolRegistry invocation count 1
- mcp.started true; mcp.completed true; mcp.failed false
- hop/outcome success
- Q-MCP-RESULT: `cust-001`, found, tier `standard`
- local counts 5 / 5 / 11

### RETEST

- RETRIEVE: `e641d6fc-2e2a-447c-9577-63b190355edc`
- WRITE: `ed32bfaf-a421-4cd6-ada6-790e05f2df87`
- RECALL: `fa343b9c-312e-49e2-8553-d94ccbb3601f`
- same fingerprint
- RAG OBSERVE; Memory OBSERVE
- CTRL-MCP-001 DENY `tool_not_granted`
- ToolRegistry invocation count 0
- mcp.started false; mcp.completed false; mcp.failed false
- hop/outcome prevented
- local counts 5 / 5 / 10

### Splunk reconstruction and completeness

| Run | Local | Splunk `dc(_raw)` |
| --- | ----- | ----------------- |
| ATTACK RETRIEVE | 5 | 5 |
| ATTACK WRITE | 5 | 5 |
| ATTACK RECALL | 11 | 11 |
| RETEST RETRIEVE | 5 | 5 |
| RETEST WRITE | 5 | 5 |
| RETEST RECALL | 10 | 10 |

Existing Q-RAG-CONTEXT-AUTHORITY, Q-MEMORY-CONTEXT-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-EXECUTED, and Q-MCP-RESULT reconstructed influence, request, authorization, invocation/completion, and outcome. Q-MCP-AUTHZ remained authorization-only.

## SPL preservation

Compared `dataSources.*.options.query` at `d33e6609…` against the remediated generated definition:

**32/32 Capstone SPL queries remain byte-identical.**

## Falsification result

- Direct retrieve-output → persistence proven? **NO.** Fixture-equivalent bytes + canonical hash equality only.
- ToolRegistry count alone proves successful completion? **NO.**
- ALLOW proves invocation/completion? **NO.**
- Splunk causes enforcement? **NO.**
- HEC acceptance proves completeness? **NO.**

Fresh runtime and Splunk evidence still support the controlled closed-lab result: same compared bytes/request; vulnerable ALLOW → invocation → completion → customer-tier outcome; defended DENY → no governed invocation.

## Tests

### Focused Capstone

```text
/usr/bin/time -p uv run --extra test python -m pytest \
  tests/unit/test_phase16b_capstone_learning_loop.py \
  tests/splunk/test_lab_agentsec_capstone_dashboard.py \
  -q --tb=line

21 passed in 0.48s
real 0.94
```

### Cross-domain regression

```text
/usr/bin/time -p uv run --extra test python -m pytest \
  tests/unit/test_phase15b_rag_learning_loop.py \
  tests/unit/test_phase15c_memory_learning_loop.py \
  tests/unit/test_phase15d_goal_learning_loop.py \
  tests/unit/test_phase15e_identity_learning_loop.py \
  tests/unit/test_phase16b_capstone_learning_loop.py \
  tests/unit/test_mcp_authorize.py \
  tests/splunk/test_lab_agentsec_capstone_dashboard.py \
  -q --tb=line

99 passed in 0.77s
real 1.22
```

This covers MCP authorization, RAG, Memory, Goal, Identity, and Capstone. Goal tests continue to distinguish permitted RETEST behavior from prohibited objective expansion.

### Full offline

```text
/usr/bin/time -p uv run --extra test python -m pytest tests -q --tb=line \
  -m "not live_ollama and not live_splunk"

947 passed, 2 deselected in 9.51s
real 10.00
```

No overlapping focused selections are summed into one test count.

One immediately preceding full-suite run produced `1 failed, 946 passed, 2 deselected`: the unchanged concurrent RAG isolation test observed a transient process-environment value at its final assertion. The failing test passed when reproduced alone (`1 passed in 0.39s`), and the complete suite then passed as recorded above. This is reported as intermittent test-state evidence, not hidden or represented as a deterministic Capstone failure.

## UI and accessibility validation

MEASURED with a newly started remediated Attack Service:

- HTTP 200 and no horizontal overflow at 1920, 1440, 1280, 1024
- ATTACK renders INVOKED, COMPLETED, and customer-tier outcome separately
- RETEST renders NOT INVOKED, NOT STARTED AFTER DENY, and no invoked outcome
- comparison has separate authorization, invocation, completion, and outcome rows
- Advanced opens and states the evidence hierarchy
- all five copy buttons copied the correct ID
- 200% zoom: key result remained visible and no horizontal overflow
- focus outline: solid 2px
- Attack Service console/page errors: none
- SIMULATED dependency error remained labeled ERROR / NOT PROVEN
- Studio tabs MISSION, INVESTIGATE, EVIDENCE, PATH B · ANSWERS loaded
- MISSION did not contain final ALLOW/DENY/count answers

Screen-reader readiness remains **PARTIAL**. No assistive-technology certification was performed.

## Secret and certificate hygiene

Diff scan found no API keys, tokens, passwords, private keys, certificates, cookies/session data, HEC tokens, `.env`, or credential files. No certificate was present for X.509 validation. Credentials remained outside source and were not printed.

## Evidence classification

- **MEASURED:** git baseline, query identity, pytest, fresh HTTP runs, local counts, Splunk `dc(_raw)`, browser checks.
- **OBSERVED:** optional Splunk Web/app-chrome failures, visible tab/render behavior.
- **DOCUMENTED:** implementation semantics and limitation statements.
- **SIMULATED:** browser-intercepted dependency ERROR only.
- **PARTIAL:** accessibility/screen-reader readiness.
- **NOT MODELED:** production authentication, OAuth/OIDC, signed delegation, PKI/workload identity.
- **NOT PROVEN:** direct retrieve-output copy, universal resistance, production effectiveness.

## Known limitations

- deterministic closed fixtures
- process-local ToolRegistry and memory store
- hash equality is not a direct data-flow link
- fresh IDs require manual Search handoff
- optional Splunk Web/app-chrome resource errors remain
- no production identity architecture
- screen-reader coverage PARTIAL
- one RETEST does not prove universal effectiveness

