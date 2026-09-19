# MCP-006 Splunk transport, SPL, and investigation validation

**Date:** 2026-09-14  
**Schema:** `agentsec.security_event` **1.4.0**  
**Lab:** LAB-MCP-006 specimens; reuse LAB-MCP-001 Q-MCP / DET-MCP-001; one new hunt `Q-MCP-DELEGATION`  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; existing Q-MCP revalidation; delegation hunt; DET-MCP-001 compatibility. **No** Dashboard Studio (`ws_lab_mcp_006`). **No** DET-MCP-006. **No** MCP-007 / A2A. Authorization model **unchanged** in this phase.

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. DET-MCP-001 positive control: **SIMULATED**. Phase 7B local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

Companion: `docs/MCP006_SPLUNK_FIELD_VALIDATION.md`, `docs/MCP006_DETECTION_VALIDATION.md`.

---

## Schema 1.4.0 SPL compatibility

Inspected all `learning/level_1/LAB-MCP-001/searches/Q-MCP-*.spl` and `DET-MCP-001.spl`.

**None** hardcode `schema.version`. Searches filter `index`, `sourcetype`, `agentsec.run.id`, and `event.name`. Indexed events on these specimens are **1.4.0**. Existing Q-MCP files were **not rewritten**.

Phase 7B bumped the schema (additive `mcp_delegation`, `CTRL-DELEGATION-001`, `MCP-006`, `delegation.authority.source`). Splunk now indexes those values. See `docs/SCHEMA_1_4_0.md`.

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
| Lab | `./scripts/lab-up.sh --build` READY; AcmeBank image rebuilt with 7B runtime (container schema **1.4.0**) |

Specimens ran in-container Python with OTEL on (`scripts/run_lab_mcp_006_live_specimens.py` copied to `/tmp`; image does not copy `scripts/`). Profile switched in-process (`AGENTSEC_SECURITY_PROFILE`) so the HTTP container stayed defended. `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI plus `artifacts/<run-id>/splunk_validation.json`.

Transport health before specimens: `lab-ready.sh` READY (AgentSec services, Splunk, HEC HTTP 200, collector-mesh HEC HTTP 200, index `agentsec_telemetry`, AgentSec app present). `otlp.ok` was not treated as Splunk success.

---

## Fresh run IDs

Do not reuse Phase 7B local-only IDs (`0eb3207d-…`, `d991e30f-…`, `874b2e37-…`).

| Spec | Profile | Mode | Runtime (authoritative) | Handlers policy / tier | `run.id` |
|------|---------|------|-------------------------|------------------------:|----------|
| **A BASELINE** | defended | BASELINE | CTRL-DELEGATION-001 ALLOW `delegation_granted` source=`delegated`; CTRL-MCP-001 ALLOW `tool_granted`; `lookup_policy` succeeds | **1 / 0** | `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` |
| **B ATTACK** | vulnerable | ATTACK | CTRL-DELEGATION-001 ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority` source=`ambient_deputy`; CTRL-MCP-001 ALLOW `tool_granted`; `lookup_customer_tier` executes | **0 / 1** | `d7524a4e-8da6-4171-8867-d2a2168128ac` |
| **C RETEST** | defended | RETEST | **same request as B**; CTRL-DELEGATION-001 DENY `delegated_authority_not_granted` source=`delegated`; no downstream MCP; handler **0** | **0 / 0** | `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` |

Canonical identities (runtime + hop-0/hop-1 indexed fields): caller `acme-agent-credit-002`, deputy `acme-agent-compliance-004`, principal `applicant-web`. Method `tools/call`. `agentsec.attack.id=MCP-006`. Schema **1.4.0**.

Trace ids: A `554769dee416de57c1f5711649fbad06`; B `a85a87e441f5e8fef72bb7f62ba5f4a1`; C `6580375e8004e80c66d248ee3124aed5`.

---

## ATTACK / RETEST request equivalence

**MEASURED** from `artifacts/<run-id>/request.json` (identical JSON):

```json
{
  "caller": "acme-agent-credit-002",
  "deputy": "acme-agent-compliance-004",
  "tool": "lookup_customer_tier",
  "requested_scope": "customer:read",
  "arguments.hash": "sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419",
  "arguments.preview": "{\"customer_id\": \"cust-001\"}"
}
```

Only profile, mode, control decision, authority source, downstream MCP, handler count, and terminal outcome differ as designed.

---

## Transport completeness

| Layer | Status | Class |
|-------|--------|--------|
| Runtime in-container invoke | Decisions and handler counts as table above | OBSERVED in specimen JSON / `manifest.json` |
| Local `events.jsonl` | 10 / 10 / 6 | MEASURED |
| OTLP SDK | `otlp.ok=true` all three packs | OBSERVED in `export.json` |
| HEC → index | `lab-ready.sh` READY; source=`agentsec-otel-collector` | OBSERVED |
| Splunk `dc(_raw)` | equals local count for every run.id | MEASURED |

| Spec | Local | Splunk | Difference | Terminal | Class |
|------|------:|-------:|-----------:|----------|--------|
| A | 10 | 10 | **0** | `completed_allowed` | **COMPLETE** |
| B | 10 | 10 | **0** | `completed_allowed` | **COMPLETE** |
| C | 6 | 6 | **0** | `completed_denied` | **COMPLETE** |

Event-by-event: local `(sequence, event.name)` equals Splunk collapsed sequence for A/B/C (**MEASURED**). C has no indexed `agentsec.mcp.started` (`dc=0`). Missing `mcp.started` on C is **not** inferred solely from Splunk; local `lookup_customer_tier` handler count is **0**.

`export.json` remains `splunk.verified=false` (runtime never sets it). Independent CLI completeness is recorded in `splunk_validation.json` and the evidence-closure table.

---

## Duplicate extraction finding

Phase 2C.1 / 3C / 4C / 5C / 6C multivalue duplication is **OBSERVED** again.

On ATTACK hop-0 CTRL-DELEGATION-001: `mvcount(agentsec.run.id)=3`, `mvcount(event.name)=3`, `mvcount(gen_ai.agent.id)=3`, `mvcount(agentsec.control.decision)=3`, `mvcount(agentsec.delegation.authority.source)=2`, `mvcount(agentsec.control.id)=2`.

Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.** Normalization reused: `mvindex(mvdedup('field'),0)`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

---

## Principal SOC question

Can Splunk show, from actual indexed evidence, that a deputy exercised authority for an operation the caller was not delegated to perform?

**Partial YES, with a documented grant-list gap.**

Indexed evidence **can** show:

- caller on hop 0 (`gen_ai.agent.id=acme-agent-credit-002`)
- deputy on hop 1 when hop 1 exists (`gen_ai.agent.id=acme-agent-compliance-004`, `agentsec.delegator.agent.id=acme-agent-credit-002`)
- requested tool/scope/resource
- CTRL-DELEGATION-001 decision + reason
- structured `agentsec.delegation.authority.source` = `delegated` vs `ambient_deputy`
- downstream CTRL-MCP-001 separate from delegation
- whether `mcp.started` / `mcp.completed` were indexed

Indexed evidence **cannot** independently prove the delegated **tool set** excluded `lookup_customer_tier`. There is no `allowed_tools` field. That membership remains runtime/manifest. `authority.source=ambient_deputy` is what the control **consulted**, not a dump of Compliance’s ambient grant.

---

## Existing Q-MCP search review

| Hunt | A | B | C | Reuse verdict |
|------|--:|--:|--:|---------------|
| Q-MCP-WHO | 2 rows (credit + compliance) | 2 rows | 1 row (credit only) | Answers who, but does **not** label caller vs deputy |
| Q-MCP-AUTHZ | 2 (DELEGATION + MCP) | 2 | 1 (DELEGATION DENY) | Answers both decisions; mixed controls |
| Q-MCP-SCOPE | 2 `granted` | 2 `known_but_ungranted` (equality, not subset) | 1 `known_but_ungranted` DENY | Do not read hop-1 ambient CSV as MCP-003 |
| Q-MCP-PARAMS | 2 | 2 | 1 | Preview/hash; not grant proof |
| Q-MCP-TOOL | 1 `mcp.started` | 1 | **0** | Zero on C is not DENY by itself |
| Q-MCP-EXECUTED | 2 (two control rows, same tool) | 2 | 1 `no_mcp_execution_event` | Execution observation; control `executed=false` is expected |
| Q-MCP-AFTER-DENY | 0 | 0 | 0 | Empty: B has no DENY; C has DENY and no later mcp.* |
| Q-MCP-RESULT / RESULT-TRUST | 1 `untrusted_data` | 1 `untrusted_data` | 0 | Classification, not authority |
| Q-MCP-RESOURCE-AUTHZ | 2 `granted` | 2 `other` | 1 `other` | Resource hunt is not the confused-deputy story |
| Q-MCP-RESULT-AUTHORITY | 0 | 0 | 0 | No RESULT-001; correctly empty |

**New hunt justified:** `Q-MCP-DELEGATION`. Existing searches cannot clearly answer authority source + caller/deputy + separate delegation vs MCP decisions in one reconstruction row.

Not created: `Q-MCP-DELEGATION-AUTHORITY`, `Q-MCP-DELEGATION-CHAIN`, `Q-MCP-DELEGATION-EXECUTED`, `Q-MCP-AMBIENT-USE` (duplicates).

---

## Q-MCP-DELEGATION live results

| Spec | caller | deputy_observation | source | delegation | MCP | execution |
|------|--------|--------------------|--------|------------|-----|-----------|
| A | credit-002 | compliance-004 | `delegated` | ALLOW `delegation_granted` | ALLOW `tool_granted` | `mcp.completed_observed` |
| B | credit-002 | compliance-004 | `ambient_deputy` | ALLOW `…:ambient_deputy_authority` | ALLOW `tool_granted` | `mcp.completed_observed` |
| C | credit-002 | `deputy_not_on_indexed_hop1` | `delegated` | DENY `delegated_authority_not_granted` | `no_downstream_mcp_control_event` | `no_indexed_mcp_execution_event` |

Three-way comparison is this hunt bound to A, then B, then C. Same caller; B/C same requested tool/scope/resource; only source, decision, MCP, and execution change.

---

## /spl-validate (Q-MCP-DELEGATION)

1. **Security question:** What did CTRL-DELEGATION-001 decide, who was caller/deputy, which authority source was used, and did downstream MCP / execution appear in the copy?
2. **Raw fields available:** listed in `Q-MCP-DELEGATION.md`; discovered on live events (see field validation).
3. **Required fields exist:** yes, except deputy on RETEST hop 1 (labeled, not invented).
4. **SPL:** `learning/level_1/LAB-MCP-006/searches/Q-MCP-DELEGATION.spl`.
5–6. **Commands:** `search` → `eval` collapse → `eventstats` by `run_id` → `where` CTRL-DELEGATION-001 present → `dedup` → `table`. Necessary to join hop 0 / hop 1 / mcp.* without `join`.
7–9. **Live output** matches expected table above (**MEASURED**).
10. **False positives:** a non-MCP-006 run with CTRL-DELEGATION-001 would appear; none exist in this lab. BASELINE legitimate delegation is a **true** ALLOW row, not an attack.
11. **False negatives:** ingest loss of hop 0; truncated fields; RETEST deputy not first-class.
12. **Performance:** index+sourcetype+run.id; no expensive commands.
13. **Simpler alternative:** Q-MCP-AUTHZ already shows two rows; it does not answer the reconstruction question.

---

## /logic-proof (evidence claims)

| Claim risk | Finding |
|------------|---------|
| Authorization inferred from execution | **Rejected.** Hunt tables delegation decision separately from `execution_observation`. ATTACK docs state execution is not caller authorization. |
| Prevention inferred solely from event absence | **Rejected.** C handler count **0** is runtime. Splunk uses `no_indexed_mcp_execution_event` on a **complete** copy. |
| Ambient authority inferred from profile alone | **Rejected.** Indexed `authority.source=ambient_deputy` on hop 0. Profile is corroboration, not the source field. |
| Caller/deputy hardcoded into narrative | **Rejected.** Caller/deputy taken from indexed `gen_ai.agent.id`. RETEST deputy not invented. |
| Reason text treated as stronger than it is | **Documented.** Prefer structured `authority.source`. Reason is a stable lab contract string, still tabulated. |
| Duplicate extraction counted as repeated decisions | **Rejected.** Completeness is `dc(_raw)`. Hunt collapses mv. |
| Splunk described as enforcement | **Rejected.** Splunk does not ALLOW or DENY. CTRL-DELEGATION-001 is runtime. |

Could the dangerous operation happen before validation? Runtime: no. Indexed C: control seq 3 DENY, no mcp.*.

Could missing context become ALLOW? Not in these specimens (canonical A/B/C).

Could one agent silently inherit another’s authority? ATTACK yes, labeled `ambient_deputy`. RETEST no.

Could telemetry report DENY after the operation already happened? C `executed=false` `outcome=prevented` on the control event; handler 0.

---

## Adversarial review

| Finding | Severity | Disposition |
|---------|----------|-------------|
| Query assuming `allowed_tools` | would be BLOCKER | Hunt documents absence; uses `authority.source` + hop-0 coded **scope** |
| Parsing preview for deputy/grants | HIGH if done | Hunt uses `deputy_not_on_indexed_hop1`; does not regex preview |
| ATTACK MCP ALLOW as caller grant | HIGH | Hunt keeps hop-0 `coded_delegated_scope=policy:read` and `authority.source=ambient_deputy` |
| No-data called prevention | HIGH | `no_indexed_mcp_execution_event` language; runtime handler count authoritative |
| Duplicate JSON inflating counts | HIGH if used for completeness | Completeness is `dc(_raw)` |
| Detector on fail-open reason only | would be HIGH | **No detector created** |
| SIMULATED fixture indexed | BLOCKER if true | `dc(_raw)=0` for `simulated-det-mcp-001-0001` |
| Q-MCP-SCOPE hop-1 ambient CSV as MCP-003 | MEDIUM | Documented equality helper, not subset |
| Q-MCP-EXECUTED two identical rows | MEDIUM | Two control events, same tool; existing hunt |
| RESOURCE-AUTHZ `other` on cust-001 vs lending-basics | MEDIUM | Not the MCP-006 predicate; existing hunt not rewritten |
| RETEST deputy not first-class | MEDIUM | Gap documented; runtime/manifest authoritative |
| Sequence / call-id gap | LOW | One operation per run; no `gen_ai.tool.call.id` |
| Dashboard Studio / MCP-007 | n/a | not started |

No remaining BLOCKER/HIGH.

---

## Evidence closure

| RUN ID | PROFILE | MODE | LOCAL | SPLUNK | CALLER | DEPUTY (indexed) | SOURCE | DELEGATION | MCP | HANDLER | TERMINAL | SPLUNK VERIFIED |
|--------|---------|------|------:|-------:|--------|------------------|--------|------------|-----|--------:|----------|-----------------|
| `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` | defended | BASELINE | 10 | 10 | credit-002 | compliance-004 (hop 1) | `delegated` | ALLOW `delegation_granted` | ALLOW `tool_granted` | 1 | completed_allowed | **true** (CLI sidecar) |
| `d7524a4e-8da6-4171-8867-d2a2168128ac` | vulnerable | ATTACK | 10 | 10 | credit-002 | compliance-004 (hop 1) | `ambient_deputy` | ALLOW fail-open | ALLOW `tool_granted` | 1 | completed_allowed | **true** (CLI sidecar) |
| `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` | defended | RETEST | 6 | 6 | credit-002 | not on hop 1 | `delegated` | DENY `delegated_authority_not_granted` | none | **0** | completed_denied | **true** (CLI sidecar) |

Runtime `export.json` still records `splunk.verified=false`.

---

## Implementation status (this phase)

MCP-006: **IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED**  
Detection: **DETECTION ANALYZED — NO NEW DETECTOR**  
Workshop / Dashboard Studio: **NOT STARTED in this 7C report** (Phase 7D later added `ws_lab_mcp_006`; see `docs/PHASE7D_MCP006_WORKSHOP.md`).
