# Phase 8E — LAB-MCP-CATALOG workshop and Dashboard Studio

**Date:** 2026-09-16  
**View:** `ws_lab_mcp_catalog` (`/en-US/app/agentsec/ws_lab_mcp_catalog`)  
**Builder:** `scripts/build_lab_mcp_catalog_dashboard.py`  
**Schema:** `agentsec.security_event` **1.5.0** (unchanged in this phase)  
**Evidence class:** OBSERVED (Splunk Web + Playwright) unless marked MEASURED / SIMULATED / DOCUMENTED.

Phase 8A/8B/8C/8D are PASS. This phase does **not** change runtime authorization, schema 1.5.0, DET-MCP-001, or Q-MCP SPL logic. No DET-MCP-CATALOG. No scanner integration. No rug-pull / `tools/list_changed`. No A2A. Rejected hunts `Q-MCP-CATALOG-METADATA`, `Q-MCP-CATALOG-TRUST`, `Q-MCP-CATALOG-FINGERPRINT`, `Q-MCP-CATALOG-FOLLOWON`, and `Q-MCP-CATALOG-AUTHZ` are not published.

Q-MCP-EXECUTED is **not rewritten**. Extra METADATA-001 OBSERVE rows are taught, not “fixed.”

---

## WORKSHOP FLOW

Ten GRID tabs:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Learning story:

- LAB-MCP-001: May this agent call this **TOOL**?
- LAB-MCP-003: May this agent call it at this **SCOPE**?
- LAB-MCP-004: May it operate on this **RESOURCE**?
- LAB-MCP-005: Can **TOOL RESULT DATA** change later authority?
- LAB-MCP-006: Can a **DEPUTY** exercise authority belonging to another caller?
- LAB-MCP-CATALOG: Can **TOOL METADATA** influence a request and improperly become authority?

These are not the only MCP security problems.

Core teaching:

REQUEST ≠ GRANT  
OBSERVE ≠ ALLOW  
METADATA PROVENANCE ≠ CONTENT TRUST  
AUTHORIZED TOOL ≠ TRUSTED DESCRIPTION

The defended security boundary is still CTRL-MCP-001. METADATA-001 classifies catalog bytes as data.

---

## DASHBOARD STRUCTURE

| Tab | Teaching | Bound searches |
|-----|----------|----------------|
| LEARN | Ladder; metadata vs tool; request vs grant; trust boundary | Markdown + three cards |
| BASELINE | NORMAL catalog; OBSERVE then legitimate `lookup_policy` | CATALOG-AUTHORITY What Happened, AUTHZ, TOOL, EXECUTED |
| ATTACK | MALICIOUS catalog; description not authorized; follow-on ALLOW overlay | CATALOG-AUTHORITY, AUTHZ, TOOL, EXECUTED |
| OBSERVE | Sequence; authority / control / execution | Sequence, CATALOG-AUTHORITY, AUTHZ, TOOL, EXECUTED |
| HUNT | Primary CATALOG-AUTHORITY; rejected hunts named; EXECUTED extra-row teaching | CATALOG-AUTHORITY, AUTHZ, TOOL, EXECUTED, WHO |
| DETECT | DETECTION GAP; DET-MCP-001 silent; LIVE 0; SIMULATED | Q-MCP-AFTER-DENY + `makeresults` SIMULATED |
| DEFEND | CTRL-MCP-001 still grants; not sanitize / scanner / Splunk | Markdown |
| RETEST | Same MALICIOUS hash as ATTACK; DENY; runtime 0 | CATALOG-AUTHORITY, AUTHZ, TOOL, EXECUTED |
| COMPARE | Three cards BASELINE / ATTACK / RETEST | Markdown only |
| PROVE | Ten questions; INV-002; evidence hierarchy | CATALOG-AUTHORITY on Hunt token |

Tokens (Phase 8D fresh LIVE specimens):

| Token | Default run.id |
|-------|----------------|
| `run_id` (Hunt) | `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` (BASELINE) |
| `baseline_run_id` | same BASELINE |
| `attack_run_id` | `a0937bff-31a5-453a-99bf-47d7b5148ce4` |
| `retest_run_id` | `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` |

---

## LEARN RESULT

DOCUMENTED in builder + OBSERVED on LEARN tab. Complete Phase 8D UUIDs sit in the first 520px panel. Conceptual flow: catalog → metadata → observe → request → CTRL-MCP-001 → handler only after ALLOW. Ladder MCP-001…006 then MCP-CATALOG.

---

## BASELINE RESULT

Phase 8D facts, workshop presentation:

profile = defended · mode = BASELINE · catalog = NORMAL  
METADATA-001 OBSERVE `metadata_is_data`  
Hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`  
`lookup_policy` ALLOW `tool_granted` then `mcp.started` / `mcp.completed`  
Follow-on: NONE  
Handlers 1/0  

Preferred sentence: “The catalog metadata was treated as data. The granted lookup_policy call was authorized separately and executed. No follow-on tool request was produced.” Not labeled SAFE.

---

## ATTACK RESULT

profile = vulnerable · mode = ATTACK · catalog = MALICIOUS  
METADATA-001 remains OBSERVE  
First `lookup_policy` remains ALLOW + execute  
Follow-on REQUEST `lookup_customer_tier`  
CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`  
then `mcp.started` / `mcp.completed`  
Handlers 1/1  
Hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

INTENTIONALLY VULNERABLE LAB BEHAVIOR. The DESCRIPTION was not authorized. The FOLLOW-ON REQUEST was improperly granted by the vulnerable authorization path.

---

## OBSERVE RESULT

What Happened is `Q-MCP-CATALOG-AUTHORITY` (indexed). Sequence helper exposes run_id, profile, mode, sequence, control id/type, decision, reason, tool, event, metadata trust/provenance, content hash, outcome. No `_raw`. No full descriptions. No LLM narrative as evidence.

---

## HUNT RESULT

Reuse: Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED. Primary: Q-MCP-CATALOG-AUTHORITY. Hunt token defaults to BASELINE. Empty Hunt is not a red error.

Q-MCP-EXECUTED extra METADATA-001 OBSERVE row: control-event executed=false is not handler non-execution; the OBSERVE row may inherit `lookup_policy` execution_state from run/tool grouping. Copy forbids “metadata executed” and “OBSERVE caused execution.” SPL not rewritten.

---

## DETECT RESULT

DET-MCP-001 / Q-MCP-AFTER-DENY LIVE specimens: BASELINE **0** · ATTACK **0** · RETEST **0** (Phase 8D MEASURED). ATTACK used an ALLOW-path failure, so execution-after-DENY does not apply. **DETECTION GAP**, not detector failure. Right table: **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL` (`makeresults`, NOT INDEXED). **No DET-MCP-CATALOG.** DET-MCP-001 unchanged.

---

## DEFEND RESULT

Defense is not: sanitize the description, block the first legitimate tool, trust scanner output, or ask Splunk for permission. Catalog metadata may influence a REQUEST. Server-owned authorization determines the GRANT. Defended follow-on: CTRL-MCP-001 DENY `tool_not_granted`. Handler does not begin. Runtime handler count remains authoritative.

---

## RETEST RESULT

`23c222ea-6a87-40b7-a3e9-f12a5b572fa1` — defended, same MALICIOUS catalog. METADATA-001 OBSERVE. `lookup_policy` ALLOW + execute. Same follow-on request. CTRL-MCP-001 DENY `tool_not_granted`. Runtime follow-on handler **0**. No indexed follow-on `mcp.started` on COMPLETE transport (12=12, Phase 8D).

Copy: “Runtime handler count 0 is the authoritative non-execution proof. The complete Splunk copy provides corroborating evidence.” Does not say Splunk proves it was blocked.

---

## ATTACK/RETEST FINGERPRINT PROOF

ATTACK hash == RETEST hash (indexed METADATA-001, hash not preview):

`sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

Visible on ATTACK, RETEST, COMPARE, and PROVE.

---

## COMPARE RESULT

Three markdown cards: BASELINE / ATTACK / RETEST. Central lesson: ATTACK and RETEST used the SAME malicious metadata. The difference was the authorization profile. Metadata did not become authority in the defended profile.

---

## PROVE RESULT

Ten questions answered from 8C/8D facts. Ends with INV-002: retrieved/tool-provided content cannot independently widen authority. Limitations stay visible (no `allowed_tools`, extra EXECUTED row, bounded preview, no `gen_ai.tool.call.id`, scanners not ingested).

---

## EMPTY-STATE RESULT

`hideWhenNoData` is false. `noDataMessage` examples: “No indexed follow-on MCP execution event was found for this run.” “No indexed DENY followed later by mcp.started was found.” Captions are populated-state teaching, not empty-state claims. Forbidden empty interpretations (blocked / safe / no attack) are absent from `noDataMessage`.

---

## ACCESSIBILITY RESULT

Ten tabs reachable via Studio tab bar (Playwright clicked). Input labels Hunt / BASELINE / ATTACK / RETEST. Status in text (OBSERVE / ALLOW / DENY / SIMULATED / MALICIOUS / NORMAL). Full UUIDs on LEARN. Full SHA-256 hashes on ATTACK / RETEST / COMPARE. Keyboard focus is Splunk chrome. Not a WCAG certification.

---

## LIVE SPLUNK UI

Playwright 10/10 tabs. Four tokens MEASURED (complete UUIDs in DOM `input_value`, not visual ellipsis). Indexed What Happened rows OBSERVED for A/B/C. DETECT left empty OBSERVED; right SIMULATED OBSERVED. ATTACK/RETEST MALICIOUS hash OBSERVED on ATTACK, RETEST, COMPARE, PROVE.

After `--refresh-app` / named-volume restage, Splunk Web served the view (HTTP 200). HEC health returned empty reply during lab-up wait (same class as Phase 7D). Do not claim the local lab was READY for new ingest during pass-2. No new LIVE specimens were generated in 8E.

Clipping inspect: 1440 all tabs; 1024 and 768 LEARN / RETEST / COMPARE. Full UUIDs remain on LEARN. Full hash remains on COMPARE header at 768.

---

## UI REVIEW

Pass-1: 0 BLOCKER / 3 HIGH / 4 MEDIUM / 3 LOW (`docs/reviews/ui-review-ws-lab-mcp-catalog-2026-09-16.md`).  
Pass-2: **0 BLOCKER / 0 HIGH**. Residual MEDIUM/LOW accepted.

---

## SECURITY SEMANTICS REVIEW

The UI does **not** claim:

- metadata OBSERVE = ALLOW
- metadata OBSERVE = DENY
- authorized tool = trusted metadata
- malicious metadata = malicious tool
- metadata provenance = content trust
- request = grant
- ALLOW = execution
- mcp.started = success
- mcp.failed = prevention
- no Splunk row = blocked
- DET-MCP-001 silence = safe
- scanner PASS = trusted
- scanner FAIL = DENY
- Splunk authorized the operation
- SIMULATED = LIVE

---

## SPLUNK KNOWLEDGE-OBJECT REUSE

| Object | Role |
|--------|------|
| Q-MCP-WHO | Hunt identity (METADATA extra row empty method) |
| Q-MCP-AUTHZ | Control decisions including METADATA-001 OBSERVE |
| Q-MCP-TOOL | mcp.started |
| Q-MCP-EXECUTED | Execution reconstruction (extra OBSERVE row taught) |
| Q-MCP-AFTER-DENY | DETECT live hunt |
| DET-MCP-001-POSITIVE-CONTROL | DETECT SIMULATED fixture |
| Q-MCP-CATALOG-AUTHORITY | Primary catalog hunt / What Happened |
| DET-MCP-001.spl | Unchanged; not enabled by this dashboard |

No DET-MCP-CATALOG. No extra Q-MCP-CATALOG-* files.

---

## TEST RESULTS

`.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`  
**454 passed, 2 deselected** (2026-09-16, this session).

XML/JSON parse and match. Ten tabs. Tokens resolve. Validated SPL bind-only. DET-MCP-001 unchanged. No DET-MCP-CATALOG. Schema remains 1.5.0. Playwright 10/10 is separate from pytest.

---

## FILES CHANGED

Workshop markdown, Studio definition/XML, nav, lab-up/lab-ready/splunk_app_init, dashboard/workshop tests, screenshot script, this document, learning note, UI review, IMPLEMENTATION_STATUS, inventory, app README.

Not changed: catalog runtime authorization, schema 1.5.0, DET-MCP-001.spl, Q-MCP-*.spl logic (bind-only), scanners, rug-pull, A2A.

---

## LIMITATIONS

- Playwright `full_page` still captures the first Studio canvas, not GRID below the fold.
- Token input fields may ellipsis 36-character UUIDs visually; LEARN prints complete values.
- Q-MCP-EXECUTED extra OBSERVE row remains (taught, not rewritten).
- Q-MCP-AUTHZ row order is not METADATA-first (taught, not rewritten).
- No indexed `allowed_tools`.
- DET-MCP-001 silence is a detection gap.
- Scanners not ingested.
- HEC health may be empty after Splunk restart; Splunk Web still served the workshop.

---

## PHASE 8E VERDICT

**VALIDATED** for the workshop/Dashboard Studio teaching surface on Phase 8D LIVE indexed copies.

LAB-MCP-CATALOG: COMPLETE FOR PHASES 8A–8E.

Runtime: IMPLEMENTED + LOCALLY VALIDATED  
Splunk: VALIDATED  
Workshop: VALIDATED  
Detection: DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN  
Scanner integration: NOT STARTED  
Rug-pull: NOT STARTED  
A2A: NOT STARTED
