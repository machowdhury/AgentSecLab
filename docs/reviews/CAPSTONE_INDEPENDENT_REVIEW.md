# CAPSTONE INDEPENDENT REVIEW

**Reviewer role:** independent adversarial release review (not the builder).  
**Mode:** READ-ONLY except this file.  
**Determination:** CONDITIONAL GO  
**Date:** 2026-09-24  
**Reviewed range:** `928053feabba0a55afa0c11eefb0fe250bd817c1` → `d33e6609a01120a5878f699a461ae667cb06aa49`

Evidence classes used below: MEASURED, OBSERVED, DOCUMENTED, SIMULATED, REPLAYED, PARTIAL, NOT MODELED, NOT PROVEN.

---

## 1. Executive Determination

The Capstone **can** demonstrate, from repository code plus independently reproduced runtime and Splunk evidence:

SOURCE → RETRIEVE → RAG OBSERVE → PERSIST (hash-equivalent fixture bytes) → RECALL → MEMORY OBSERVE → REQUEST → MCP PDP (`CTRL-MCP-001`) → ToolRegistry → EVIDENCE

with a controlled ATTACK ↔ RETEST comparison on the **same document-byte fingerprint**, where profile/authorization/execution/outcome change and RAG/Memory remain OBSERVE.

Core security conclusion is **supported**. Release is **CONDITIONAL GO** because several builder statements are **stronger than the implementation**: persist is fixture-equivalent rather than a retrieve-output copy; ToolRegistry count increments **before** the handler body; `Q-MCP-AUTHZ` `executed=false` on ATTACK ALLOW control rows; MISSION predict copy discloses expected ALLOW/handler 1 before Path A investigation; claimed “47 focused tests” was not reconstructed as a single command.

None of those defects falsified ATTACK execution, RETEST non-execution, or MCP PDP ownership.

---

## 2. Review Scope

Inspected the stated commit range, full diff (36 files), runtime PDP/registry/memory/RAG paths **not** modified in-range, Capstone UI/workshop/SPL, builder artifacts, independently launched LIVE ATTACK/RETEST, Splunk re-query of builder run IDs, focused and full pytest.

Did **not** modify application code, tests, dashboards, detections, schema, artifacts, or git history.

---

## 3. Repository Verification

| Check | Independent result | Class |
| ----- | ------------------ | ----- |
| Branch | `develop` tracking `origin/develop` | MEASURED |
| HEAD | `d33e6609a01120a5878f699a461ae667cb06aa49` | MEASURED |
| `origin/develop` | same as HEAD | MEASURED |
| Ending commit claim | MATCH | MEASURED |
| Starting commit | `928053feabba0a55afa0c11eefb0fe250bd817c1` exists; parent of ending commit; one commit in range (`feat(ux): build capstone security investigation workbench`) | MEASURED |
| RC1 commit `e6115b6d1c03a1672b4364e84748c7840671fbfc` | exists; annotated tag `v1.0.0-rc1` points at this commit; ancestor of HEAD | MEASURED |
| Working tree at review start | clean | MEASURED |
| File count `START..END` | **36 files**, 2860 insertions / 2303 deletions | MEASURED |

`git tag --points-at HEAD` does **not** place `v1.0.0-rc1` on the Capstone commit. The tag object hashes to a tag blob; the tagged commit is `e6115b6d…`.

---

## 4. Diff Analysis

### File classification (36)

| Class | Files |
| ----- | ----- |
| RUNTIME | none of `mcp/`, `rag/`, `memory/`, `identity/`, `goal/`, schema, detectors |
| UI | `src/agentsec/attack_app.py` (Capstone template routing + workbench dict only), `src/agentsec/templates/attack_capstone.html` |
| SPLUNK DASHBOARD | `learning/level_1/LAB-AGENTSEC-CAPSTONE-001/dashboard.definition.json`, `splunk_app/agentsec/default/data/ui/views/ws_lab_agentsec_capstone.xml` |
| SPL | data-source **query strings** in the dashboard JSON (see §14) |
| TEST | `tests/unit/test_phase16b_capstone_learning_loop.py`, `tests/splunk/test_lab_agentsec_capstone_dashboard.py` |
| DOCUMENTATION | learning note + 6 review/logic/live-validation files |
| EVIDENCE | screenshot PNGs + validation JSON under `docs/screenshots/` |
| GENERATED | Studio XML/JSON from builder |
| CONFIGURATION | `investigations.json` tab labels |
| OTHER | `scripts/build_lab_agentsec_capstone_dashboard.py`, `capture_lab_agentsec_capstone_screenshots.py`, `validate_capstone_live.py`, `validate_shared_workbench_regression.py` |

### Runtime semantics outside Capstone UI

**Claim: runtime security semantics unchanged.** Supported for this range.

`git diff START..END -- src/agentsec/attack_app.py` is template selection + `capstone_workbench` presentation fields. No change to `authorize.py`, `registry.py`, `memory/store.py`, `mcp/pipeline.py`, schema, or `savedsearches.conf`.

---

## 5. Security Model Reconstruction

Reconstructed from code, not from the build summary.

| Stage | Implementation | Evidence | Security Role |
| ----- | -------------- | -------- | ------------- |
| SOURCE | Closed `MALICIOUS_DOCUMENT` / `doc.lending-policy.malicious` | Fixture + `content_hash()` | Influence only |
| RETRIEVE | `launch_service._launch_capstone` → `/rag/retrieve` | Distinct `retrieve_run_id` | Context entry |
| RAG | `CTRL-RAG-CONTEXT-001` OBSERVE `retrieved_context_is_data` | retrieve hop 0 | Classification, **not** PDP |
| PERSIST | `InProcessMemoryStore.write_fixture` loads `FIXTURES[memory_id]` (`MALICIOUS_DOCUMENT`); launch then **checks** retrieve hash == write hash == experiment fingerprint | write `content_hash`; provenance `agentsec.memory.fixture` | Persistence of **equivalent** bytes, not a copy of retrieve payload |
| RECALL | `/memory/recall`; primary `run_id == recall_run_id` | `source_run_id` = write UUID | Later influence |
| MEMORY | `CTRL-MEMORY-CONTEXT-001` OBSERVE `memory_context_is_data`; overlay minted **only** if `profile == "vulnerable"` | recall hop 0 | Classification; overlay is **lab fail-open machinery**, not a grant object for defended |
| REQUEST | Closed follow-on `lookup_customer_tier` / `customer:read` / `cust-001` | recall hop 1 tool name | Intent |
| MCP PDP | `authorize_tool` / `CTRL-MCP-001` in `mcp/authorize.py` | hop 1 control row | **Sole tool authorization** on this path |
| ToolRegistry | `McpServer.execute` requires AllowTicket; `call_handler` increments then runs handler | handler counts; `mcp.started/completed` | Execution begin |
| EVIDENCE | local events + OTLP/HEC copy to Splunk | `dc(_raw)` vs local counts | Downstream reconstruction |

**Goal** and **Identity** are **not** active causal stages. Live packets had empty `goal_control_decision` / `identity_control_decision`. Splunk Goal/Identity reconstructions on builder IDs were empty lists. Workshop asks the learner to **rule them out**; it does not present them as the incident mechanism.

---

## 6. Trust Boundaries

| Boundary | Input | Output | Control | Evidence | Assumptions | Failure mode |
| -------- | ----- | ------ | ------- | -------- | ----------- | ------------ |
| 1 Retrieved data → agent context | Fixture document | RAG context + OBSERVE | CTRL-RAG-CONTEXT-001 | retrieve control event | Closed catalog | Treating OBSERVE as ALLOW |
| 2 Retrieved bytes → persistent memory | `memory_id` key | Fixture bytes with matching hash | Launch hash equality check; store write | write hash / retrieve hash | Same closed string in two fixture tables | Pedagogical “copy” overclaim; hash-ambiguous if many identical docs |
| 3 Recalled influence → privileged request | Recalled text + closed interpreter | Follow-on tool request | Interpreter, not PDP | follow-on fields | Marker recognized | Influence mistaken for grant |
| 4 Tool request → MCP PDP | RPC tools/call | ALLOW/DENY | CTRL-MCP-001 | control.decision | Overlay only on vulnerable | Overlay misread as RAG/Memory enforcement |
| 5 PDP → ToolRegistry | AllowTicket | Handler body | Ticket pop + `execute` | count, mcp.* | Count before body | Count=1 without completion |
| 6 Runtime telemetry → Splunk | Local events | Indexed copy | None (not a PDP) | `dc(_raw)` | Export complete | Absence ≠ prevention |

**Missing / weak boundary:** there is **no schema field** retrieve→write. Hash equality is the join. That is honest for 1.9.0, not a hidden extension.

---

## 7. Control Ownership

| Control | Actual semantics | Enforcement? |
| ------- | ---------------- | ------------ |
| `CTRL-RAG-CONTEXT-001` | OBSERVE `retrieved_context_is_data` | No |
| `CTRL-MEMORY-CONTEXT-001` | OBSERVE `memory_context_is_data`; overlay mint only when vulnerable | No (classification). Overlay is **intentionally vulnerable lab machinery** consumed by MCP |
| `CTRL-MCP-001` | Allowlist + overlays + profile fail-open / `tool_not_granted` | **Yes — sole tool PDP** on this path |

`ToolRegistry` has no authorization. `McpServer.execute` refuses missing tickets.

No second tool PDP was found on the Capstone launch path (`/rag/retrieve`, `/memory/write`, `/memory/recall` only).

UI/docs generally keep OBSERVE ≠ ALLOW. Residual overclaims are listed in §22 / findings.

---

## 8. ATTACK Reproduction

### Builder packet (REPLAYED artifacts + MEASURED Splunk re-query)

| Field | Expected | Independent |
| ----- | -------- | ----------- |
| RETRIEVE | `98c160d8-e54e-4af4-962f-fc48dcb194a0` | Present in Splunk; `dc(_raw)=5`, `count=5` |
| WRITE | `f75a7e0c-beb4-4273-af96-ef120f033c01` | `dc(_raw)=5` |
| RECALL | `6cf91471-96a0-4505-9e67-fca41f6af2af` | `dc(_raw)=11`; sequence 1–11 reconstructable |
| MCP | ALLOW `vulnerable_profile_fail_open:memory_derived_authority` | Splunk control row MEASURED |
| Tool | `lookup_customer_tier` | MEASURED |
| Count | 1 | Artifact hops: handler.invoked true, mcp.started/completed, outcome success |
| Customer-tier | occurred | Splunk `mcp.completed` preview contains `cust-001`, `tier`, `standard` |

Causal order on builder RECALL (MEASURED Splunk sequence): run.started → hop0 memory.recalled + MEMORY OBSERVE → hop1 MCP ALLOW → mcp.started → mcp.completed → hop.completed → run.completed.

### Fresh LIVE this review (MEASURED)

POST `/api/launch` ATTACK `specimen_id=CAPSTONE-001`:

- RECALL `613dab6a-b661-4d97-b749-4ab1fc38525e`
- ALLOW `vulnerable_profile_fail_open:memory_derived_authority`
- handler count 1; hop1 mcp.completed / outcome success
- fingerprint `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`
- schema `1.9.0`
- `source_run_id` == write UUID
- RAG/Memory OBSERVE

**Core ATTACK claim:** VERIFIED (not from string search alone).

---

## 9. RETEST Reproduction

### Builder packet

| Field | Independent |
| ----- | ----------- |
| RETRIEVE `c8e886e5-6de5-4362-ac0c-b9f6d2cca5ab` | Splunk `dc(_raw)=5` |
| WRITE `c71fd015-bebf-4298-8f4d-918797029478` | `dc(_raw)=5` |
| RECALL `16bfb73c-0fdb-4aab-881a-99efa34fd049` | `dc(_raw)=10` |
| MCP DENY `tool_not_granted` | Splunk MEASURED |
| mcp.started/completed | **none** indexed |
| handler 0 | Artifact hops: handler.invoked false, outcome prevented |

### Fresh LIVE this review (MEASURED)

Same specimen `CAPSTONE-001`, `mode=RETEST`:

- DENY `tool_not_granted`
- handler 0; hop1 no mcp.started; outcome prevented
- **same fingerprint** as this review’s ATTACK
- local events 5 / 5 / 10

Wrong specimen `CAPSTONE-001-RETEST` returned HTTP 400 `unknown_specimen` (UX mix-up risk; see §15).

**Core RETEST claim:** VERIFIED.

---

## 10. Controlled Comparison

Fingerprint `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` is SHA-256 of **UTF-8 closed RAG document bytes** (`MALICIOUS_DOCUMENT` only). Independently hashed. It is **not** experiment-level integrity.

Held constant (MEASURED this session + builder artifacts): document id, document-byte hash, memory id, RAG OBSERVE, Memory OBSERVE, requested tool/scope/resource, schema 1.9.0.

Changed: ExperimentContext profile (`vulnerable` vs `defended`), overlay eligibility, CTRL-MCP-001 ALLOW vs DENY, handler 1 vs 0, mcp.completed vs no mcp execution events, local recall 11 vs 10 events (the extra ATTACK events are mcp.started/completed).

Uncontrolled but **not** outcome-explanatory here: new UUIDs each launch; process-local memory store; OTLP vs HEC (`hec.ok` false on builder HTTP, `otlp.ok` true). Sequential ATTACK then RETEST this session still produced DENY/0 after ALLOW/1 with identical hashes.

**Controlled comparison:** VERIFIED for the closed lab.

---

## 11. Correlation Analysis

1. Two RETRIEVE events **can** share identical document bytes (ATTACK and RETEST do by design; BASELINE uses different bytes).
2. Multiple WRITEs **can** persist identical fixture bytes (`allow_replace` / sequential launches of the same `memory_id`).
3. Hash equality retrieve→write is therefore **ambiguous across experiments** if IDs are mixed.
4. Timestamps/`_time` are **not** treated as authority; `agentsec.sequence` within a run is ordered.
5. Concurrent launches share process memory; tests include `test_concurrent_capstone_attack_and_retest_do_not_leak_profile`. Residual race remains a lab limitation.
6. `agentsec.memory.source_run_id` uniquely names the WRITE for that RECALL **when the learner uses the matching triple**.
7. Full chain is deterministic **inside one launched triple**; cross-triple hash joins are not unique.

**Correlation quality:** ADEQUATE_FOR_CONTROLLED_LAB  
Schema 1.9.0 was not changed (as required).

---

## 12. ToolRegistry Evidence Analysis

`ToolRegistry.call_handler` increments `invoke_counts[name]` **then** invokes the handler. `McpServer.execute` calls it only with a ticket. Pipeline records per-run delta vs `counts_before_by_tool`.

| Count | Proves | Does not prove |
| ----- | ------ | -------------- |
| 1 | This run’s registry entered `lookup_customer_tier` handler (invocation **began**). Process-local, once per `call_handler`, not reset between HTTP launches except new process. | Successful return; customer-tier payload; no exception after increment; no other process |
| 0 | This run’s delta did not enter `call_handler` for that tool | That no other code path exists in the universe; that Splunk is complete |

ATTACK this review: count 1 **and** `mcp.completed` + outcome `success` + indexed preview with `tier`/`standard`. That combination supports customer-tier access **occurred**. Count alone is weaker than the UI sentence “CUSTOMER-TIER ACCESS OCCURRED”.

Pipeline sets `operation.executed = True` **before** `server.execute()` returns; a failed handler can still show attempted/executed with `mcp.failed`. Capstone ATTACK observed **completed**, not failed.

**ToolRegistry execution evidence:** PARTIAL as an exclusive authority; ADEQUATE when combined with mcp.completed / hop outcome.

---

## 13. Splunk Evidence

Independently reconstructed builder RECALL runs:

- RAG/Memory OBSERVE on retrieve/recall families (artifact + hunt-shaped fields).
- Authorization: CTRL-MCP-001 ALLOW vs DENY as above.
- Execution: ATTACK `mcp.started` + `mcp.completed` present; RETEST **no** mcp execution events.

`Q-MCP-AUTHZ` binds `agentsec.operation.executed` on **control.decision** rows → ATTACK ALLOW shows `executed=false` even when mcp.completed exists. Missing telemetry ≠ prevention; that distinction is taught in Advanced/Path B, but the AUTH Z table can mislead if used as execution proof.

Splunk is downstream-only. No Splunk path mutates `coded_policy`.

---

## 14. SPL Identity Verification

Python extracted all `dataSources.*.options.query` from `dashboard.definition.json` at START vs END:

**32/32 IDENTICAL.** No added/removed query names.

Presentation markdown/layout changed; query bytes did not.

---

## 15. Completeness Verification

Builder claim format: local event count / Splunk `dc(_raw)`.

Independently MEASURED on builder IDs (also `count(_raw)`):

| Packet | Local (artifact) | Splunk `dc(_raw)` | Splunk `count` |
| ------ | ---------------- | ----------------- | -------------- |
| ATTACK retrieve | 5 | 5 | 5 |
| ATTACK write | 5 | 5 | 5 |
| ATTACK recall | 11 | 11 | 11 |
| RETEST retrieve | 5 | 5 | 5 |
| RETEST write | 5 | 5 | 5 |
| RETEST recall | 10 | 10 | 10 |

Numerator: events emitted locally for that `run.id`. Denominator: distinct `_raw` values indexed for that `run.id`.

This is **local-to-index distinct-raw agreement**, not “100% telemetry completeness,” not HEC health (`hec.ok` false on builder HTTP), not proof no other sinks dropped fields.

Naive `stats count by event.name` over-counted `mcp.started` (3) versus sequence table (1 mcp.started). Completeness using `dc(_raw)` remains consistent.

---

## 16. Workshop Review

Four tabs: MISSION, INVESTIGATE, EVIDENCE, PATH B · ANSWERS. Capture JSON lists the same tabs. Tokens default to **BASELINE** IDs, which is safer than defaulting ATTACK answers into tables.

Path A (INVESTIGATE + MISSION “Determine” / six questions) generally asks influence/intent/authority/execution without pasting DENY as a Search result. Progressive hints exist.

**Leakage:** MISSION “Predict ATTACK” markdown states expected **Vulnerable CTRL-MCP-001 ALLOW** and **Privileged handler 1** before the learner hunts. That is Path-A-adjacent answer disclosure. Path B itself is labeled a review key.

INVESTIGATE intro still says dropdowns default to “the official LIVE triple” while MISSION evidence rules correctly say **BASELINE**. Mixing BASELINE tokens into an ATTACK investigation is a learner error mode.

Goal/Identity investigations teach **instrumented absence**, not causal stages.

---

## 17. Attack Service UX

Workbench separates evidence map, multi-run IDs, influence/intent/authority/execution, grouped comparison, Advanced raw JSON. Semantic line: INFLUENCE ≠ AUTHORITY, REQUEST ≠ GRANT, ALLOW ≠ EXECUTION, SPLUNK ≠ ENFORCEMENT.

ATTACK is visually primary; RETEST remains an equal click (no server-side ATTACK-first lock). That matches “ATTACK-first investigation” as **copy**, not architecture.

Chain text “exact bytes” overstates persist mechanism (fixture load + hash check).

Hardcoded JS `requestedTool` / `cust-001` displays intent even if a future specimen lacked follow-on; current ATTACK/RETEST buttons only launch Capstone specimens that do request the tool.

---

## 18. Test Review

### Counts (MEASURED this session)

| Suite | Result |
| ----- | ------ |
| Claimed 47 focused | **Not reconstructed** as one documented command |
| Changed test files only (`test_phase16b_capstone_learning_loop.py` + `test_lab_agentsec_capstone_dashboard.py`) | 20 collected; included in passing runs |
| Those + `test_guided_investigations.py` | 28 collected |
| Broader academy/capstone-related files (reviewer-selected) | 98 passed |
| Full offline `pytest tests -m "not live_ollama and not live_splunk"` | **946 passed, 2 deselected, 0 failed** |

### Quality

Behavioral: `test_live_capstone_attack_and_retest_via_attack_service` asserts ATTACK ALLOW/count 1 vs RETEST DENY/count 0, fingerprint, `source_run_id`, OBSERVE, no browser-supplied grants. Concurrent profile isolation exists.

Structural: dashboard tests assert tabs, unused datasources, teaching strings, **do not execute SPL**. HTML tests assert copy, not WCAG. Passing tests do **not** prove production security effectiveness.

---

## 19. Schema Review

`SCHEMA_VERSION = "1.9.0"` in `experiment.py`. `schemas/security_event.schema.json` const `1.9.0`. Live packets reported `schema_version: 1.9.0`. **No schema files in the review range.** No new retrieve→write field.

---

## 20. Detector Review

No `DET-CAPSTONE` in `savedsearches.conf`. Range does not add saved searches. Workshop repeatedly says no DET-CAPSTONE. Existing DET-MCP-001 remains disabled hunt-form. UI does not claim a new detector was added.

---

## 21. Accessibility Review

Independent this session: CSS `:focus-visible { outline: 2px solid }` and skip-link; template skip-link, `aria-labelledby`, `role="status"` `aria-live="polite"`, table `th scope="row"`, semantic headings. Capture JSON: HTTP 200 at 1920/1440/1280/1024; overflow flag is `scrollWidth <= innerWidth` (true = **no** overflow); focus `solid 2px`; SIMULATED error via interception.

Not independently re-run: full keyboard traversal, screen-reader AT, 200% zoom live.

**Classification:** PARTIAL lab-grade accessibility. **Not** WCAG certified. Screen-reader readiness: **PARTIAL** (live status + headings; Advanced `<details>` and Studio chrome not AT-verified).

---

## 22. Security Claim Review

Problematic or overly strong language (not all fatal):

1. Logic proof / UI “WRITE exact bytes” / “retrieved bytes are written unchanged” — **data-flow overclaim**; hash-equivalent fixtures.  
2. Advanced/UI “Runtime handler count is authoritative for execution” — **too strong** vs increment-before-body.  
3. UI “CUSTOMER-TIER ACCESS OCCURRED” from `count > 0` without requiring `mcp.completed`.  
4. MISSION predict card states ALLOW and handler 1.  
5. Lab manifest “whether the defended retest **prevents** the same operation” — acceptable if read as this specimen, not universal. Elsewhere correctly denies universal resistance.  
6. No found claim that RAG/Memory OBSERVE **blocks** attacks, that Splunk enforces, or that Capstone proves production/universal effectiveness, in the changed Capstone surfaces reviewed. Path B explicitly marks those INCORRECT.

---

## 23. Secret Hygiene

Review-range diff scanned for AWS keys, GitHub PATs, Stripe live keys, PEM private keys, JWT-shaped strings, HEC token assignments, Bearer tokens. **0 hits.** No `.env` / credential files in the 36-file range. Splunk CLI uses container env `admin:${SPLUNK_PASSWORD}` and was not echoed.

**PASS** for this range. (Rule applied: treat any committed credential as compromised; none found.)

---

## 24. Certificate / TLS Finding

Builder documented Splunk CLI hostname-validation warning. This review’s `splunk search` CSV runs did **not** emit `WARNING:` lines. The setting is a **local Splunk CLI / container** behavior documented historically (`cliVerifyServerName`), **not** a committed application certificate or production TLS disable in this range. No PEM material added.

**Classification:** LOCAL DEVELOPMENT ONLY. Residual **DOCUMENTATION RISK** if operators copy CLI flags to production without reading KNOWN_LIMITATIONS. **Not** PRODUCTION CONFIGURATION RISK in committed Capstone files.

No certificate objects were present to expire/key-strength check.

---

## 25. Evidence Classification

| Item | Class |
| ---- | ----- |
| Git identities, 36-file diff, 32 query identity | MEASURED |
| In-range runtime PDP unchanged | MEASURED (diff) |
| Fresh ATTACK/RETEST HTTP launches | MEASURED |
| Builder run IDs in Splunk | MEASURED (re-query); original launch REPLAYED from artifacts |
| Completeness table | MEASURED |
| Pytest 946 / 2 deselected | MEASURED |
| Screenshots / 200% zoom / Studio 404s | OBSERVED (builder capture); not re-captured |
| SIMULATED ERROR screenshot | SIMULATED |
| Architecture statements | DOCUMENTED |
| Production auth / OAuth / PKI | NOT MODELED |
| Universal resistance | NOT PROVEN |
| 47 focused tests as one number | NOT PROVEN |

---

## 26. Claim-Evidence Matrix

| Claim | Evidence | Class | Reproduced? | Confidence | Limitation |
| ----- | -------- | ----- | ----------- | ---------- | ---------- |
| Document equality | Same `MALICIOUS_DOCUMENT` hash | MEASURED | Yes | HIGH | Bytes only |
| Persisted-byte equality | Write/recall hashes match retrieve | MEASURED | Yes | HIGH | Fixture load, not copy |
| Request equality | `lookup_customer_tier` / `customer:read` | MEASURED | Yes | HIGH | Closed interpreter |
| ATTACK ALLOW | hops + Splunk | MEASURED | Yes | HIGH | Lab overlay |
| RETEST DENY | hops + Splunk | MEASURED | Yes | HIGH | Same specimen, different mode |
| ATTACK execution | count 1 + mcp.completed + preview | MEASURED | Yes | HIGH | Count alone PARTIAL |
| RETEST non-execution | count 0 + no mcp.* + hop prevented | MEASURED | Yes | HIGH | Splunk absence insufficient alone |
| Customer-tier outcome | completed preview `tier`/`standard` | MEASURED | Yes (builder Splunk) | HIGH | Lab fixture, not real PII |
| RAG OBSERVE | retrieve hops | MEASURED | Yes | HIGH | Not enforcement |
| Memory OBSERVE | recall hop 0 | MEASURED | Yes | HIGH | Overlay still MCP’s problem |
| MCP PDP authority | `authorize_tool` only | MEASURED | Yes | HIGH | Overlays are MCP inputs |
| ToolRegistry authority | increment-before-body | MEASURED | Yes | MEDIUM | Not exclusive success proof |
| Splunk downstream-only | no policy mutation | MEASURED | Yes | HIGH | AUTH Z `executed` field trap |
| 32-query identity | hash/diff of queries | MEASURED | Yes | HIGH | Markdown changed |
| Completeness counts | dc(_raw) | MEASURED | Yes | HIGH | Distinct-raw, not omniscience |
| Schema 1.9.0 | const + live field + no schema diff | MEASURED | Yes | HIGH | |
| No detector | savedsearches + diff | MEASURED | Yes | HIGH | |
| Test counts | 946/2; 47 unmatched | MEASURED / NOT PROVEN | Partial | MEDIUM | 47 command unknown |
| Accessibility | CSS + capture JSON | PARTIAL | Partial | MEDIUM | No AT pass |
| Secret hygiene | diff scan | MEASURED | Yes | HIGH | Heuristic |

---

## 27. Falsification Attempts

| Attempt | Result |
| ------- | ------ |
| Stale handler count / no per-run delta | Pipeline subtracts `counts_before_by_tool`; RETEST 0 after ATTACK 1 in one process this session |
| RETEST different input | Fresh hashes identical |
| Different persist bytes | Hashes matched retrieve |
| Hash join ambiguity | Real across triples; not this sequential pair |
| Splunk order as causality | Used `agentsec.sequence` |
| Duplicate `_raw` inflating completeness | `dc` == `count` on builder IDs |
| Execution outside ToolRegistry | Follow-on goes `server.execute` → `call_handler` only |
| Mock mistaken for handler | Live HTTP + Splunk mcp.completed payload |
| Browser vs backend | Launch API JSON, not screenshots, used for decisions |
| Wrong specimen for RETEST | 400; correct specimen DENY |
| Overlay applies on defended | `evaluate_memory_trust_safe` mints overlay only if `profile == "vulnerable"` |
| `Q-MCP-AUTHZ executed` proves ATTACK did not run | Falsifies **that interpretation**; mcp.completed still present |
| AcmeBank `:8080` down ⇒ no runtime | `/api/launch` still 200; target was reachable via Attack Service client |
| 47 focused tests | Not found as a single suite |

No alternative explanation displaced ALLOW→DENY + 1→0 on identical document bytes.

---

## 28. Findings

### BLOCKER

None.

### HIGH

None.

### MEDIUM

**F-01 Persist is fixture-equivalent, not a retrieve-output copy**  
Severity: MEDIUM  
Evidence: `memory/store.py` `FIXTURES[memory_id]`; launch hash check in `_launch_capstone`.  
Component: memory store + launch_service + logic-proof/UI “exact bytes”.  
Why it matters: learners may believe a live byte pipe retrieve→write exists.  
Claim falsified: data-flow “copy” language. Hash equality **not** falsified.  
Remediation: say “same closed fixture bytes, verified by SHA-256” (do not implement in this review).

**F-02 ToolRegistry count increments before handler body**  
Severity: MEDIUM  
Evidence: `registry.py` `call_handler`; UI outcome from `count > 0`.  
Why it matters: count=1 is invocation-began. ATTACK still had mcp.completed.  
Claim falsified: exclusive “authoritative execution” without qualification.  
Remediation: pair count with mcp.completed / hop outcome in learner copy.

**F-03 `Q-MCP-AUTHZ` shows `executed=false` on ATTACK ALLOW**  
Severity: MEDIUM  
Evidence: Splunk control.decision rows this review.  
Why it matters: collapses evidence with non-execution if the table is misread.  
Claim falsified: using that field as execution authority. Workshop Advanced is clearer.  
Remediation: teach field provenance; prefer mcp.* / runtime count.

**F-04 MISSION predict card discloses ALLOW and handler 1**  
Severity: MEDIUM  
Evidence: `dashboard.definition.json` ATTACK predict markdown.  
Why it matters: Path A investigation is less independent.  
Claim falsified: “Path A does not reveal the final result” as a strict reading.  
Remediation: move expected numbers to Path B only.

### LOW

**F-05** INVESTIGATE copy “official LIVE triple” vs BASELINE token defaults.  
**F-06** Claimed 47 focused tests not independently located.  
**F-07** Multi-run ID copy: mixing ATTACK/RETEST/BASELINE UUIDs — **MODERATE UX RISK**, not HIGH investigation risk if learners follow labeled fields.  
**F-08** Studio three platform 404s (OBSERVED in capture JSON); tabs still loaded.  
**F-09** Builder HTTP `hec.ok=false` while OTLP path indexed events; do not equate HEC flag with completeness.

### INFORMATIONAL

Certificate hostname validation (local CLI). Goal/Identity hunts as absence tests. SIMULATED error labeled in capture JSON. `stats count by event.name` can over-count relative to sequenced `event.name`.

---

## 29. Release Determination

**CONDITIONAL GO**

Core Capstone claims independently reproduce. No release-blocking evidence defects. Several non-core accuracy/UX issues should be **accepted in writing** or corrected before tagging a release that treats the builder summary as literal.

---

## 30. Required Actions

Before calling the Capstone UX packet release-literal:

1. Accept or correct persist wording (fixture + hash check vs copy).  
2. Qualify ToolRegistry count vs successful completion.  
3. Accept MISSION predict leakage or move expected ALLOW/handler 1 to Path B.  
4. Do not advertise “47 focused tests” unless the exact command is recorded.

Do **not** start remediation from this review without explicit authorization.

---

## 31. Non-Blocking Improvements

- Align INVESTIGATE “LIVE triple” language with BASELINE defaults.  
- ATTACK-first as a real UX gate is optional; not required for the security result.  
- Studio custom token binding remains out of scope; keep Search handoff.  
- Screen-reader pass on Advanced `<details>`.  
- Avoid `stats count by event.name` as completeness.

---

## 32. Evidence Limitations

- This review’s fresh run IDs are **not** the builder IDs; both were used.  
- Viewport/zoom/AT not re-run live; rely on capture JSON (OBSERVED).  
- Pytest does not prove Splunk rendering or production control effectiveness.  
- Authentication, OAuth/OIDC, signed delegation, SPIFFE: **NOT MODELED** (stated in workbench Advanced).  
- One RETEST ≠ universal resistance.  
- Schema 1.9.0 hash join is lab-adequate, not globally unique attribution.

---

## Repository integrity (end of review)

The only intended persistent addition is this file. Application, tests, dashboards, SPL, and evidence artifacts were not modified by this review.
