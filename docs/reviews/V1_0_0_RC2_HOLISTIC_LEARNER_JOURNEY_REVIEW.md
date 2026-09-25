# AgentSec v1.0.0-rc2 — holistic learner-journey review

**Date:** 2026-09-24  
**Reviewer role:** external technically capable learner / independent assessor (not a feature builder)  
**Mode:** assessment. No RC2 tag. No schema change. No detector. No Phase 18.  
**Starting / reviewed commit:** `d38d33f327b728e469b84032553673dfe7ee9c37`  
**Determination:** GO FOR RC2 REMEDIATION  

Companion: [V1_0_0_RC2_LEARNER_FRICTION_LOG.md](V1_0_0_RC2_LEARNER_FRICTION_LOG.md)

---

## 1. Executive determination

**GO FOR RC2 REMEDIATION**

Core LIVE loop works on this workstation: clone docs, Attack Service launch, CTRL-MCP-001 ATTACK ALLOW vs RETEST DENY, Splunk `dc(_raw)` matching local counts for fresh PI and MCP runs, Academy/Mastery/Capstone artifacts exist, schema 1.9.0, RC1 tag immutable.

RC2 must **not** be tagged yet. Exit criteria require BLOCKER=0 **and** HIGH=0. This review found **1 HIGH** (product-wide execution-evidence language still contradicts the Capstone/ToolRegistry model). Clean-room install remains **not proven**. GitHub landing over-sells detect/defend.

Do not read this as RC2 released.

---

## 2. Review scope

Whole-product external journey:

DISCOVER → CLONE → UNDERSTAND → INSTALL → START → ORIENTATION → PI → MCP → RAG → MEMORY → GOAL → IDENTITY → CAPSTONE → MASTERY → SPLUNK → LIMITATIONS → INDEPENDENT OPERATION

Personas: technical beginner (A), SOC/Splunk engineer (B), security architect (C).

Evidence classes follow repository research-integrity rules. Simulated browser interception was **not** used in this session.

---

## 3. Repository verification

| Item | Value | Class |
|------|-------|-------|
| Branch | `develop` | MEASURED |
| HEAD | `d38d33f327b728e469b84032553673dfe7ee9c37` | MEASURED |
| origin/develop | same | MEASURED |
| Working tree at start | clean | MEASURED |
| Tag `v1.0.0-rc1` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` | MEASURED |
| Other tags | historical phase tags + rc1 only | MEASURED |
| RC2 tag | absent | MEASURED |
| Product version | `1.0.0rc1` (`pyproject.toml`, `__version__`, health JSON) / Splunk app `1.0.0-rc1` | MEASURED |
| Schema | `1.9.0` (`SCHEMA_VERSION`) | MEASURED |
| Python | `>=3.11`; learner path does not require `uv` | DOCUMENTED |
| Docker | Compose v2, `splunk/splunk:10.2` `linux/amd64` | DOCUMENTED |
| Model | compose Ollama `llama3.2:1b` (host 11434 unpublished) | DOCUMENTED |
| Browser | unspecified; Splunk Web + Attack Service | DOCUMENTED |

RC1 was not moved. RC2 was not created.

---

## 4. Diff analysis (this review)

This assessment did not modify application code. Only review markdown is added.

---

## 5. GitHub landing (60 seconds)

Public repo: https://github.com/machowdhury/AgentSecLab (`visibility: PUBLIC`).

| Question | Answerable from landing + README? |
|----------|-----------------------------------|
| What is AgentSec? | YES — README first paragraph |
| Who is it for? | YES |
| What will I learn? | YES — Academy list |
| What do I need? | YES — Docker, Git, browser |
| How do I start? | YES — QUICKSTART commands |
| How long? | WEAK — effort lives in lab matrix, not README |
| Where does Splunk fit? | YES — investigation workbench, not PDP |
| Production security software? | YES — explicitly not |
| Where are the labs? | YES — Academy URL + matrix |
| Limitations? | YES — KNOWN_LIMITATIONS |

**Friction:** GitHub `description` is broader than README (“detect… defend… validate AI-agent security”). A visitor who never opens README can over-read product claims. **RC2-F-02.**

---

## 6. README / Quickstart command matrix

| Command | Source | Purpose | Works | Expected output documented | Failure guidance |
|---------|--------|---------|-------|----------------------------|------------------|
| `./scripts/lab-preflight.sh` | README/QS | Prerequisites | Syntax OK; not re-run as clean-room | PASS/WARN/FAIL | YES |
| `cp .env.example .env` | README/QS | Config | Clone has example, no committed `.env` | “once; do not commit” | Partial (no copy error text) |
| `./scripts/lab-up.sh` | README/QS | Start stack | Not executed this review (existing stack) | 10–20 min first Splunk | TROUBLESHOOTING |
| `./scripts/lab-up.sh --build` | QS | Rebuild images | Required after UI changes; this stack appeared stale | Documented | YES |
| `./scripts/lab-ready.sh` | README/QS | Service health | Not re-run; semantics: health ≠ searchable evidence | READY = SERVICE HEALTH | YES |
| `./scripts/lab-down.sh` | README | Soft stop | Not executed | Volumes persist | YES |
| pytest (optional) | README | Developers | **947 passed, 2 deselected** | Command listed | N/A |

---

## 7. Clean-install and first-boot

**Classification: PARTIAL — NOT CLEAN-ROOM PROVEN**

What was isolated:

- Fresh `git clone` to `/tmp/agentsec-rc2-clone` (no `.env` in tree). README/Quickstart readable. **MEASURED.**

What was **not** isolated (must not be claimed as clean-room):

- Existing Docker images, Splunk volumes, indexes, `.env`, Ollama model cache, historical REPLAY ids.
- No second compose project / VM.

This matches RC1 `V1_0_0_RC1_CLEAN_INSTALL_VALIDATION.md` and `KNOWN_LIMITATIONS.md`.

Observed on the **existing** stack (not first boot):

- Attack Service `/health` 200, version `1.0.0rc1`, schema `1.9.0`
- AcmeBank `/health` 200, version `1.0.0rc1`, profile `defended`, Ollama reachable
- Academy Home URL HTTP 303 (login redirect)
- All seven LIVE Attack lab URLs HTTP 200

**clone → first useful page:** not timed from empty Docker. From clone, README + Academy URL are immediate; Splunk login blocks Academy until admin password from `.env`.

**clone → first successful LIVE:** PI ATTACK this session in **~2.3s** API time on a warm stack (`run_id` `d31a7ec7-2cfe-476d-a722-eaf1f4611701`). Cold first boot remains 10–20 minutes per docs. **NOT PROVEN** as clean-room elapsed time.

---

## 8. Health semantics

`lab-ready.sh` and QUICKSTART state READY is **service health**. Attack `/health` is availability and educational-bind flags, not control effectiveness. AcmeBank `/health` is profile/model reachability, not “experiment correct.”

This session: `hec.ok=false` with `otlp.ok=true` on PI/MCP launches; Splunk still indexed matching `dc(_raw)`. HEC flag is transport/health, not completeness. **RC2-F-06.**

---

## 9. Academy and orientation

Home tabs: **START · ORIENT · PATH · SPLUNK**. Primary action: Direct Prompt Injection.

ORIENTATION content (source) teaches agents/tools/MCP, RAG/memory as data, PDP vs OBSERVE, Splunk as copy, LIVE vs REPLAY, inequalities (REQUEST ≠ GRANT, ALLOW ≠ EXECUTION, SPLUNK ≠ ENFORCEMENT).

Gap: Home still defines EXECUTION as “handler or LLM actually started” **and** “Runtime counts are authoritative.” That collides with Capstone invocation-vs-completion. **RC2-F-01.**

Persona A can find “where do I start?” Persona A can skip ORIENT because START pushes PI first.

---

## 10. LIVE vs REPLAY

Docs (`LIVE_VS_REPLAY.md`) are accurate. LIVE labs: PI, MCP-001, RAG, Memory, Goal, Identity, Capstone. REPLAY-only workshops: MCP-003/004/005/Catalog/Scanner/006.

Fresh Splunk volume may have empty REPLAY tables. Documented. Beginner risk remains. **RC2-F-03.**

Studio tokens are not bound to fresh LIVE ids (Capstone and others). Manual Search handoff is the product.

---

## 11. Learning journey (curriculum, not a rebuild)

| Lab | LIVE/REPLAY | Purpose (learner) | This review |
|-----|-------------|-------------------|-------------|
| PI | LIVE | Untrusted input vs CTRL-INPUT-001 | Fresh ATTACK MEASURED; 22 local = 22 Splunk |
| MCP | LIVE | Tool request vs CTRL-MCP-001 | Fresh ATTACK ALLOW invoke 1 + mcp.completed; RETEST DENY invoke 0 |
| RAG | LIVE | Retrieved data OBSERVE; tool PDP MCP | Source + prior reviews; Attack UI still overclaims handler count |
| Memory | LIVE | Persist/recall data; MCP PDP | Same |
| Goal | LIVE | Authorized tool ≠ authorized goal | Source: CTRL-GOAL then CTRL-MCP-001 |
| Identity | LIVE | Claim ≠ authentication; MCP PDP | Source + Mastery |
| Capstone | LIVE | Integrated chain | Source remediations present; **running container HTML stale vs HEAD** |
| Mastery | Assessment | Reasoning, not certificate | Path B visible; questions are conceptually strong |

Concept progression in `curriculum.json` is logical: input → tool grant → context → intent/identity → capstone. L4 is woven into Path A, not a separate workshop (documented).

---

## 12. Control map (implementation, not marketing)

| Control | Domain | Decisions | Controls | Does not control | Role |
|---------|--------|-----------|----------|------------------|------|
| CTRL-INPUT-001 | PI / LLM invoke | ALLOW / DENY (lab regex) | Whether Ollama is invoked on PI path | MCP tools | Enforcement on PI hops |
| CTRL-MCP-001 | MCP tools | ALLOW / DENY | Tool grant before handler | RAG/memory classification, goals, identity authn | **Tool PDP** |
| CTRL-RAG-CONTEXT-001 | Retrieval | OBSERVE | Classification of retrieved bytes | Grants | Advisory |
| CTRL-MEMORY-CONTEXT-001 | Memory | OBSERVE | Classification of stored/recalled bytes | Grants | Advisory |
| CTRL-GOAL-INTEGRITY-001 | Task | OBSERVE / DENY | Task expansion vs contract | Tool allow-list | Goal boundary; not tool PDP |
| CTRL-IDENTITY-001 | Claims | OBSERVE | Claim classification | Authentication, grants | Advisory |
| CTRL-MCP-RESULT-001 / METADATA-001 / DELEGATION-001 | MCP labs | OBSERVE / compose with MCP | Result/catalog/deputy teaching | Production IAM | Lab-specific |

Falsification: this session did **not** find a second tool PDP on the MCP ATTACK/RETEST path. Overlay fail-open is still CTRL-MCP-001 labeled ALLOW.

---

## 13. Execution evidence model

**Implemented (ToolRegistry):** `invoke_counts` increment in `call_handler` **before** the handler body. Count is process-local **invocation-begin**. Completion is `mcp.completed` / `mcp.failed` + hop outcome.

**Taught inconsistently:**

- Capstone source/docs (post independent-review remediation): invocation vs completion.
- Home, RAG/Memory Attack UI (`attack_context.html`), MCP/RAG/Memory/Goal/Identity/Scanner workshops: “runtime handler count is authoritative proof of execution / non-execution.”
- Live Capstone page on this Docker image still served the old handler-count-as-authority copy (**stale image**, **RC2-F-07**).

MCP this session (MEASURED): ATTACK `operation.executed=true`, `mcp.started/completed=true`, handler_invokes=1; RETEST `executed=false`, `outcome=prevented`, no start/complete, count 0.

---

## 14. Trust boundaries (actual)

| Boundary | Trusted? | Owner |
|----------|----------|-------|
| Learner → Attack Service | No (unauthenticated localhost client) | Closed JSON contract |
| Fixture → agent context | Data, not authority | RAG/memory fixtures |
| Retrieval → context | Untrusted data | CTRL-RAG-CONTEXT-001 OBSERVE |
| Memory → recall | Untrusted data | CTRL-MEMORY-CONTEXT-001 OBSERVE |
| Instruction → goal | Untrusted instruction | CTRL-GOAL-INTEGRITY-001 |
| Identity claim → policy | Claim is data | CTRL-IDENTITY-001 OBSERVE |
| Agent → MCP request | Request ≠ grant | CTRL-MCP-001 |
| PDP → runtime | Coded policy + overlay | AcmeBank |
| Runtime → telemetry | Best-effort emit | OTel |
| Telemetry → Splunk | Downstream copy | HEC/OTLP |
| Splunk → learner | Interpretation risk | Path A discipline |

---

## 15. Threat-model (educational, not compliance)

| Theme | Coverage |
|-------|----------|
| Prompt / instruction injection | Covered (PI, Goal) |
| Tool authorization / confused deputy | Covered (MCP-001, MCP-006 REPLAY) |
| Retrieved / stored context as instruction | Covered (RAG, Memory) |
| Identity/delegation claims | Partial (claims as data; no OAuth/OIDC/SPIFFE) |
| Scanner vs runtime | Partial (REPLAY) |
| Supply-chain / rug-pull | Intentionally not covered |
| Production MCP mesh / A2A wire | Intentionally not covered |

No formal OWASP/ATLAS/NIST compliance claim is justified. ATLAS labels are already limited in KNOWN_LIMITATIONS.

---

## 16. Attack UI (product grammar)

Five templates: PI (`attack.html`), MCP, context (RAG/Memory), authority (Goal/Identity), Capstone.

They are one family but **not** one evidence vocabulary. Context UI maps `count > 0` to **EXECUTED**. Capstone source separates invocation/completion; running image did not show that copy.

Copy controls: Capstone source names Primary/Retrieve/Write/Recall/Source. Memory workbench still uses mixed “Copy” vs “Copy ATTACK write run.id”. **LOW.**

Responsive/accessibility: **PARTIAL**. HTTP 200 on lab pages. No new 1920–1024 / 200% zoom pass in this session. Screen-reader **PARTIAL** (not AT-tested). Prior UI reviews exist as OBSERVED provenance.

---

## 17. Splunk workshops and queries

**Grammar:** Most labs: LEARN → … → PROVE (10 tabs). Capstone: MISSION / INVESTIGATE / EVIDENCE / PATH B · ANSWERS. Home: START/ORIENT/PATH/SPLUNK. Mastery: challenge markdown with Path B on-page.

This is intentional Capstone graduation vs instructional labs, but Persona A will feel two products. **RC2-F-04.**

Path B cannot be hidden on Studio 10.2 (Mastery states this). Answer leakage is a **documented platform limit**, still material for “Capstone evaluates reasoning.” **RC2-F-05.**

**Query inventory:** 27 standalone `Q-*.spl` files; **308** Studio-embedded `dataSources` queries across 14 dashboards (including reused families). Duplicates are mostly tokenized copies of the same hunt per tab.

**Q-RUN / Q-DENY:** `savedsearches.conf` `disabled=1`, NOT VALIDATED. Acceptable to leave for RC2 if CHANGELOG/inventory stay honest. CHANGELOG currently lists them as packaged hunts. **RC2-F-08.**

**DET-MCP-001:** packaged, disabled. No DET-CAPSTONE / DET-RAG / DET-MEMORY / DET-GOAL. Detector silence ≠ SAFE is taught on Home.

**Handoff:** PI launch JSON includes `search_handoff.starter_spl` and Search URL. Learner still must log into Splunk. Studio tables remain REPLAY specimens.

This session did **not** click Path A inside Dashboard Studio (login wall). Workshop visual review is **source + prior UI reviews (OBSERVED/DOCUMENTED)** plus live Search completeness via CLI.

---

## 18. Completeness (this session)

| Run | Lab | Local | Splunk `dc(_raw)` |
|-----|-----|-------|-------------------|
| `d31a7ec7-…` | PI ATTACK | 22 | 22 |
| `d4ff7f01-…` | MCP ATTACK | 7 | 7 |
| `b461688a-…` | MCP RETEST | 6 | 6 |

HEC was **not** used as completeness. `evidence_state` remained `WAITING_FOR_EVIDENCE` at HTTP return.

Historical seven-lab RC1 pairs remain documented MEASURED in `docs/releases/`. Not re-run in full this review.

---

## 19. Closed contract

Live POST `/api/launch` with extra `profile` or `grants`: HTTP JSON `error_class=ERROR`, `unknown_fields`, not DENY. Unit tests cover the listed authority-like fields. **MEASURED + tested.**

ERROR ≠ DENY is implemented.

---

## 20. Tests

Focused:

```text
uv run --extra test python -m pytest \
  tests/unit/test_launch_contract.py \
  tests/unit/test_mcp_authorize.py \
  tests/unit/test_phase16b_capstone_learning_loop.py \
  tests/unit/test_phase16d_academy.py \
  tests/unit/test_phase17a_mastery.py \
  tests/unit/test_phase17b_learner.py \
  tests/unit/test_phase17d_release.py \
  tests/unit/test_phase15b_rag_learning_loop.py::test_concurrent_rag_attack_and_retest_do_not_leak_profile \
  -q --tb=line
```

**78 passed in 0.73s**

Full offline:

```text
uv run --extra test python -m pytest tests -q --tb=line \
  -m "not live_ollama and not live_splunk"
```

**947 passed, 2 deselected in 8.79s** (real 9.22s)

Concurrent RAG isolation test: **passed** in focused and full suite this session. Prior remediations observed one intermittent full-suite failure. Classification: **UNKNOWN** (test isolation vs process-env vs product concurrency). Do not hide. **RC2-F-09.**

Gaps: Studio rendering, clean-room compose, and rebuilt Attack image are not covered by this pytest command.

---

## 21. Version consistency

| Surface | Value |
|---------|-------|
| Python package | `1.0.0rc1` |
| Splunk app.conf | `1.0.0-rc1` |
| README | v1.0.0-rc1 candidate |
| Health JSON | `1.0.0rc1` (AcmeBank and Attack Service) |

Hyphen vs PEP440 spelling is **LOW**. Historical “AcmeBank `/health` older until rebuild” was **not reproduced**; health matched package.

---

## 22. Secret hygiene

- `.env` gitignored; clone had no `.env`
- `.env.example` contains **lab defaults** (Splunk password complexity string, HEC token labeled lab ingest). Not treated as a committed production secret; still a workshop credential. **INFORMATIONAL**
- No private keys/certs added this review
- This report does not reprint `.env` values
- Splunk CLI used container `admin:${SPLUNK_PASSWORD}` without printing it; stderr contained a WARNING (hostname validation class; not reproduced as a committed TLS disable)

---

## 23. Repository hygiene

Large `docs/reviews`, `docs/PHASE*`, `artifacts/`, screenshots. GETTING_STARTED correctly says PHASE files are provenance, not install. Outsiders can still land in phase docs via search. Cleanup is optional RC2 polish, not a blocker.

---

## 24. Release artifacts vs RC2

Still RC1-branded: CHANGELOG, `docs/releases/V1_0_0_RC1_*`, app version. Required before tagging rc2: bump notes, inventory, known limitations (clean-room, execution language), GitHub description. **Do not do that in this commit.**

---

## 25. Falsification

| Claim | Result this review |
|-------|--------------------|
| CTRL-MCP-001 is the tool PDP | **Not falsified** (MCP ATTACK/RETEST) |
| RAG/Memory observational | **Not falsified** in code comments/pipelines |
| Splunk is downstream | **Not falsified** |
| ALLOW ≠ completion | **Not falsified** (control `executed` vs mcp.*) |
| Handler count ≠ completion | **Implementation agrees; UI/docs often disagree** → HIGH teaching defect, not a PDP bug |
| Hash equality ≠ data-flow copy | Capstone remediation; other labs still casual “same fingerprint” |
| HEC health ≠ completeness | **Confirmed** (`hec.ok=false`, counts matched) |
| Identity not cryptographically authenticated | **Not falsified**; docs generally careful |
| Detector silence ≠ SAFE | **Not falsified** on Home |

No core runtime claim was falsified. The **curriculum claim** that handler count is authoritative execution **is falsified by ToolRegistry**.

---

## 26. Findings

### RC2-F-01 — Product-wide “authoritative handler count” vs invocation-begin

- **Severity:** HIGH  
- **Evidence:** `ToolRegistry.call_handler` increments before handler; Capstone remediation language; Home `dashboard.definition.json`; `attack_context.html` maps count>0 to EXECUTED; MCP/RAG/Memory/Goal/Identity/Scanner workshop markdown.  
- **Why it matters:** After Capstone, the product teaches two evidence models. Architects and SOC learners will collapse INVOKED with COMPLETED.  
- **Claim falsified:** “Runtime handler count is authoritative proof of successful execution / non-execution” as a whole-product doctrine.  
- **Remediation (later):** Align Home, Attack UIs, workshops, Mastery hints to REQUESTED / AUTHORIZED / INVOKED / COMPLETED / FAILED / OUTCOME using existing telemetry. No schema change.

### RC2-F-02 — GitHub description over-sells detect/defend

- **Severity:** MEDIUM  
- **Evidence:** `gh repo view` description vs README “not a production security product.”  
- **Remediation:** Match GitHub about text to README one-liner.

### RC2-F-03 — Clean-room / empty REPLAY still unproven

- **Severity:** MEDIUM  
- **Evidence:** This clone-only isolation; RC1 reproducibility PARTIAL; KNOWN_LIMITATIONS.  
- **Remediation:** Documented operator clean-room or accepted limitation on the rc2 notes. Do not claim clean-room because containers were already up.

### RC2-F-04 — Dual workshop grammars

- **Severity:** MEDIUM  
- **Evidence:** 10-tab labs vs Capstone 4-tab vs Home 4-tab.  
- **Remediation:** Explain on Home PATH why Capstone looks different; optional later unification (not required if documented).

### RC2-F-05 — Path B always visible

- **Severity:** MEDIUM  
- **Evidence:** Mastery copy; KNOWN_LIMITATIONS.  
- **Remediation:** Accept for Studio 10.2 or hide via product capability later. Do not pretend Path A is a technical gate.

### RC2-F-06 — WAITING_FOR_EVIDENCE / hec.ok=false while OTLP indexes

- **Severity:** MEDIUM  
- **Evidence:** PI/MCP launch JSON vs Splunk counts.  
- **Remediation:** Clarify launcher state machine; never imply HEC is the completeness channel.

### RC2-F-07 — Attack Service image can lag git HEAD

- **Severity:** MEDIUM  
- **Evidence:** Live Capstone HTML still contained `attack_context.html` execution-authority sentences; HEAD `attack_capstone.html` does not. QUICKSTART `--build`.  
- **Remediation:** Operator rebuild after UI commits; optional ready-check that template hash matches.

### RC2-F-08 — Q-RUN / Q-DENY placeholders vs CHANGELOG

- **Severity:** LOW  
- **Evidence:** `savedsearches.conf` disabled; CHANGELOG “Packaged hunts include Q-RUN, Q-DENY.”  
- **Remediation:** CHANGELOG wording; keep searches disabled.

### RC2-F-09 — Intermittent concurrent-RAG pytest

- **Severity:** LOW  
- **Evidence:** Passed this session; previously failed once in a full suite then passed isolated. **UNKNOWN** root cause.  
- **Remediation:** Isolation hardening of `AGENTSEC_SECURITY_PROFILE` assertions; do not “fix” by deleting the test.

### RC2-F-10 — README omits total effort

- **Severity:** LOW  
- **Evidence:** Effort in curriculum/matrix only.

### RC2-F-11 — Memory copy-button label mix

- **Severity:** LOW  
- **Evidence:** `attack_context.html` generic Copy vs labeled write.

### RC2-F-12 — Lab default credentials in `.env.example`

- **Severity:** INFORMATIONAL  
- **Evidence:** Documented localhost lab defaults. Rotate if bound off localhost.

### RC2-F-13 — Splunk CLI hostname-validation WARNING

- **Severity:** INFORMATIONAL  
- **Evidence:** CLI stderr WARNING on search (not printed). Local container CLI, not a new committed certificate.

### RC2-F-14 — Version string hyphen inconsistency

- **Severity:** INFORMATIONAL  
- **Evidence:** `1.0.0rc1` vs `1.0.0-rc1`.

---

## 27. Release readiness matrix

| Area | Result | Evidence | Highest finding |
|------|--------|----------|-----------------|
| GitHub landing | PASS WITH FRICTION | README strong; about text broad | F-02 |
| Install | PARTIAL | Clone yes; clean-room no | F-03 |
| First boot | PARTIAL | Warm stack only | F-03, F-07 |
| Academy | PASS WITH FRICTION | START/ORIENT present | F-01, F-04 |
| LIVE labs | PASS | PI/MCP MEASURED; others DOCUMENTED | F-01 |
| REPLAY | PARTIAL | Docs honest; empty index risk | F-03 |
| Attack UI | PASS WITH FRICTION | HTTP 200; stale Capstone image; handler language | F-01, F-07 |
| Splunk workshops | PASS WITH FRICTION | Source + prior reviews; Studio not clicked | F-04, F-05 |
| Correlation | PASS WITH FRICTION | PI one id; multi-run docs exist | F-11 |
| Security semantics | FAIL (teaching) / PASS (runtime) | PDP MEASURED; doctrine HIGH | F-01 |
| Capstone | PARTIAL | Source remediations; live UI stale | F-07 |
| Mastery | PASS WITH FRICTION | Strong questions; Path B visible | F-05 |
| Accessibility | PARTIAL | Not AT-tested this session | — |
| Documentation | PASS WITH FRICTION | QUICKSTART excellent; CHANGELOG/GitHub | F-02, F-08 |
| Tests | PASS | 947/2 | F-09 |
| Secret hygiene | PASS | Lab defaults only | F-12 |
| Release artifacts | PARTIAL | Still RC1 branded | — |

---

## 28. RC2 exit criteria status

| Criterion | Status |
|-----------|--------|
| BLOCKER = 0 | PASS |
| HIGH = 0 | **FAIL** (F-01) |
| Core learner journey works | PARTIAL (warm stack yes; clean-room no) |
| README/Quickstart usable | PASS |
| First boot documented | PASS |
| LIVE labs work | PASS (sampled MEASURED) |
| Splunk handoff works | PASS (PI/MCP) |
| Capstone works | PARTIAL (source vs running image) |
| Mastery works | PASS WITH FRICTION |
| Limitations discoverable | PASS |
| Control semantics consistent | **FAIL** (teaching) |
| Schema coherent | PASS (1.9.0) |
| No secret issue | PASS |
| Tests reproducible | PASS (with F-09 UNKNOWN) |
| RC1 immutable | PASS |

---

## 29. Personas

- **A Beginner:** Can install from docs on a prepared machine. Will struggle with REPLAY emptiness, Path B answers, 10 tabs, WAITING_FOR_EVIDENCE, and `--build`. **Not a clean PASS.**
- **B SOC:** Can reconstruct Splunk role. Must ignore Q-RUN/Q-DENY and handler-count slogans. **PASS WITH FRICTION.**
- **C Architect:** Runtime/PDP story is bounded. GitHub blurb and handler-count doctrine are the main precision failures. **PASS WITH FRICTION.**

---

## 30. Product comprehension (plain language)

Shipped README **does** support:

> AgentSec is a controlled educational environment for learning how AI-agent influence, context, memory, goals, identity claims, authorization, runtime execution, and downstream evidence interact.

> Splunk observes and reconstructs evidence here; it does not authorize the agent's tool call.

> The labs demonstrate specific controlled scenarios, not universal production security effectiveness.

GitHub about-text **weakens** the third sentence. Handler-count doctrine **weakens** precise execution language. Limitations are findable if the learner opens KNOWN_LIMITATIONS.

---

## 31. Evidence classification

- **MEASURED:** git, clone, health HTTP, closed-contract ERROR, PI/MCP launches, local vs Splunk counts, pytest  
- **OBSERVED:** live Capstone HTML stale vs HEAD, Attack page copy  
- **DOCUMENTED:** Academy/Mastery/workshop source, RC1 packs, limitations  
- **SIMULATED:** none this session  
- **PARTIAL:** clean-room, Studio clicking, viewports, AT, remaining LIVE labs  
- **NOT TESTED:** disposable VM compose, Splunk-down failure, Ollama-down PI, 200% zoom this session  
- **NOT MODELED:** OAuth/OIDC/SPIFFE, production MCP mesh  
- **NOT PROVEN:** clean-room first boot, universal security, WCAG  

---

## 32. Required actions before RC2 (do not start here)

1. Align whole-product execution language with ToolRegistry + Capstone evidence levels (**F-01**).  
2. Rebuild/verify Attack Service image matches HEAD (**F-07**).  
3. Decide accept-or-run a true clean-room boot (**F-03**).  
4. Tighten GitHub description (**F-02**).  
5. Clarify WAITING_FOR_EVIDENCE vs OTLP completeness (**F-06**).  
6. Optional: CHANGELOG Q-RUN/Q-DENY, copy labels, README duration.

No tag. No GitHub Release. No schema bump.

---

## 33. Known limitations (learner-visible)

Localhost unauthenticated Attack Service; fixture RAG/memory; process-local counters; no production identity; Path B visible; DET-MCP-001 disabled; HEC ≠ completeness; REPLAY needs indexed specimens; hardware not benchmarked; clean-room not proven; screen-reader PARTIAL.

---

## 34. Git integrity (end of review commit expected)

Expected after review-only commit:

- Branch `develop`
- RC1 tag unchanged
- No `v1.0.0-rc2`
- Working tree clean after push
