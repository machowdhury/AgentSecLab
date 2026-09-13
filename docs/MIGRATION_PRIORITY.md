# AgentWatch Range — Migration Priority

**Phase:** AgentSec Phase 0  
**Companion:** `docs/MIGRATION_INVENTORY.md`  
**Rule:** Identify proven assets. Do not blindly copy. Do not migrate code in this phase.

Evidence is **OBSERVED** (source inspection of `/Users/mahamudc/Documents/workspace/AgentwatchRange`) or **DOCUMENTED** (AgentWatch docs). Live attack outcomes and live Splunk results are **NOT MEASURED**.

---

## What this phase decided

Phase 0 is complete enough to start Phase 1 **architecture and a thin proving loop**. Phase 1 is not “copy AgentWatch.”

Phase 1 must still make AgentSec-owned decisions that AgentWatch cannot make:

1. Fill `docs/MASTER_SPEC.md` (currently headings only).
2. Name which surfaces are IMPLEMENTED vs SIMULATED vs PLANNED.
3. Freeze a telemetry contract that includes `run.id`.
4. Define `vulnerable` vs `defended` security profiles and control decisions.
5. Map the first attacks to invariants, not to 51 techniques.
6. Create tests before claiming controls.

Those items are the **start of Phase 1**, not leftover archaeology.

---

## Priority order

1. Do not copy the predecessor tree.  
2. Reuse proven teaching and telemetry **shapes**.  
3. Refactor what is useful but loosely wired.  
4. Redesign surfaces that were only simulated.  
5. Drop duplicates and theater that would teach the wrong lesson.

---

## P0 — First proving loop (Phase 1 slice)

Smallest useful AgentSec path after this inventory:

| # | Outcome | AgentWatch analog | Inventory class |
|---|---------|-------------------|-----------------|
| 1 | One sequential 4-agent (or equivalent) loan path + local Ollama | `agent_router` + `llm_client` | REFACTOR |
| 2 | One benign baseline request on the **real** path | `traffic_simulator` / `/api/v1/process` | REUSE |
| 3 | One live attack from an Attack Service | Top 10 / custom POST | REFACTOR |
| 4 | Input control **before** LLM | AcmeGate placement | REFACTOR (reference control) |
| 5 | Honest output-control telemetry **after** inference | AcmeSentinel placement | REFACTOR (do not call it pre-op DENY) |
| 6 | OTel → collector → Splunk HEC | collector config | REUSE |
| 7 | Shared `run.id` + one `incident_id` for the pipeline | **Missing** on live 4-agent path; present on kill chains | New + borrow chain idea |
| 8 | A few **validated** hunts (not 15 dashboards) | macros + `otel:agentic:json` | REUSE shape |
| 9 | Unit tests for deterministic guards | **Missing** | New (AgentSec `tests/` layout) |
| 10 | Learning note for that slice | `docs/learning-notes/` | New |

**Stop.** Do not import Exercise Runner, All 51, MLTK, Cisco CLIs, or MAESTRO UI until this loop is proven with tests.

Suggested first teaching surfaces (from AgentWatch value, not bulk coverage):

| Teaching | AgentWatch analog | Invariant |
|----------|-------------------|-----------|
| Input inspection before LLM | Scenario 3 / AcmeGate | INV-008, check-before-use |
| Output inspection honesty | Scenario 5 / AcmeSentinel | Never call post-LLM block a pre-op DENY |
| Baseline vs attack | Traffic simulator | INV-007 |
| Optional later: tool allowlist | Scenario 6 MCP | INV-001 — only when a real tool exists |

---

## Wave 1 — Reuse first (highest value, lowest lie)

Bring **concepts and shapes**, not a git subtree.

| Priority | Asset | Why it is valuable |
|----------|-------|--------------------|
| 1 | LIVE / HYBRID / SIMULATED + `testbed_mode` | Protects research integrity |
| 2 | Technique registry schema (YAML → OTel → lookup) | One taxonomy, many consumers |
| 3 | Pre-LLM `workflow_guard` **placement** | Control before inference |
| 4 | OTel Collector → Splunk HEC | Apps do not speak Splunk SDK |
| 5 | Benign baseline on the real LLM path | Attacks visible against noise |
| 6 | Top 10 scenarios + First Win pedagogy | Curriculum spine |
| 7 | Kill-chain **shared `incident_id`** idea | Best correlation in the old lab |
| 8 | Dashboard Studio **generators** + packaging script idea | Repeatable Splunk engineering |
| 9 | Exercise Runner **workflow** (predict → hunt → reveal) | How to teach |
| 10 | `norm_*` cross-app normalization idea | Splunk as SIEM |
| 11 | Index macros + a single control-block predicate | Customer-retargetable SPL |
| 12 | Control matrix as **measurement**, not enforcement | Honest attestation |
| 13 | CONCEPTS.md-style limitation writing | Stops overclaiming |
| 14 | Compose overlay pattern (local / external Splunk / optional vendor) | Deployment without extra platforms |
| 15 | Learning tiers 0–6 + “do not teach SIMULATED standalone” | Curriculum honesty |

---

## Wave 2 — Refactor (keep, but fix)

| Asset | What AgentSec must fix |
|-------|------------------------|
| LLM client | Honor security-profile flags; emit `run.id`; fail-closed option on Ollama errors |
| Agent router | One incident + parent trace per pipeline; stop implying network A2A |
| Attack Panel | `run.id` on every click; store returned IDs; align hybrid defaults; 51 vs 45 copy |
| Input / output regex | Tests; labeled **reference** controls; separate vulnerable/defended profiles |
| HITL | Vulnerable profile may fail open **and say so**; defended profile REQUIRE_APPROVAL |
| Technique executor | In-process live calls; `telemetry.fidelity`; no contradictory HARD_DENY on sim leg |
| Chain engine | Label SIMULATED; do not hardcode guard outcomes as if measured |
| Campaign enrichment | Prefix or field for SIMULATED Cisco/Galileo/CTSM |
| Splunk props | Extract `session.id` **or** emit `session_id`; emit `control.id` if attestation joins need it |
| Cisco integration | Wire enforce **or** delete the claim (`should_block_from_cisco_scan` is dead) |
| Docs | Single technique count; mappings ≠ certification |

---

## Wave 3 — Redesign (keep the lesson, rewrite the mechanism)

| Lesson | AgentWatch implementation | AgentSec direction |
|--------|---------------------------|--------------------|
| MCP tool abuse | Substring gateway, no MCP server | Real tool allowlist, or labeled SIMULATED stub |
| A2A identity | `did:acme:` regex, default valid passport | Explicit delegation object (INV-001 / INV-005) |
| RAG exfil | Alert-only regex, no store | INV-002 when RAG exists; omit until then |
| Memory poisoning | In-process dict | Trust-tagged records (INV-003) |
| Orchestration bypass | Foundry marker strings | Workflow state machine (INV-006) |
| 4-agent “architecture” | One process, four prompts | Fine for Phase 1 if documented as sequential |
| Test strategy | None | `tests/unit`, `tests/security`, `tests/telemetry` from day one |
| Dashboards | 13 Classic + 2 Studio | AgentSec rule: new views are Studio unless documented otherwise |
| Output DENY | After successful inference | Telemetry must not claim pre-op DENY |

---

## Drop

| Asset | Why |
|-------|-----|
| `splunk_app/App-Agentic-Compliance/` | Superseded by the canonical app |
| `scripts/phase6_bulk_rename.py` and siblings | One-shot history |
| Pretending SIMULATED OTel is live control proof | Research integrity |
| `soar_simulator.py` as a control | Sleep + field injection |
| DefenseClaw / Skill Scanner embedding | Not in the repo |
| Guard env vars **as if they work** | Displayed, not enforced on the LLM path |
| Copying all 51 generic LIVE payloads | Many non–Top-10 payloads are template strings |
| `LAB_MODE=enforce` documentation | Function never called |
| “Cisco commercial platform” overlay claim | Env flags only |
| Kubernetes, Kafka, extra databases, enterprise IAM | Forbidden by AgentSec core rules |

---

## Phase 1 definition of done (proposed)

A learner can:

1. Send one benign AcmeBank (or AgentSec-named) request.  
2. Send one attack.  
3. See `run.id` in the UI and in Splunk.  
4. Explain the trust boundary (HTTP client → app → Ollama).  
5. Explain whether a control ran **before** or **after** the dangerous operation.  
6. Point to a test that proves the deterministic guard without requiring the LLM.

It does **not** mean 51 techniques, 15 dashboards, MLTK, or Cisco CLIs.

---

## What must not leak from AgentWatch into AgentSec

- Regex theater labeled as MCP / A2A / RAG / cryptographic passport.  
- Dashboards that imply 51 equally real live tests.  
- `HARD_DENY` on events that never called the model.  
- `session.id` / `session_id` split.  
- Unauthenticated execute-all in any shared lab.  
- Lab-default passwords and HEC tokens copied as “the” credentials. Use env/secret injection only (**hardcoded-credentials rule**).

No code was migrated in this phase.
