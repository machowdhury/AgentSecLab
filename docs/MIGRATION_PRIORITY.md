# AgentWatch Range — Migration Priority

**Phase:** AgentSec Phase 0  
**Companion:** `docs/MIGRATION_INVENTORY.md`  
**Rule:** Identify proven assets. Do not blindly copy. Do not migrate code in this phase.

Evidence in this file is **OBSERVED** (source inspection and one Splunk packaging script run) or **DOCUMENTED** (AgentWatch docs). Live attack outcomes and live Splunk query results are **NOT MEASURED**.

---

## Priority order

1. Finish AgentSec decisions that AgentWatch cannot make for us.
2. Reuse proven teaching and telemetry shapes.
3. Refactor what is useful but broken or loosely wired.
4. Redesign surfaces that were only simulated.
5. Drop duplicates and theater that would teach the wrong lesson.

---

## P0 — Must be solved before Phase 1

Phase 1 should not start by copying AgentWatch into AgentSec. These questions are still open.

### 1. Fill `docs/MASTER_SPEC.md`

**OBSERVED:** The file is headings only (Mission, Architecture, Curriculum, Splunk design, Telemetry model, Security model, Workshops, MLTK, Compliance, Cisco integrations, Community adapters, Research campaign, Definition of done).

Without a filled spec, reuse decisions will recreate AgentWatch by default.

### 2. Decide what is real in AgentSec vs what is labeled SIMULATED

AgentWatch mixes:

- live Ollama attacks
- regex controls
- marker-based MCP / A2A / RAG
- direct OTel emission for SIMULATED techniques and kill chains
- optional Cisco CLIs that are not in the default image

AgentSec research rules require SIMULATED / REPLAYED evidence to stay labeled. Phase 1 needs an explicit matrix: which surfaces are IMPLEMENTED, EXPERIMENTAL, PLANNED, or SIMULATED.

### 3. Define the telemetry contract, including `run.id`

AgentWatch has no `run.id`. Live 4-agent runs do not share one `incident_id` or one trace. Logs emit `session.id`; Splunk extracts `session_id`.

AgentSec experiments require `run.id`, `lab.id`, version, model, security profile, attack, expected vs actual behavior, telemetry, control result, detection result, limitations.

This schema must exist before workshops or dashboards.

### 4. Define security profiles and control decisions

AgentWatch documents guard enable flags that the LLM path does not honor. HITL defaults to fail-open. Output DENY happens after inference.

AgentSec needs:

- a vulnerable profile (intentional fail-open, labeled)
- a defended profile (checks before dangerous operations)
- control enum: ALLOW / DENY / SANITIZE / QUARANTINE / REQUIRE_APPROVAL / OBSERVE / ERROR
- a rule that telemetry must not report DENY after a successful dangerous operation

### 5. Map first attacks to invariants, not to “51 techniques”

Do not port all 51 techniques in Phase 1. Pick a thin path that can prove:

- threat, attacker, asset, trust boundary, invariant
- expected result, reference control, telemetry, detection, test

Suggested first surfaces (from AgentWatch teaching value, not from bulk coverage):

| First teaching | AgentWatch analog | Invariant to prove |
|----------------|-------------------|--------------------|
| Input inspection before LLM | Scenario 3 / AcmeGate | INV-008, check-before-use |
| Output inspection honesty | Scenario 5 / AcmeSentinel | Never call POST-LLM block a pre-op DENY |
| Tool/MCP allowlist | Scenario 6 | INV-001 |
| Baseline vs attack | Traffic simulator | INV-007 |

### 6. Create a test strategy before application code

AgentWatch has **zero** automated security tests. AgentSec rules say no important feature is complete until tested.

Phase 1 minimum: unit tests for deterministic guards, separate from live LLM behavior. Reproduce-failing-test-fix is not possible until a harness exists.

### 7. Decide the application shell

Keep the **idea** of a small multi-agent loan (or similar) pipeline. Do not treat `app_runtime.py` + `exploit_ui.py` as the AgentSec architecture.

Decisions needed:

- same ACME Bank story or a new AgentSec story
- two processes (app + attack panel) vs one
- in-process sequential agents vs real A2A later
- local Ollama only for Phase 1

### 8. Decide Splunk app identity

Reuse the **pattern** (Dashboard Studio generators, macros, lookups, Exercise Runner). Do not import `acme_genai_compliance` as-is.

Rename macros, indexes, sourcetypes, and lookups to AgentSec names. Confirm NIST mappings against allowed frameworks only (AI RMF, 800-171 Rev. 3, 800-171A, 800-53 where relevant, ATLAS, OWASP LLM/Agentic, CSA MAESTRO). Do not use NIST SP 800-17.

### 9. Decide Cisco / MLTK / MAESTRO scope for v1

These are optional overlays in AgentWatch. They are not required to prove the core lifecycle:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → MEASURE → PROVE

Phase 1 can ship without Cisco CLIs, Foundation-Sec, CTSM, or the external MAESTRO UI.

### 10. Write the first learning objective and definition of done

Phase 1 done means a learner can run one benign request, one attack, see telemetry, and explain the trust boundary — with tests. It does not mean 51 techniques, 14 dashboards, and vendor overlays.

---

## Wave 1 — Reuse first (highest value, lowest lie)

Bring these as **concepts and shapes**, not as a git subtree dump.

| Priority | Asset | Why it is valuable |
|----------|-------|--------------------|
| 1 | LIVE / HYBRID / SIMULATED + `testbed_mode` | Protects research integrity |
| 2 | Technique registry schema (YAML → OTel → Splunk lookup) | One taxonomy, many consumers |
| 3 | Pre-LLM `workflow_guard` placement | Control before inference |
| 4 | OTel Collector → Splunk HEC pipeline | Apps do not speak Splunk SDK |
| 5 | Benign baseline traffic on the real path | Attacks are visible against noise |
| 6 | Top 10 scenarios + First Win (6 → 5 → 9) | Curriculum spine |
| 7 | Kill-chain shared `incident_id` model | Best correlation pattern in the old lab |
| 8 | Dashboard Studio sync generators + `validate_splunk_app.sh` | Repeatable Splunk engineering |
| 9 | Exercise Runner + learning tiers 0–6 | How to teach, not just what to log |
| 10 | `norm_*` cross-app normalization | Splunk as the SIEM, not N dashboards |
| 11 | Macros `*_index` and `*_control_block` | Customer-retargetable SPL |
| 12 | Control matrix as **measurement**, not enforcement | Honest attestation |
| 13 | CONCEPTS.md-style limitation writing | Stops overclaiming |
| 14 | Compose overlay pattern (local / external Splunk / optional Cisco) | Deployment without extra platforms |

---

## Wave 2 — Refactor (keep, but fix)

| Asset | What to fix in AgentSec |
|-------|-------------------------|
| `llm_client.py` | Honor security-profile flags; emit `run.id`; one incident per run |
| `agent_router.py` | Propagate run/incident/trace; stop implying network A2A |
| Attack Panel | Auth decision for shared labs; attach technique IDs to custom attacks; 51 vs 45 copy |
| AcmeGate / AcmeSentinel | Keep regex as **reference** controls; add tests; separate profiles |
| HITL gate | Vulnerable profile may fail open; defended profile must REQUIRE_APPROVAL |
| Campaign enrichment | Label simulated Cisco/Galileo/CTSM fields as SIMULATED |
| Splunk joins / `appendcols` | Acceptable at lab scale; document cost |
| MLTK dashboard | Optional module, not core path |
| Cisco integration | Wire enforce or delete the claim |
| Docs | Single technique count; framework mapping = not certification |

---

## Wave 3 — Redesign (keep the lesson, rewrite the mechanism)

| Lesson | AgentWatch implementation | AgentSec direction |
|--------|---------------------------|--------------------|
| MCP tool abuse | Substring gateway, no MCP server | Real tool allowlist or an honest SIMULATED lab with a tiny MCP stub |
| A2A identity | `did:acme:` regex | Explicit delegation object, or SIMULATED with labels |
| RAG exfil | Regex probes, never blocks | INV-002: retrieved text cannot authorize; optional later |
| Memory poisoning | In-process dict | Trust-tagged memory records (INV-003) |
| Orchestration bypass | Foundry marker strings | Workflow state machine (INV-006) |
| 4-agent “architecture” | One process, four prompts | Same for Phase 1 is fine if documented as sequential, not distributed |
| Test strategy | None | `tests/unit` + `tests/security` + `tests/telemetry` from day one |

---

## Drop

| Asset | Why |
|-------|-----|
| `splunk_app/App-Agentic-Compliance/` | Superseded by the canonical app |
| `phase6/8/15_bulk_rename.py` | One-shot history; they also trip the current validator |
| Pretending SIMULATED OTel is live control proof | Violates research integrity |
| SOAR `soar_simulator.py` as a control | Sleep + field injection |
| DefenseClaw / Skill Scanner embedding | Not in the repo |
| Guard env vars as if they work | They are displayed, not enforced |
| Copying 51 generic LIVE payloads | Many non–Top-10 payloads are template replay strings |
| Kubernetes, Kafka, extra databases, enterprise IAM | Forbidden by AgentSec core rules; AgentWatch already avoided most of this — keep it that way |

---

## Suggested Phase 1 slice (smallest useful scope)

After P0 decisions:

1. One app, four sequential agents, local Ollama.
2. One benign baseline request and one live attack.
3. Input control before LLM; honest output-control telemetry.
4. OTel fields including `run.id`.
5. One Splunk index, a few validated searches, no 14-dashboard import.
6. Tests for the deterministic control path.
7. A learning note for that slice.

Stop. Do not import Exercise Runner, All 51, MLTK, or Cisco until that loop is proven.
