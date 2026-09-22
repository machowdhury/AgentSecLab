# AgentSec curriculum levels

**Status:** DESIGN (Phase 15A). Ordered by **learning dependency**, not implementation phase number.  
**Do not start Phase 15B from this file.** Do not treat this as a nav implementation.

**Phase 16A note (historical file):** Current LIVE path and three-level academy model live in `docs/AGENTSEC_LEARNING_LEVELS.md` and `docs/PHASE16A_CURRICULUM_INTEGRATION.md`. This 15A file still defines **grant-anatomy order** (MCP-003/004 before INV-002 workshops). Rows below that say RAG/memory/identity are “REPLAY today; LIVE later” are **stale** as of 15B–15E — do not silently rewrite the tables.

The Phase 8A outline that lumped MCP-001–006 as “Level 1 complete” is superseded for teaching order. Those labs remain implemented; the **journey** is now dimensional.

---

## Level 0 — Orientation

**Home / DESIGN EXERCISE / REFERENCE.** No attack required.

**KNOW:** What an AI agent, LLM, tool, MCP, RAG, memory, identity, delegation, telemetry, control, invariant, hunt, and detection are; what Splunk does in AgentSec (evidence workbench).  
**DO:** Open AgentSec Home; name the four platform roles (Studio, Search, Attack Service, runtime).  
**INVESTIGATE:** Nothing required. Optional: run a canned Home search if present.  
**EXPLAIN:** Splunk does not enforce AgentSec authorization.  
**DEFEND:** Not yet — identify that defense will be a runtime control.  
**PROVE:** Nothing experimental.  
**AVOID:** “I completed AgentSec because I opened every dashboard.”

**Labs:** Home (`ws_agentsec_home`).  
**Mode:** DESIGN EXERCISE + REFERENCE.

---

## Level 1 — Trusting input

**Core idea:** Untrusted input cannot silently redefine authority.

**KNOW:** Prompt vs policy; CTRL-INPUT-001 is a regex PDP before the LLM; vulnerable vs secure profile.  
**DO:** Launch ATK-002 via Attack Service (LIVE) or inspect REPLAY. Capture `run.id`. Predict before launch.  
**INVESTIGATE:** Filter `run.id`; find `control.decision`; find whether `llm.call` executed; do not treat missing rows as prevention.  
**EXPLAIN:** Why the same user text can ALLOW or DENY depending on profile, and why ALLOW is not proof the model obeyed.  
**DEFEND:** CTRL-INPUT-001 on the loan path; Splunk is the copy.  
**PROVE:** For this `run.id`, whether the control ran before the LLM and whether execution started.  
**AVOID:** “Splunk blocked the prompt”; “no event means blocked”; “RETEST proves all injections fail.”

**Labs:** LAB-PI-001 (14E reference).  
**Mode:** LIVE + REPLAY. SIMULATED only where labeled (Q-LLM-AFTER-DENY).  
**Splunk skill:** find a run, read sequence, interpret `control.decision`.

---

## Level 2 — Tool authority (dimensional grant)

**Core idea:** Request ≠ grant. Grant is **tool, then scope, then resource** — not a boolean “MCP is allowed.”

**KNOW:** CTRL-MCP-001 is the tool PDP; `POST /mcp/invoke` is not a grant; catalog-valid ≠ granted.  
**DO:** Launch MCP-002 (ungranted tool) LIVE on MCP-001; later launch MCP-003 and MCP-004 specimens once migrated.  
**INVESTIGATE:** Who / authz / tool / executed / after-deny; then scope; then resource.  
**EXPLAIN:** Why a granted tool can still DENY or ERROR at scope or resource.  
**DEFEND:** Server-owned tool policy — not Studio, not the model, not the catalog string.  
**PROVE:** Whether the handler started using runtime + complete evidence.  
**AVOID:** “DENY means Splunk blocked MCP”; collapsing tool/scope/resource into one question.

**Labs:** LAB-MCP-001 (14E reference) → LAB-MCP-003 → LAB-MCP-004.  
**Mode today:** MCP-001 LIVE+REPLAY; 003/004 REPLAY + operator LIVE until Attack Service migration.  
**Why this order:** 14E already taught tool-level REQUEST≠GRANT. Scope and resource are the same PDP and same HTTP entry. Catalog/result (INV-002) wait until grant anatomy is solid.

---

## Level 3 — Tool ecosystem trust

**Core idea:** Discovery, metadata, output, and scanner findings are not authority.

**KNOW:** INV-002; OBSERVE classifiers; NORMAL ≠ SAFE; SCANNER FINDING ≠ AUTHORIZATION.  
**DO:** Inspect result-derived, catalog-derived, and scanner-correlated runs (LIVE when migrated, else REPLAY).  
**INVESTIGATE:** Correlate prior authorized call or catalog hash with follow-on MCP decision; join scanner sourcetype to runtime `run.id` without treating join as grant.  
**EXPLAIN:** Why a legitimate first call can still be followed by a DENY; why a scanner finding is corroborative.  
**DEFEND:** CTRL-MCP-001 remains the grant. METADATA/RESULT/scanner never grant.  
**PROVE:** Follow-on tool grant/deny and classifier labels; not “the scanner blocked the tool.”  
**AVOID:** New DET-* for every suspicious string; “metadata poisoning = malware.”

**Labs:** LAB-MCP-005 → LAB-MCP-CATALOG → LAB-SCANNER-RUNTIME-EVIDENCE.  
**Mode:** REPLAY (and historical LIVE packs). Scanner is not an Attack Service lab.  
**Note:** Catalog is **not** Wave 1. It is INV-002; it depends on knowing what a grant is.

---

## Level 4 — Context security (RAG)

**Core idea:** Retrieved content is data.

**KNOW:** Retrieval is not authorization; untrusted ≠ malicious; RAG classifier is OBSERVE.  
**DO:** Retrieve then follow-on tool path (when launcher exists) or reconstruct from two event families in Splunk.  
**INVESTIGATE:** `rag.*` fields + CTRL-RAG-CONTEXT-001 + CTRL-MCP-001 on the same `run.id`.  
**EXPLAIN:** EchoLeak-class *pattern* as REFERENCE, not as “AgentSec reproduced EchoLeak.”  
**DEFEND:** Tool PDP after retrieval; optional retrieval filters are not this lab’s claim.  
**PROVE:** Retrieved text did or did not create a grant.  
**AVOID:** “The document authorized the tool.”

**Labs:** LAB-RAG-CONTEXT.  
**Mode:** REPLAY today; LIVE later (moderate Attack Service: retrieve→invoke).

---

## Level 5 — Persistent state

**Core idea:** Persistence does not create trust.

**KNOW:** INV-003; write run ≠ recall run; recalled text is data.  
**DO:** Reconstruct write → later recall → tool request across `run.id`s.  
**INVESTIGATE:** Memory hashes, `memory.trust`, OBSERVE, follow-on MCP.  
**EXPLAIN:** Why a later run can request a privileged tool without a new user attack in that run.  
**DEFEND:** Memory classifier + MCP PDP; not “delete Splunk events.”  
**PROVE:** Recalled content influenced a request; it did not mint a grant.  
**AVOID:** “The agent remembered it, so it was policy.”

**Labs:** LAB-MEMORY-001.  
**Mode:** REPLAY today; LIVE later (two linked launches).

---

## Level 6 — Agent authority (deputy, then identity)

**Core idea:** Identity/delegation claims cannot mint authority. Deputy ambient ≠ caller grant.

**KNOW:** MCP-006 (confused deputy, CTRL-DELEGATION-001) is **not** the same lab as A2A-001 (CTRL-IDENTITY-001).  
**DO:** Reconstruct caller → deputy → MCP (006); then Agent A → Agent B identity claims (delegation lab).  
**INVESTIGATE:** Delegation fields then MCP; identity claims then MCP.  
**EXPLAIN:** Claim ≠ authentication; claim ≠ grant.  
**DEFEND:** Delegation/identity classify or bind; MCP still grants tools.  
**PROVE:** Whether the follow-on tool was granted from **coded** policy, not from the claim.  
**AVOID:** Collapsing 006 and identity into one “A2A lab”; implying live A2A transport.

**Labs:** LAB-MCP-006 (has Studio) then LAB-AGENT-DELEGATION-001 (Splunk only until a workshop exists).  
**Mode:** REPLAY / DESIGN EXERCISE for identity until Studio + launcher.

---

## Level 7 — Intent / goal integrity

**Core idea:** Authorized tool ≠ authorized use of the tool.

**KNOW:** INV-006; CTRL-GOAL-INTEGRITY-001 is not CTRL-MCP-001; goal DENY ≠ MCP DENY.  
**DO:** Same granted `lookup_policy`, unauthorized task expansion.  
**INVESTIGATE:** Goal decision then MCP decision then execution.  
**EXPLAIN:** Why tool-level ALLOW can still be the wrong task.  
**DEFEND:** Goal integrity then tool PDP.  
**PROVE:** Task was/wasn’t authorized; tool grant is a separate fact.  
**AVOID:** “Goal DENY means MCP blocked it”; “ML should decide the goal.”

**Labs:** LAB-AGENT-GOAL-INTEGRITY-001.  
**Prerequisites:** Level 2 (know what a tool grant is). Goal workshop already exists; **migration** waits until learners have dimensional MCP + at least one INV-002 lab, unless used as a DESIGN EXERCISE earlier.

---

## Level 8 — Cross-domain investigation

**DESIGNED, not implemented.** Mixed workflow without naming the failing domain. See `docs/AGENTSEC_CAPSTONE_DESIGN.md`.

---

## Level 9 — Purple team / capstone

**DESIGNED, not implemented.** ATTACK → OBSERVE → HUNT → DEFEND → RETEST → PROVE on a mixed chain, equivalent-input check, hunt vs detection call.

---

## Why not the 14A candidate wave (catalog + result first)?

Catalog and result are conceptually adjacent to MCP-001, but they teach **INV-002**, not grant anatomy. A learner who has only seen “ungranted tool name” will misread catalog OBSERVE as a second PDP. Scope and resource keep the same control and the same invoke path; they complete REQUEST≠GRANT before DATA≠AUTHORITY.

Scanner stays after catalog because it is an evidence plane, not a third grant dimension.

Identity stays after MCP-006 so “delegation” is not one overloaded word.

Goal stays after tool authorization because the whole point is **authorized tool, unauthorized task**.
