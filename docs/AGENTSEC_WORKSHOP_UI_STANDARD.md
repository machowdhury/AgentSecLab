# AgentSec Workshop UI Standard

**Status:** Required for new LEARN → PROVE workshops unless a documented semantic reason requires deviation.  
**Date:** 2026-09-24
**Do not copy Goal Integrity evidence planes onto RAG, Memory, Scanner, Identity, or MCP.**

Reuse visual grammar. Preserve each domain’s controls and evidence.

---

## Shell

Header (LEVEL 1–3):

- Human title
- One-sentence purpose
- LIVE/SIMULATED · `LAB-id` · schema

Then Studio tabs:

LEARN | BASELINE | ATTACK | OBSERVE | HUNT | DETECT | DEFEND | RETEST | COMPARE | PROVE

`submitButton`: false. `submitOnDashboardLoad`: true.

Hunt control title: **Investigate specimen** (`input.dropdown`). Memory uses write + recall. Scanner uses specimen + scan.

Canonical BASELINE / ATTACK / RETEST searches bind literal validated run.id values at build time.

---

## Page standards

**LEARN** — security question card, short decision path, distinctions as readable inequalities, evidence identity, domain planes. No wall of text.

**BASELINE / ATTACK / RETEST** — structured specimen cards answering: input, profile, decision, authorization, execution, authoritative evidence, conclusion. Full run.id on the card.

**OBSERVE** — evidence-plane / sequence view. No `_raw` by default. Hunt dropdown selects the copy.

**HUNT** — SOC investigation. Security question, primary hunt, supporting hunts. SPL is secondary. Custom run.id → Search (Studio limitation).

**DETECT** — CONTEXT / HUNT / DETECTION / FUTURE / REJECTED. Do not manufacture a detector because a tab exists. Preserve `0 DET-MCP-001 rows != SAFE` where that hunt is shown.

**DEFEND** — actual control boundary. Incorrect defenses stay small.

**COMPARE** — three aligned cards, same rows: profile, input, trust, proposed action, security decision, authorization, effective action, execution, handler count, run.id. Emphasize SAME vs DIFFERENT in text.

**PROVE** — what we can prove, cannot prove, authoritative vs corroborative, knowledge check, limitations.

---

## MCP reference workbench pattern

`LAB-MCP-001` is the post-RC1 reference implementation for a compact experiment workbench. It does **not** authorize automatic propagation to other labs.

Attack Service order:

1. Security question and compact trust context
2. Closed ATTACK / RETEST controls
3. Prominent current `run.id`
4. `PRINCIPAL → AGENT → REQUEST → AUTHORIZATION → EXECUTION → EVIDENCE`
5. Aligned ATTACK ↔ RETEST comparison
6. Splunk handoff
7. `Evidence / Advanced` progressive disclosure

Studio order:

1. **MISSION** — question, boundary, mode, control, evidence source
2. **INVESTIGATE** — Path A and `WHO → REQUEST → AUTHZ → EXECUTION → EVIDENCE`
3. **EVIDENCE** — supporting fields and ATTACK ↔ RETEST
4. **PATH B · ANSWERS** — optional answer material using existing validated Q-* searches

The browser still submits only `lab_id`, `specimen_id`, `mode`, and `execution`. Runtime handler count remains authoritative for MCP non-execution. Splunk absence is corroborative only after completeness is measured.

---

## Context Security specialization

The compact workbench grammar generalizes to RAG and Persistent Memory, but the MCP evidence chain does not.

Shared Attack Service grammar:

1. Domain security question
2. Attacker influence and server-owned facts
3. Closed ATTACK / RETEST controls
4. Prominent server-owned correlation IDs
5. Domain-specific evidence chain
6. Precise ATTACK ↔ RETEST comparison
7. Splunk handoff
8. `Evidence / Advanced`

RAG uses:

`SOURCE → RETRIEVAL → CONTEXT → CONTEXT CONTROL → AGENT EFFECT → TOOL AUTHORIZATION → EXECUTION → EVIDENCE`

It must keep `RETRIEVED != TRUSTED`, `PROVENANCE != AUTHORITY`, and context OBSERVE separate from later MCP authorization.

Persistent Memory uses:

`WRITE RUN → PERSIST → RECALL RUN → source_run_id → MEMORY CONTROL → INFLUENCED REQUEST → TOOL AUTHORIZATION → EXECUTION`

It must make time and cross-run causality visible. The primary RECALL count must not absorb sibling WRITE events.

For the reviewed RAG and Memory Studio workshops, the compact order is MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS. Path A remains primary. Existing validated Q-* SPL is reused unchanged. Legacy LEARN→PROVE detail may remain in Path B, but it must not dominate the initial investigation.

Fingerprint equality is always scoped to the exact hashed object. It never means the entire experiment is identical.

---

## Goal Integrity exemplar (do not clone the evidence model)

Distinctions that must remain readable:

AUTHORIZED TOOL != AUTHORIZED GOAL  
AUTHORIZED TOOL != AUTHORIZED USE OF TOOL  
REQUEST != GRANT  
OBSERVE != ALLOW  
ALLOW != EXECUTION  
SPLUNK != ENFORCEMENT

Defense does not mean block `lookup_policy`.

Goal workbenches must report execution by security meaning, not only by total handler count. Show the permitted supporting operation and prohibited objective separately. A defended RETEST may execute a permitted operation; that fact is not automatically a defense failure.

Recommended chain:

`GOAL → PROPOSED ACTION → GOAL CONTROL → EFFECTIVE ACTION → TOOL AUTHORIZATION → OPERATION-SPECIFIC EXECUTION → EVIDENCE`

---

## Identity / Delegation specialization

Identity strings and delegation fields need explicit assurance labels:

- **CLAIMED** — principal, caller, callee, and delegation supplied by the closed request fixture
- **ESTABLISHED IN LAB** — exact fixture/fingerprint, coded policy, control output, and runtime count
- **NOT MODELED** — cryptographic authentication, signed delegation, OAuth/OIDC, mTLS/PKI, or production workload identity

Do not style a claim as though it were authenticated. Keep `CTRL-IDENTITY-001 OBSERVE` separate from the tool PDP:

`CLAIM → DELEGATION → CLAIM CONTROL → REQUEST → TOOL AUTHORIZATION → EXECUTION → EVIDENCE`

The default viewport must expose `IDENTITY CLAIM != AUTHENTICATION`, `DELEGATION CLAIM != AUTHORIZATION`, and any authentication gap.

---

## Builder helper

Shared helpers live in `scripts/agentsec_studio.py` (`specimen_dropdown`, `bind_literal`, `bind_run_id`, `workshop_header`, `EMPTY_STANDARD`, `write_studio_xml`).

Hunt SPL files stay validated. UI binding is substitution only.

---

## Runtime evidence levels

Where a workshop discusses a governed operation, keep these states distinct:

- **REQUESTED** — request/tool fields exist.
- **AUTHORIZED** — the PDP returned ALLOW.
- **INVOKED** — the runtime entered the ToolRegistry invocation path; a process-local invocation count may establish this.
- **COMPLETED** — `mcp.completed` and a successful hop/outcome exist.
- **FAILED** — `mcp.failed` and an error hop/outcome exist after invocation.
- **OUTCOME** — the application-specific security-sensitive result is supported by result evidence.

`REQUESTED != AUTHORIZED != INVOKED != COMPLETED != OUTCOME`.

An invocation count that increments before the handler body does not by itself prove successful completion. An authorization event's `attempted` / `executed` values are event-local unless a query explicitly reconstructs later runtime events.

---

## Phase 14A overlay (DESIGN — not implemented)

Do not add Studio views in 14A. When a later phase implements guided investigation, keep this shell and add copy only:

**ATTACK (before launch or before opening ATTACK evidence)** must include: ATTACK OBJECTIVE, WHY THIS MATTERS, WHAT WILL CHANGE, WHAT WILL NOT CHANGE, WHAT I EXPECT TO SEE, WHAT SECURITY PROPERTY IS BEING TESTED.

**HUNT** should offer Path A (Open Search) before Path B (Show solution). Reuse `Q-*`. No GFM tables in `splunk.markdown`.

**CONNECT** is a PROVE subsection (invariants, adjacent labs, verified framework notes, residual uncertainty). It is not a new top-level nav item and not a detector.

Launch stays on Attack Service via link, not a Studio POST. Phase 14B ships the Attack Service predict + LIVE BASELINE/ATTACK surface; Studio copy is unchanged. Visual language remains `docs/AGENTSEC_UI_DESIGN_SYSTEM.md`.
