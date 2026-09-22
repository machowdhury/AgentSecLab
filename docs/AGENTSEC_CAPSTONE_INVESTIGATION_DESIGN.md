# Capstone investigation design

**Status:** DESIGN ONLY. No new Q-* or DET-* in Phase 16A.  
**Do not start Phase 16B from this file.**

Studio = syllabus / evidence explainer. **Splunk Search = notebook.**  
Path A: security question + index/sourcetype + `run.id` (or write/recall pair) + optional Hint 1/2. Learner writes SPL.  
Path B: copyable existing Q-* SPL + expected shape + meaning + **does not mean** + security-model link + next question.

Do not replace Search with a prebuilt “answer dashboard.”

Reuse existing hunts. Do not author new SPL in 16A unless a design test requires a citation.

---

## Shared starter

- Index: `agentsec_telemetry`
- Sourcetype: `otel:agentic:json`
- Correlation: quoted `agentsec.run.id` (memory: write id **and** recall id / `source_run_id`)
- Hint 1 (typical): start from `Q-RUN-EVENTS` on the given id
- Hint 2: do not search `index=*`

---

## Investigations (16)

### 1. Find the experiment — CAP-I1

**Security question:** Which experiment ids belong to this incident, and are they LIVE or REPLAY?  
**Reuse:** Q-RUN-EVENTS  
**Path B does not mean:** Completeness, prevention, or that Studio launched it.

### 2. Reconstruct sequence — CAP-I2

**Security question:** What happened, in runtime `sequence` order?  
**Reuse:** Q-RUN-EVENTS  
**Look for:** retrieve, memory write/recall, control.decision, mcp.*  
**Does not mean:** `_time` order is authoritative.

### 3. Identify sources — CAP-I3

**Security question:** What untrusted bytes entered (document, memory body, user prompt, claim)?  
**Reuse:** Q-RAG-CONTEXT-AUTHORITY and/or Q-MEMORY-CONTEXT-AUTHORITY  
**Does not mean:** Source is malicious. Untrusted ≠ malicious.

### 4. Trust boundaries — CAP-I4

**Security question:** Which trust boundaries did those bytes cross?  
**Teaching:** retrieve→classifier; store→recall; request→CTRL-MCP-001.  
**Reuse:** domain hunts + Q-MCP-AUTHZ  
**Does not mean:** Crossing a boundary is a breach.

### 5. Provenance — CAP-I5

**Security question:** What ids/hashes attribute the bytes (document.id, memory.id, content.hash, source_run_id)?  
**Reuse:** RAG/memory hunts  
**Inequality:** PROVENANCE ≠ TRUST.

### 6. Influence — CAP-I6

**Security question:** Did retrieved or recalled text shape the later tool request?  
**Reuse:** Q-RAG-CONTEXT-AUTHORITY, Q-MEMORY-CONTEXT-AUTHORITY  
**Does not mean:** Influence is a grant. RETRIEVED CONTENT ≠ AUTHORITY. STORED MEMORY ≠ TRUSTED INSTRUCTION.

### 7. Authoritative task — CAP-I7

**Security question:** What task was server-owned, if any?  
**Reuse:** Q-GOAL-INTEGRITY-AUTHORITY  
**Expected honest outcome:** **No goal events** (or only in-task). Absence → do not invent a goal failure. NOT PROVEN that goal caused the incident.

### 8. Proposed goal — CAP-I8

**Security question:** Was an unauthorized task proposed (`extract_full_policy` family)?  
**Reuse:** Q-GOAL-INTEGRITY-AUTHORITY  
**Expected:** Not in this packet. INCORRECT to claim GOAL DENY if no goal control row.

### 9. Caller / callee — CAP-I9

**Security question:** Did an identity/delegation claim appear?  
**Reuse:** Q-AGENT-DELEGATION-AUTHORITY  
**Expected:** Not in this packet. IDENTITY CLAIM ≠ AUTHENTICATION still holds as a **rule**, but this incident is not a claim incident.

### 10. Requested tool — CAP-I10

**Security question:** What tool/scope/resource was requested?  
**Reuse:** Q-MCP-WHO, Q-MCP-TOOL  
**Does not mean:** Requested = granted.

### 11. Actual grants — CAP-I11

**Security question:** What did `coded_policy()` grant to the acting agent?  
**Reuse:** Q-MCP-AUTHZ  
**Inequality:** REQUEST ≠ GRANT. CALLER ID ≠ GRANT.

### 12. Authorization decision — CAP-I12

**Security question:** Which control decided, and ALLOW / DENY / OBSERVE?  
**Reuse:** Q-MCP-AUTHZ; RAG/memory OBSERVE rows  
**Must teach:** OBSERVE ≠ ALLOW. Two control ids may appear; only CTRL-MCP-001 is the tool PDP.

### 13. Execution — CAP-I13

**Security question:** Did the handler start?  
**Reuse:** Q-MCP-EXECUTED, Q-MCP-AFTER-DENY  
**Runtime counts remain authoritative.** ALLOW ≠ EXECUTION. DENY ≠ PROOF OF NON-EXECUTION without execution evidence. MISSING EVENT ≠ PREVENTION.

### 14. Cross-run memory — CAP-I14

**Security question:** Which write `run.id` produced the recall that influenced this request?  
**Reuse:** Q-MEMORY-CONTEXT-AUTHORITY  
**Does not mean:** Persistence is trust.

### 15. ATTACK vs RETEST — CAP-I15

**Security question:** What changed when defense changed, given equivalent adversarial bytes?  
**Reuse:** same hunts on both ids; COMPARE pedagogy from 14E  
**Does not mean:** RETEST ≠ UNIVERSAL SECURITY. BASELINE ≠ SAFE.

### 16. Enforcement, proof, unknowns — CAP-I16

**Security question:** Where was enforcement performed? What can Splunk prove? What remains unknown?  
**Reuse:** Q-MCP-AFTER-DENY + PROVE tab pattern  
**Must state:** SPLUNK ≠ ENFORCEMENT. HEC ACCEPTANCE ≠ SEARCHABLE EVIDENCE. ANOMALY ≠ INCIDENT. Overlay is a **lab** fail-open. WHO AUTHENTICATED remains NOT PROVEN (no auth stack). HITL not in path.

---

## Path A / Path B

Every item above is Path A first. Path B binds the listed Q-* (already in `learning/level_1/**/searches/`). Capstone Path B should be **review-gated** (skill progression: advanced/capstone), not a first click — pedagogy only, not an access-control feature.

## Hunt vs detection

If the learner proposes a new detector: require them to classify CONTEXT / HUNT / DETECTION / REJECTED. Capstone default: **HUNT**. DET-MCP-001 still does not fire on overlay-ALLOW ATTACK. 0 notable rows ≠ SAFE.
