# Phase 16D — AgentSec Academy P0/P1 remediation

**Status:** IMPLEMENTATION + VALIDATION (academy packaging only).  
**Date:** 2026-09-21.  
**Schema:** 1.9.0 UNCHANGED.  
**Authorization:** UNCHANGED (`coded_policy()`, CTRL-MCP-001, overlays, fixtures).  
**STOP:** Do not start Phase 17A from this file.

Phase 16C remains the audit authority. This phase implements only the P0/P1 items in `docs/PHASE16D_P0_P1_IMPLEMENTATION_MATRIX.md`. It does not add a security domain.

---

## What 16D is

A learner with basic cybersecurity knowledge should enter AgentSec, understand the environment, follow a deliberate curriculum, investigate in Splunk Search, and reach the integrated capstone without repository knowledge.

The technical loop is unchanged:

LEARN → UNDERSTAND THE TRUST BOUNDARY → PREDICT → LAUNCH ATTACK → OBSERVE → INVESTIGATE IN SPLUNK → OPTIONAL SOLUTION → UNDERSTAND THE CONTROL → DEFEND → RETEST → COMPARE → PROVE → CONNECT

Studio is the syllabus. Attack Service is a closed launcher. AcmeBank is enforcement. Splunk Search is the notebook. Splunk is not a PDP.

---

## What 16C found (not rewritten)

P0: Home copy was false (identity “not published”; capstone omitted). Nav placed capstone before Goal/Identity.

P1: no L0 orientation; LIVE vs REPLAY unmarked on Home; Path B undisclosed on LIVE INVESTIGATE; REPLAY labs had no try-first prompt; assessment not in product.

Those findings stay true of the 16C snapshot. 16D remediates the product, not the audit documents.

---

## What shipped

1. **Academy Home** (`ws_agentsec_home`) — START / ORIENT / PATH / SPLUNK. Primary action: Direct Prompt Injection. Identity and capstone are listed. LIVE vs REPLAY labeled per lab.
2. **Curriculum navigation** — Foundations → Context Security → Agent Intent → Capstone. Human titles. No top-level `LAB-*` / `ws_lab_*`.
3. **Curriculum metadata** — `learning/academy/curriculum.json` with `not_authorization=true` and schema_version 1.9.0 (telemetry schema, not a bump).
4. **Path A/B disclosure** on LIVE workshops; capstone Path B is a review key.
5. **REPLAY HUNT banners** — try Search first; bound tables are Path B.
6. **CONNECT scaffolding** after major LIVE labs (YOU JUST LEARNED / THIS CONNECTS TO / NEXT).
7. **Attack Service** educational “Where you are” strip + explicit attacker-does-not-control / server-owned facts. Allowlist unchanged.
8. **Capstone** “Before you start” gate + PROVE Debrief. Not another random lab.
9. **Assessment** — Home CHECK plus existing PROVE prompts. No leaderboard, no scoring backend.

---

## Predecessor regression (not re-run LIVE)

Existing validated LIVE domains remain registered: PI, MCP-001, RAG, Memory, Goal Integrity, Identity/Delegation, capstone. Historical `run.id`s remain historical. 16D did not mint official pairs and did not rewrite packs.

---

## Security semantics that must survive

CTRL-INPUT-001, CTRL-RAG-CONTEXT-001, CTRL-MEMORY-CONTEXT-001, CTRL-IDENTITY-001, CTRL-GOAL-INTEGRITY-001, and CTRL-MCP-001 are unchanged. OBSERVE is not ALLOW. ALLOW is not execution. Splunk is not enforcement. BASELINE is not SAFE. Detector silence is not SAFE. Learning metadata is not policy.

See `docs/PHASE16D_SECURITY_SEMANTICS_REVIEW.md`.

---

## Verdict

See the end of this phase’s chat report. Pytest offline is necessary and not sufficient. UI review of changed surfaces is required. Do not start 17A, detectors, MLTK, real A2A, or a schema bump from this file.
