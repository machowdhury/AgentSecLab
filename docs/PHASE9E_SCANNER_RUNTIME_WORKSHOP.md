# Phase 9E — Scanner + runtime evidence workshop

**Date:** 2026-09-16  
**View:** `ws_lab_scanner_runtime_evidence`  
**Verdict:** PASS — SCANNER / CATALOG CHAPTER COMPLETE FOR THE DESIGNED PHASE 8A–9E PATH. This file does not authorize Phase 10, Agent Scan, rug-pull, or A2A.

## Purpose

Teach learners how a SOC combines external scanner evidence with runtime metadata, authorization, and execution evidence without collapsing those planes.

LAB-MCP-CATALOG already exists. Phase 9E does **not** create another catalog-poisoning runtime.

Learner question: when an external security scanner flags agent/tool metadata, what can the SOC actually conclude from that evidence?

## Hard stops (observed in this phase)

- No runtime authorization change
- No CTRL-MCP-001 / CTRL-MCP-METADATA-001 / schema 1.5.0 change
- No DET-MCP-CATALOG, DET-SCANNER-HIGH, DET-MCP-005
- DET-MCP-001 unchanged
- No invented findings, fields, or attack specimens
- No Agent Scan, no rug-pull, no A2A, no MCP-007, no Phase 10

## Evidence used (validated earlier)

Runtime BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d`  
Runtime ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4`  
Runtime RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`  
Scanner NORMAL `b3061c4e-7a81-445c-8fd8-3108dd14c419`  
Scanner MALICIOUS `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8`  
NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`  
MALICIOUS hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

ATTACK and RETEST share the malicious description hash.

## Workshop flow

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

## Evidence-plane model

PLANE 1 artifact (Cisco mcp-scanner).  
PLANE 2 runtime trust / request (METADATA-001).  
PLANE 3 authorization / execution (CTRL-MCP-001).

SCANNER FINDING != AUTHORIZATION DECISION. ZERO FINDINGS != SAFE.

## Dashboard

GRID 1440 / 12. Tokens: Hunt, Hunt scan, BASELINE RUN, ATTACK RUN, RETEST RUN, NORMAL SCAN, MALICIOUS SCAN. Hunt defaults to BASELINE. Hunt scan defaults to NORMAL.

Searches reused (bind only): Q-SCANNER-WHO, Q-SCANNER-ARTIFACT, Q-SCANNER-FINDINGS, Q-SCANNER-RUNTIME-CORRELATION, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-CATALOG-AUTHORITY, Q-MCP-AFTER-DENY, DET-MCP-001-POSITIVE-CONTROL (SIMULATED).

Rebuild: `python3 scripts/build_lab_scanner_runtime_evidence_dashboard.py`

## Detection teaching

DETECTION ANALYZED — NO NEW DETECTOR.

DET-MCP-001 ATTACK = 0 because no DENY occurred.  
DET-MCP-001 RETEST = 0 because DENY occurred but no later mcp.started.

## UI / KO

Pass-1 HIGH: LEARN inequality line clipped. Fixed as per-line bullets. Pass-2: 10/10 tabs, 7/7 tokens. KO review: PUBLISH, bind-only, no new detector.

## Contract tests

`.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` → 508 passed, 2 deselected.

## Limitations

- Pytest does not prove Splunk rendering.
- Playwright captures the first Studio canvas; GRID below the fold may clip.
- Seven global inputs may ellipsize UUIDs; full ids are on LEARN.
- No WCAG certification.
- Scanner HIGH is identical on ATTACK and RETEST, so it cannot discriminate authorization.

## Stop

**PHASE 9E VERDICT: PASS**

SCANNER / CATALOG CHAPTER: COMPLETE FOR THE DESIGNED PHASE 8A–9E PATH.

Runtime: VALIDATED. Splunk: VALIDATED. Cisco mcp-scanner: STATIC INTEGRATED + LOCALLY VALIDATED + SPLUNK CORRELATED. Detection: ANALYZED — NO NEW DETECTOR. Workshop: VALIDATED.

Phase 10 not started. No Agent Scan. No rug-pull. No A2A.
