# LIVE vs REPLAY

## LIVE

A **fresh experiment**. The Attack Service called the runtime **now**. You get a **new** `run.id`. Splunk Search investigates **that** UUID.

LIVE does not mean Studio tables auto-bind to your new id. Copy the id into Search.

## REPLAY

A **canonical historical specimen**. Stable `run.id` values appear in Investigate dropdowns and Path B. They exist so teaching is reproducible when you cannot or should not mint a new attack.

REPLAY **does not** mean you just executed that attack. Empty Search on a REPLAY id means this Splunk volume may not contain that specimen — not DENY.

## Why both exist

LIVE proves the loop still works. REPLAY lets a class share the same evidence shape without each student destroying the lesson timing or requiring identical model behavior.

## Static reasoning and simulated data

**Static / reasoning** is analysis without a fresh attack execution. L0 orientation, L4 investigation craft, L7 threat modeling, and the Mastery Check are in this class. L7 is stored in `curriculum.json` with workshop mode REPLAY because it is not a launcher. The lab adds no attack.

**Simulated** means fixture-backed or in-process data (for example retrieved documents, educational memory, or an identity claim). A fixture teaches a bounded idea. It is not a production system and not a customer incident.

## Published labs (curriculum on `develop`)

**LIVE** (Attack Service launch; seven labs): LAB-PI-001, LAB-MCP-001, LAB-RAG-CONTEXT, LAB-MEMORY-001, LAB-AGENT-GOAL-INTEGRITY-001, LAB-AGENT-DELEGATION-001, LAB-AGENTSEC-CAPSTONE-001.

**REPLAY** (no launcher): LAB-MCP-003, LAB-MCP-004, LAB-MCP-005, LAB-MCP-CATALOG, LAB-SCANNER-RUNTIME-EVIDENCE, LAB-EXTERNAL-EVALUATION-GARAK, LAB-MCP-006, LAB-BLUE-TEAM-INCIDENT-001, LAB-PRIVACY-DATA-GOVERNANCE-001, LAB-MULTI-STAGE-INCIDENT-001, LAB-ADVANCED-CAPSTONE-MASTERY-001.

LAB-THREAT-MODELING-001 is static architecture reasoning. It is not a LIVE launch.

There is **no** separate MIXED lab type in `curriculum.json`. Some LIVE dashboards also show REPLAY specimens for Investigate/Path B. Treat those ids as REPLAY unless Attack Service minted them in this session. The L5 menu label Capstone is the LIVE lending-assistant lab. Advanced Capstone is the L10 REPLAY investigation. Mastery Check is neither.

Official historical LIVE pairs from prior phases remain **historical evidence**. New smoke launches are **release validation**, not replacements for those pairs.
