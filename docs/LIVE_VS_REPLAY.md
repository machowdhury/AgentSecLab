# LIVE vs REPLAY

## LIVE

A **fresh experiment**. The Attack Service called the runtime **now**. You get a **new** `run.id`. Splunk Search investigates **that** UUID.

LIVE does not mean Studio tables auto-bind to your new id. Copy the id into Search.

## REPLAY

A **canonical historical specimen**. Stable `run.id` values appear in Investigate dropdowns and Path B. They exist so teaching is reproducible when you cannot or should not mint a new attack.

REPLAY **does not** mean you just executed that attack. Empty Search on a REPLAY id means this Splunk volume may not contain that specimen — not DENY.

## Why both exist

LIVE proves the loop still works. REPLAY lets a class share the same evidence shape without each student destroying the lesson timing or requiring identical model behavior.

## Published labs (curriculum)

**LIVE** (Attack Service launch): LAB-PI-001, LAB-MCP-001, LAB-RAG-CONTEXT, LAB-MEMORY-001, LAB-AGENT-GOAL-INTEGRITY-001, LAB-AGENT-DELEGATION-001, LAB-AGENTSEC-CAPSTONE-001.

**REPLAY** (no launcher on that workshop): LAB-MCP-003, LAB-MCP-004, LAB-MCP-005, LAB-MCP-CATALOG, LAB-SCANNER-RUNTIME-EVIDENCE, LAB-MCP-006.

There is **no** separate MIXED lab type in `curriculum.json`. Some LIVE dashboards also show REPLAY specimens for Investigate/Path B. Treat those ids as REPLAY unless Attack Service minted them in this session.

Official historical LIVE pairs from prior phases remain **historical evidence**. New smoke launches are **release validation**, not replacements for those pairs.
