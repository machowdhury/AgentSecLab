# Scanner search contract

**Status:** Phase 9C **VALIDATED** against live Splunk (2026-09-16).  
**Not:** notables, detectors, Dashboard Studio, CIM mapping, schema 1.5.0 fields.  
**Boundary:** SCANNER FINDING ≠ AUTHORIZATION DECISION. Splunk does not authorize.

Stored SPL: `learning/level_1/LAB-MCP-CATALOG/searches/Q-SCANNER-*.spl`.  
Catalog: `learning/level_1/LAB-MCP-CATALOG/searches/scanner_catalog.json`.  
Tokens: `__SCAN_ID__`, `__DESCRIPTION_SHA256__`.

Index: `agentsec_telemetry`. Sourcetype: `agentsec:scanner:finding` (correlation search also reads `otel:agentic:json` METADATA-001).

`earliest=0` is lab-only.

---

## Questions before searches

| ID | Question |
|----|----------|
| Q1 | Which scanner ran? |
| Q2 | What artifact did it scan? |
| Q3 | Were findings produced? |
| Q4 | What scanner-native rules/categories/severities were reported? |
| Q5 | Which runtime catalog observations correspond to the scanned artifact? |
| Q6 | For the same malicious metadata, what happened in ATTACK vs RETEST? |
| Q7 | Did scanner evidence and runtime outcome agree, disagree, or answer different questions? |

Q1→`Q-SCANNER-WHO`. Q2→`Q-SCANNER-ARTIFACT`. Q3+Q4→`Q-SCANNER-FINDINGS`. Q5→`Q-SCANNER-RUNTIME-CORRELATION`. Q6→reuse `Q-MCP-CATALOG-AUTHORITY` + `Q-MCP-AUTHZ` + `Q-MCP-EXECUTED`. Q7 is an investigation conclusion, not a detector eval.

---

## Published searches

| Query ID | Security question | Zero results means |
|----------|-------------------|--------------------|
| **Q-SCANNER-WHO** | Which scanner ran? | No indexed scan summary for that `scan_id`. Not "clean." |
| **Q-SCANNER-ARTIFACT** | What artifact was scanned? | No indexed scan summary. Not a missing finding. |
| **Q-SCANNER-FINDINGS** | Did the scan execute, and were native findings produced? | No indexed scanner events. Distinguish from finding_count=0. |
| **Q-SCANNER-RUNTIME-CORRELATION** | Which METADATA-001 rows share the description hash? | No indexed scan **and** no METADATA-001 with that hash. |

---

## Reused (unchanged)

`Q-MCP-WHO`, `Q-MCP-AUTHZ`, `Q-MCP-EXECUTED`, `Q-MCP-CATALOG-AUTHORITY`. First lines remain `sourcetype=otel:agentic:json`. Not rewritten to mix scanner fields.

---

## Rejected

| ID | Reason |
|----|--------|
| Q-SCANNER-PASS-FAIL | Collapses zero findings / missing scan / error |
| DET-SCANNER-* / DET-MCP-CATALOG | Phase 9C is investigation only |
| Q-SCANNER-FILEHASH-TO-CONTENT-HASH | Wrong hash semantics; live 0 rows |
| Q-MCP-AUTHZ-WITH-SCANNER | Would mix authorization with scanner findings |
| Q-SCANNER-SEVERITY-MAP | Would invent AgentSec severity |

---

## Authority split

| Question | Authoritative surface |
|----------|------------------------|
| Did the scanner run? | Scan-summary event + evidence pack + `dc(_raw)` |
| What did it report? | Finding events / finding_count=0 |
| Did the handler run? | Runtime `handler_invoke_count` / `Q-MCP-EXECUTED` |
| Was the follow-on ALLOW/DENY? | CTRL-MCP-001 (`Q-MCP-AUTHZ`) |
| Did Splunk receive scanner events? | `dc(_raw)` vs local normalized count |

Scanner HIGH did not authorize ATTACK. Scanner silence on NORMAL did not make BASELINE "trusted."
