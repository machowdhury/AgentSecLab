# PHASE 9D — scanner + runtime detection engineering analysis

**Date:** 2026-09-16  
**Type:** DESIGN / ANALYSIS ONLY  
**Verdict:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.5.0** unchanged  
**DET-MCP-001:** unchanged  
**New detector:** none (`DET-SCANNER-*`, `DET-MCP-CATALOG` not created)

Evidence class: 9B/9C scanner + 8D runtime = **DOCUMENTED** from LIVE field contracts. This file does **not** claim a new LIVE detection run. Pytest does **not** prove detection effectiveness.

Do not treat this as Phase 9E, a notable, Dashboard Studio, Agent Scan, rug-pull, or A2A.

---

## Security question

What behavior would a SOC actually want to detect?

Not “the scanner said HIGH.” At least:

A. scanner finds suspicious MCP metadata  
B. an agent observes that metadata  
C. a follow-on REQUEST is produced  
D. that request is DENIED  
E. that request is ALLOWED because of the lab overlay  
F. the follow-on tool starts  
G. the follow-on tool completes or fails  

These are different states. See `docs/SCANNER_RUNTIME_EVIDENCE_PLANES.md`.

---

## Evidence planes

| Plane | Question | Sourcetype |
|-------|----------|------------|
| 1 Artifact | What did static analysis say? | `agentsec:scanner:finding` |
| 2 Trust/request | Did the agent observe metadata and ask? | `otel:agentic:json` METADATA-001 + hop-1 request |
| 3 Authz/execution | Was authority granted and did execution begin? | CTRL-MCP-001 + `mcp.started`/`completed`/`failed` |

A production-quality detection must name which plane(s) it covers. 9C hunts already reconstruct each plane. 9D does not add SPL.

---

## LIVE ATTACK / RETEST evidence (from 9C, not re-ingested)

Canonical MALICIOUS description `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`. Scanner scan `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8`. Native severity **HIGH** preserved (not remapped).

| | ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` | RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` |
|--|-----------------------------------------------|-----------------------------------------------|
| Plane 1 | DETECTED_BY_SCANNER, finding_count 1 | **same artifact class / same finding** |
| Plane 2 | METADATA-001 OBSERVE `untrusted_data` | **same OBSERVE** |
| Plane 2 request | hop-1 `lookup_customer_tier` | **same request** |
| Plane 3 | ALLOW overlay + `mcp.completed_observed` | DENY `tool_not_granted` + `no_indexed_followon_execution_event` |

**Discriminator is Plane 3, not the scanner.**

NORMAL scan `b3061c4e-7a81-445c-8fd8-3108dd14c419` correlates to BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` with finding_count 0. Zero findings ≠ no scan ≠ trusted.

---

## DET-MCP-001 reuse

See `docs/SCANNER_DETECTION_MODEL.md`. 8D MEASURED 0/0/0 on A/B/C. Correct for execution-after-DENY. Silent on catalog ATTACK because there is no DENY. Silent on RETEST because there is no later `mcp.started`. Do not broaden.

---

## New detector decision

**A. DETECTION ANALYZED — NO NEW DETECTOR**

Not B: implementation is not justified. Grant snapshot is missing; overlay reason is lab-only; description-hash correlation is production-weak; scanner HIGH is not incident severity.

Not C as the overall catalog/scanner property: DET-MCP-001 is sufficient **only** for DENY-then-start.

8D’s “lab teaching detector” note on the overlay **string** stands as workshop concept, still **REJECT** as production detection (Candidate F).

---

## Correlation quality

| Use | Description SHA-256 | File SHA-256 |
|-----|---------------------|--------------|
| This lab | Sufficient (9C LIVE) | Wrong join (0 rows MEASURED) |
| Production | Weak | Different identity (whole catalog file) |

Gaps: same description on multiple tools; description edits; multiple servers/agents/invokes; scan time ≠ run time; no `gen_ai.tool.call.id`; scanner events have no `agentsec.run.id`. Do not invent correlation fields.

---

## False positives / negatives

Documented in `docs/SCANNER_DETECTION_MODEL.md` and this phase’s dedicated sections in the 9D report. Highlights: benign wording, unused scans, successful DENY, stale scans, YARA miss, rug-pull after T1, ingest loss.

---

## Severity

`finding.native_severity=HIGH` is **scanner-native**. It is not HIGH runtime incident, HIGH authz violation, or proof of execution. Any future SOC severity must be justified from Plane 3 (and a real grant snapshot), independently. No invented risk scores.

---

## Splunk ES future model (DESIGN ONLY)

If a later phase ever passed the detection gate, a finding would need: named plane(s), scanner provenance (`scanner.name`, pin hash, `scan_id`), runtime provenance (`run.id`, control id, decision), description hash (not preview as join), drilldown to `Q-SCANNER-FINDINGS` + `Q-MCP-AUTHZ`, CIM **NOT APPLICABLE**.

Do **not** create savedsearches, notables, risk events, correlation searches, or ES detections in 9D. Do not invent risk scores.

---

## Maturity

| Object | Maturity |
|--------|----------|
| Q-SCANNER-* hunts | LAB VALIDATED (9C) as hunts, not detections |
| DET-MCP-001 | LAB VALIDATED for DENY-then-start |
| Candidates A–F as detections | EXPERIMENTAL |
| Any scanner+runtime notable | **Not** PRODUCTION CANDIDATE |

To advance Candidate E: indexed grant set, integrity pin T1 vs T2, production correlation identity, FP/FN beyond one fixture, schedule/throttle, LIVE validation of the **detector** (not just hunts).

---

## Rug-pull boundary

Scan artifact at T1 vs runtime catalog at T2 is an **integrity** property (`list_changed` / pin). 9D does not implement it. Input to a later rug-pull phase: description-hash equality can hide a swapped file or a swapped description if the wrong hash is used; even the right hash is stale if the catalog moved after the scan.

---

## Existing search review

| Search | Role in 9D | Gap? |
|--------|------------|------|
| Q-SCANNER-WHO/ARTIFACT/FINDINGS | Plane 1 | None for analysis |
| Q-SCANNER-RUNTIME-CORRELATION | Plane 1∩2 hash | Does not table follow-on ALLOW/DENY (by design; reuse Q-MCP) |
| Q-MCP-AUTHZ / EXECUTED / CATALOG-AUTHORITY | Planes 2–3 | None; do not mix scanner into them |
| DET-MCP-001 | Plane 3 after DENY | Intentionally misses ATTACK B |

**No new SPL.** Combining scanner HIGH with hop-1 ALLOW in one search would be convenient and would invite a fake detector. Existing files already answer Q6 by reuse.

KO recommendations: REQUIRED none. RECOMMENDED keep hunts. OPTIONAL later workshop. DEFERRED ES, rug-pull, grant-snapshot field, DET-SCANNER.

---

## Framework mapping

Revalidated against `docs/PHASE9A_SCANNER_RESEARCH.md` and `docs/AGENTSEC_ATTACK_RESEARCH_PIPELINE.md`. No new ATLAS ids.

| Item | Status |
|------|--------|
| OWASP LLM01 (description PI class) | RELATED |
| OWASP ASI02 / ASI04 | RELATED |
| INV-002 | SUPPORTED by runtime, not by scanner |
| MITRE ATLAS | **UNMAPPED / REQUIRES REVALIDATION** (9A: atlas technique pages not verified here) |
| YARA HIGH = ASI02 proven | **Not mapped** |

---

## External tool generalization (not integrated)

```text
EXTERNAL TOOL
    → NATIVE OUTPUT
    → AGENTSEC ADAPTER
    → NORMALIZED EVIDENCE
    → SPLUNK (separate sourcetype)
    → CORRELATION WITH RUNTIME (honest join key only)
```

Applies later to Cisco AI Defense inspect APIs, Snyk Agent Scan / Invariant lineage, AI-BOM / supply-chain scanners, Foundation-Sec-8B as hunt-assist. Each keeps native severity. None become CTRL-MCP-001. 9D integrates **none** of them.

---

## Security review

| Risk | Finding |
|------|---------|
| Scanner as authority | Not designed. Decision is no detector |
| Native HIGH → incident HIGH | Forbidden; documented |
| Lab fail-open as production signal | Candidate F REJECT |
| Hash mismatch hidden | File vs description documented; wrong join 0 rows |
| Zero findings = safe | Forbidden (9C zero-finding semantics) |
| Missing evidence = clean | Forbidden |
| Splunk as enforcement | Forbidden |
| Runtime changed by scanner | Not implemented |
| Raw stdout indexed | Not in 9C contract |

No BLOCKER/HIGH design defects that require a detector to “fix.” Publishing DET-SCANNER-HIGH would **create** a HIGH defect.

---

## Tests

Contract tests preserve: no new detector, DET-MCP-001 unchanged, schema 1.5.0, no Studio, no Agent Scan, no rug-pull, no A2A. Offline pytest does not prove detection effectiveness.

---

## Stop

No detector implementation. No Dashboard Studio. No Snyk Agent Scan. No rug-pull. No A2A. Phase 9E not started.
