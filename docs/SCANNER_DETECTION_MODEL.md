# Scanner + runtime detection model (analysis only)

**Status:** Phase 9D DESIGN / ANALYSIS. **No SPL. DET-MCP-001 unchanged. No DET-SCANNER. No DET-MCP-CATALOG.**  
**Decision:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.5.0** unchanged.

Parents: `docs/MCP_CATALOG_POISONING_DETECTION_MODEL.md`, `docs/MCP005_DETECTION_VALIDATION.md`, `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

---

## Security property (SOC)

A production SOC does **not** want “YARA said HIGH.” It wants to know which of these happened:

1. A catalog artifact looks instruction-like (**artifact**).
2. An agent **consumed** that metadata (**observation**).
3. The agent **requested** an extra tool (**request**).
4. Authorization **denied** or **allowed** that request (**authz**).
5. The handler **started** (**execution**).

Collapsing 1–5 into one notable would train analysts to treat scanners as policy engines.

Primary AgentSec property remains **INV-002**: retrieved/catalog content cannot independently authorize privileged actions. DET-MCP-001 remains **INV-001-shaped**: execution after DENY.

---

## DET-MCP-001 reuse (do not edit)

Predicate: after CTRL-MCP-001 **DENY**, did `mcp.started` occur for the same `run.id` + tool?

| Specimen | Indexed story | DET-MCP-001 |
|----------|---------------|-------------|
| BASELINE A | no DENY | 0 rows (8D MEASURED) |
| ATTACK B | follow-on **ALLOW** then start | 0 rows — **no DENY to pair** |
| RETEST C | follow-on **DENY**, no later start | 0 rows — invariant holds in telemetry |

**Detects:** execution-after-DENY (MCP-002-shaped bug).  
**Intentionally misses:** catalog-poisoning ATTACK (ALLOW overlay), successful RETEST DENY, scanner findings, METADATA-001 OBSERVE.  
**Do not broaden** to “catch poisoning.” That would destroy the teaching of execution-after-DENY.

DET-MCP-001 is **sufficient for its own security property**. It is **not** sufficient for catalog poisoning or scanner correlation.

---

## Candidates A–G

### CANDIDATE A — Scanner finding exists

| Item | Analysis |
|------|----------|
| Security property | Static analyzer flagged an artifact |
| Required fields | `event.name=agentsec.scanner.finding`, native rule/severity (9C indexed) |
| Planes | 1 |
| FP | Scanner false positive; unused catalog copy; shared wording |
| FN | Novel/LLM poisoning; YARA miss; scan never ingested |
| Production generalizability | Vendor-rule dependent |
| Lab-only | Cisco 4.8.4 YARA on AgentSec fixture |
| Severity | **Keep native.** Do not copy HIGH into incident severity |
| Class | **CONTEXT / HUNT** |
| Maturity | EXPERIMENTAL as detection; LAB VALIDATED as hunt (9C) |

### CANDIDATE B — Scanner finding + matching metadata observation

| Item | Analysis |
|------|----------|
| Security property | Agent observed bytes the scanner also hashed |
| Required fields | `artifact.description_sha256`, `agentsec.content.hash`, METADATA-001 |
| Planes | 1+2 |
| FP | Same description on a different tool/server; stale scan |
| FN | Description changed after scan (rug-pull); ingest loss |
| Lab-only | Hash equality proven on 8D/9C specimens |
| Class | **HUNT / CONTEXT** (exposure). Fires on ATTACK **and** RETEST |
| Maturity | EXPERIMENTAL as detection |

### CANDIDATE C — Scanner finding + follow-on request

| Item | Analysis |
|------|----------|
| Security property | Flagged metadata preceded a follow-on **ask** |
| Planes | 1+2 |
| Distinguishes ATTACK/RETEST | **No** — both request `lookup_customer_tier` |
| Class | **HUNT** |
| Maturity | EXPERIMENTAL as detection |

### CANDIDATE D — Scanner finding + follow-on ALLOW

| Item | Analysis |
|------|----------|
| Security property | Flagged metadata and a later ALLOW |
| Planes | 1+3 |
| Distinguishes ATTACK/RETEST | Yes **in this lab** |
| FP | Legitimate grant of a tool whose description also YARA-matches; hash collision |
| Lab-only | Overlay ALLOW is not a coded grant snapshot (`allowed_tools` **not indexed**) |
| Class | **HUNT**. **REJECT** as production detection |
| Maturity | EXPERIMENTAL |

### CANDIDATE E — Scanner finding + follow-on execution

| Item | Analysis |
|------|----------|
| Security property | Flagged metadata and handler begin for a follow-on tool |
| Required fields | Scanner finding + hash + hop-1 `mcp.started` |
| Planes | 1+3 |
| Distinguishes ATTACK/RETEST | Yes in this lab (ATTACK start, RETEST none) |
| Blocker | Still does not prove the tool was **ungranted**. No indexed `allowed_tools`. No `gen_ai.tool.call.id`. Description hash ≠ artifact identity over time. |
| Class | Strongest **future research** hunt. **Not** a published detector |
| Maturity | EXPERIMENTAL. Not PRODUCTION CANDIDATE |

To become even a lab-validated detector later, a later phase would still need: grant snapshot telemetry, negative specimens beyond this fixture, time-window/schedule/throttle, and a predicate that does **not** use scanner native HIGH as SOC severity. That work is **not** justified as 9D implementation.

### CANDIDATE F — `vulnerable_profile_fail_open:metadata_derived_authority`

| Item | Analysis |
|------|----------|
| Security property | Lab overlay minted a grant from metadata |
| Required fields | CTRL-MCP-001 reason **exact string** |
| Planes | 3 (lab vocabulary) |
| Production | **Would detect AgentSec’s intentionally vulnerable fixture**, not general poisoning |
| Class | **REJECT** as production detection. Workshop **positive-control concept** only (same conclusion as 8D) |
| Maturity | LAB teaching signal, not a detector |

### CANDIDATE G — DET-MCP-001 (existing)

| Item | Analysis |
|------|----------|
| Security property | Execution after DENY |
| Planes | 3 |
| Class | **DETECTION** (already packaged, disabled) |
| Maturity | LAB VALIDATED for that invariant (3E–8D). Unchanged in 9D |

---

## Classification summary

| Candidate | DETECTION | HUNT | CONTEXT | REJECT |
|-----------|-----------|------|---------|--------|
| A scanner finding | | yes | yes | as detector |
| B + metadata | | yes | exposure | as detector |
| C + request | | yes | | as detector |
| D + ALLOW | | lab hunt only | | production |
| E + execution | | future hunt | | as detector now |
| F overlay string | | workshop control | | **production** |
| G DET-MCP-001 | **existing** | | | do not broaden |

---

## What would a later detector still need (not built)

Detection gate from `.cursor/skills/splunk-ko-review/SKILL.md`: security predicate, required telemetry, correlation contract, negative specimens, positive control, FP/FN, performance, severity, time window, schedule, throttle, LIVE validation.

**TELEMETRY GAP — QUERY NOT DEFENSIBLE** for “scanner HIGH means unauthorized execution”:

- no indexed server-owned tool grant set
- no scan-vs-call integrity pin (`list_changed` not implemented)
- description-hash join is lab-sufficient, production-weak
- scanner native HIGH is not incident severity

Do not invent those fields in 9D.

---

## Scanner semantics (locked)

Cisco mcp-scanner is evidence.

PASS != trusted.  
FAIL != DENY.  
No finding != safe.  
Finding != exploit.  
Finding != execution.  
Finding != authorization failure.  
Splunk != enforcement.
