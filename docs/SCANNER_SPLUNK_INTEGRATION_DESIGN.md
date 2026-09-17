# Scanner Splunk integration design

**Status:** Phase 9A DESIGN ONLY. **No SPL. No detections. No Dashboard Studio. No invented indexed fields.**  
**Parents:** `docs/SCANNER_EVIDENCE_MODEL.md`, `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

Apply the AgentSec Splunk engineering rule and run splunk-ko-review for all new or materially changed Splunk knowledge objects **when a later phase writes them**. This file is not that phase.

---

## Index vs sourcetype

| Option | Verdict |
|--------|---------|
| New index for scanners | **Not first.** Extra operational surface for a local lab; no retention/volume evidence yet |
| Same index `agentsec_telemetry` + **separate sourcetype** | **RECOMMENDED** |

**Candidate conceptual sourcetype:** `agentsec:scanner:finding`

Not implemented. Not added to `props.conf` in this phase.

Reasons for same index + new sourcetype:

- Lab already investigates in `index=agentsec_telemetry`
- Sourcetype isolation prevents scanner JSON from being parsed as `otel:agentic:json`
- Learners can still `| tstats` / filter by sourcetype
- Avoids CIM-forcing two indexes to look “enterprise”

Do **not** send scanner JSON through the existing OTel → `otel:agentic:json` pipeline.

---

## Existing inventory (do not reuse as scanner KOs)

From `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md` (8E):

- Index: `agentsec_telemetry`
- Sourcetype: `otel:agentic:json` only
- No lookups, data models, event types, or tags packaged
- Q-MCP-* are schema-version agnostic runtime hunts
- DET-MCP-001 is the only detector (disabled)
- No DET-MCP-CATALOG

Scanner evidence must not be stuffed into Q-MCP-AUTHZ, Q-MCP-CATALOG-AUTHORITY, or DET-MCP-001. Those answer **runtime** questions.

CIM: AgentSec `agentsec.*` fields are often **CIM NOT APPLICABLE**. Scanner findings (YARA rule hits, vendor risk names) are also **not** a CIM data model. Do not invent `IDS:Attack` mapping for a catalog YARA hit.

---

## Field-contract gate (before any future SPL)

Required order (`.cursor/rules/33-splunk-agent-skills.mdc`):

```text
SECURITY / OPERATIONAL QUESTION
→ EVIDENCE REQUIREMENT
→ VALIDATED TELEMETRY
→ INDEXED FIELD DISCOVERY
→ FIELD CONTRACT
→ KNOWLEDGE OBJECT DESIGN
→ SPL
```

If 9B only writes files to `artifacts/`, Splunk has **no** scanner telemetry. Then: `TELEMETRY GAP — QUERY NOT DEFENSIBLE`. File evidence is still valid as OBSERVED_SCANNER on disk.

Do not invent indexed fields in this design. After first ingest, discover what Splunk actually extracts.

---

## Future investigation questions (not queries)

These are the questions a later hunt must earn the right to answer:

1. Which artifact was scanned? (hash + path in the pack)
2. Which scanner found what? (scanner identity + native rule id)
3. Which runtime run used the same artifact hash?
4. Did scanner findings predict observed runtime behavior?
5. Did runtime controls prevent execution? (Q-MCP-AFTER-DENY / RETEST DENY — **runtime SPL already exists**)
6. Did multiple scanners disagree?
7. Which findings are scanner-only with no runtime evidence?
8. Which runtime ATTACK runs have **no** scan attached (silence ≠ safe)?

Join key **candidate** after discovery: description SHA-256 already indexed as `agentsec.content.hash` on METADATA-001. The scanner sourcetype must **actually contain** an equivalent extracted field before a join is written.

---

## Future KO strategy (not created)

| KO class | 9A decision |
|----------|-------------|
| Field extractions | Later: JSON for `agentsec:scanner:finding` only after live events exist. Consult **Field Extraction and CIM Mapping** skill — expect CIM NOT APPLICABLE |
| Event types / tags | Not justified until a hunt needs them |
| Macros | Not until two+ scanner searches share a proven fragment |
| Lookups | Optional later: scanner version → release notes. Do not lookup “severity → DENY” |
| Saved searches | Investigation/hunt only after field contract. Not a detector |
| Detection | **Do not publish** a DET-MCP-SCANNER because a scanner emitted HIGH |
| Dashboard Studio | After SPL + `/splunk-ko-review` + live validation + `/ui-review`. Not 9A. Do not add a scanner tab to `ws_lab_mcp_catalog` automatically |
| Data models | None |
| CIM | Do not force |

**Data Source Onboarding Advisor** / **Ingestion Pipeline Design** apply when (and only when) a later phase adds HEC routing for the new sourcetype.

---

## Relationship to validated SPL

| Existing search | Scanner interaction |
|-----------------|---------------------|
| Q-MCP-AUTHZ | Unchanged. Authorization, not scan verdict |
| Q-MCP-CATALOG-AUTHORITY | Unchanged. Metadata trust vs follow-on. May later be **compared** to scanner rows in a **new** hunt |
| Q-MCP-AFTER-DENY / DET-MCP-001 | Unchanged. Execution after DENY |
| Q-MCP-AUTHZ.spl first line | Must remain `index=agentsec_telemetry sourcetype=otel:agentic:json` |

A future comparison hunt would be a **new** file, new question, new field contract — not an edit that mixes sourcetypes into Q-MCP-AUTHZ.

---

## No-data semantics

| Observation | Honest meaning |
|-------------|----------------|
| Zero scanner events | Scan not ingested or not run — **not** “catalog is clean” |
| Zero `mcp.started` | Not by itself prevention (existing lab rule) |
| Scanner FAIL rows + RETEST DENY | Two independent evidence streams; do not merge reasons |
| Scanner PASS + ATTACK ALLOW | Scanner did not protect the runtime (expected in fail-open overlay) |

---

## Cisco / Splunk time-series future path (not Phase 9A)

See also `docs/AGENTSEC_ANALYTICS_ROADMAP.md`. Verified 8A naming: Splunk **AI Toolkit** (former MLTK); **Cisco Deep Time Series Model (CDTSM)** (`apply CDTSM`, `mode=anomaly|forecast`); open weights `cisco-ai/cisco-time-series-model-1.0`; GitHub `splunk/cisco-time-series-model`.

**Do not implement anomaly detection in Phase 9A.** Do not invent a Cisco time-series field model. None is verified as an AgentSec schema.

CDTSM needs a **metric time series**, not raw `mcp.started` rows and not raw scanner JSON.

### Candidate metrics (event-derived later)

| Signal | Would require | Security question |
|--------|---------------|-------------------|
| Tool invocation rate | `mcp.started` counts per agent per bucket (already derivable) | Runaway loop — **not** authorization |
| New tool appearance | `dc(gen_ai.tool.name)` over time | Catalog growth — after more tools exist |
| Scope/request distribution | existing MCP-003 fields | Drift vs coded grant |
| Resource access patterns | MCP-004 fields | Same |
| Authorization-denial rates | `control.decision=DENY` counts | Control pressure, not “more secure” |
| Metadata fingerprint churn | distinct `agentsec.content.hash` over time | Rug-pull **research** later; not 9A |
| Scanner finding rates | **after** scanner sourcetype exists | Scan volume, not runtime truth |
| Follow-on behavior changes | Q-MCP-CATALOG-AUTHORITY class metrics | Overlay vs defended |

Ladder: baseline counts → simple threshold → z-score with documented n → AI Toolkit optional → CDTSM optional. A workshop ATTACK spike is **expected**, not anomalous.

DET-MCP-001 remains a sequence predicate. It must not be replaced by an anomaly score.

---

## Cursor + Splunk skill utilization (future phases)

When Phase 9B+ touches Splunk:

1. `.cursor/rules/33-splunk-agent-skills.mdc` (glob-scoped; do not alwaysApply on runtime work)
2. `.cursor/skills/splunk-ko-review/SKILL.md` + `reference.md`
3. `.cursor/skills/spl-validate/SKILL.md` + `.cursor/rules/31-spl-validation.mdc`
4. Official Splunk skills only as mapped in `reference.md` (Search Performance Optimizer **after** the question is fixed; Field Extraction; Knowledge Object Governance; Data Source Onboarding Advisor for the new sourcetype; HEC Setup if ingesting)
5. `.cursor/rules/32-ui-design-system.mdc` + `/ui-review` only if Studio is in scope
6. `/logic-proof` for workshop security claims
7. `.cursor/rules/40-testing.mdc` for tests
8. `.cursor/rules/50-research-integrity.mdc` for OBSERVED_SCANNER vs OBSERVED_RUNTIME

Do **not** duplicate official Splunk Agent Skills inside AgentSec. Map and invoke them.

Do **not** run splunk-ko-review against scanner **design** docs as if they were `props.conf`.
