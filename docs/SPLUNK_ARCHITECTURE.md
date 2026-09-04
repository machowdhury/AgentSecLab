# Splunk Architecture

**Status:** PLANNED  
**Related:** `SECURITY_EVENT_MODEL.md`, `SPLUNK_DESIGN_SYSTEM.md`, `SPLUNK_INFORMATION_ARCHITECTURE.md`

Splunk is the SOC side of AgentSec. It does not run agents and does not authorize loans.

---

## Pipeline

```text
AcmeBank OTLP ──► OTel Collector ──► Splunk HEC ──► index agentsec_telemetry
                         └──► file archive (lab debug)

Apps do not use a Splunk SDK.
```

| Item | Phase 1 value |
|------|----------------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| HEC | Local container or later external/Cloud overlay |
| App | `agentsec` |
| Macros | `agentsec_index`, time windows |

Later sourcetypes (adapters) union through `norm_*` fields. Phase 1 has one sourcetype.

---

## Phase 1 Splunk deliverables

1. Index + HEC token bootstrap (lab defaults, localhost).
2. `props.conf` JSON KV + EXTRACT for `run.id` (same name as OTel).
3. Two **validated** searches (only after events exist):

| QUERY ID | Security question |
|----------|-------------------|
| Q-RUN | Did this `run.id` produce events? |
| Q-DENY | Which LIVE events have `control.decision=DENY` and `operation.executed=false`? |

4. Saved searches disabled by default.  
5. No Technique Coverage / Attestation / Governance dashboards in Phase 1.

SPL process: question → fields exist in real events → simplest query → run → inspect → then any dashboard.

Avoid unnecessary `join`, `transaction`, `map`, `append`, large subsearches.

---

## Later Splunk (approved shapes from inventory)

Reuse AgentWatch **patterns**, rebranded:

| Asset | When |
|-------|------|
| Dashboard Studio generators + validate script | When first dashboard is justified |
| Exercise Runner / workshop views | Workshop Engine |
| Technique Coverage | After many **LIVE** techniques |
| Control Attestation | Measurement of control tags, split by `testbed_mode` |
| Cross-app normalization | Community adapters |
| Executive governance | After coverage exists |
| MLTK anomaly hunting | Optional track |
| Detection library | After each hunt is validated |

**DROP:** legacy `App-Agentic-Compliance`; dark classic matrix; claiming SIMULATED as live proof.

---

## Deployment overlays (later)

| Mode | Splunk location |
|------|-----------------|
| Local | Compose profile |
| External Enterprise | HEC endpoint in env |
| Splunk Cloud | HEC to stack; TLS verify on |

Never open HEC to the internet.

---

## Major decisions

### Decision: One app, one index, one primary sourcetype in Phase 1

**DECISION:** `agentsec` / `agentsec_telemetry` / `otel:agentic:json`.

**ALTERNATIVES:** Import `acme_genai_compliance`; two indexes (`security` + telemetry) on day one.

**WHY CHOSEN:** AgentWatch’s second index and legacy app confused learners. Macros can retarget later.

**SECURITY CONSEQUENCE:** Clear evidence store. No “events went to the other index.”

**LEARNING VALUE:** One search: `` `agentsec_index` run.id=* ``

### Decision: Collector → HEC, not app → HEC

**DECISION:** OTLP from AcmeBank; collector exports.

**ALTERNATIVES:** Direct HEC from Flask (AgentWatch also had baseline emitters).

**WHY CHOSEN:** One schema on the live path. Direct HEC is reserved for later **labeled** adapter demos.

**SECURITY CONSEQUENCE:** Fewer duplicate tokens and sourcetypes on the defend path.

**LEARNING VALUE:** Observability pipeline vs SIEM.

### Decision: No dashboard until SPL is validated

**DECISION:** Phase 1 may ship zero Studio views.

**ALTERNATIVES:** Copy 14 AgentWatch dashboards immediately.

**WHY CHOSEN:** AgentSec SPL and Studio rules. Fields do not exist yet.

**SECURITY CONSEQUENCE:** Prevents invented fields and fake “what happened” panels.

**LEARNING VALUE:** Search literacy before dashboard literacy.

### Decision: Macros isolate index/sourcetype

**DECISION:** All hunts start with `` `agentsec_index` ``.

**ALTERNATIVES:** Hardcoded `index=acme_agentic_telemetry`.

**WHY CHOSEN:** AgentWatch macros were a proven reuse. Customers change one macro.

**SECURITY CONSEQUENCE:** Less copy-paste drift; still must not invent fields.

**LEARNING VALUE:** Detection engineering hygiene.
