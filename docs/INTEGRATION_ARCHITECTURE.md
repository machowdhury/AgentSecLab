# Integration Architecture

**Status:** PLANNED  
**Default lab:** works without Cisco, MLTK, MAESTRO UI, or community emitters.

Integrations are tracks. They must not break Workshop LIVE attacks or silently become enforcement.

---

## Layers

```text
Core (Phase 1)
  AcmeBank + Attack Service + Ollama + OTel + Splunk ingest

Optional tracks (later)
  ├─ Cisco Advanced Track     compose overlay, teach-mode
  ├─ MLTK Track               Splunk-side apps
  ├─ MAESTRO workshop         external UI + our architecture export
  └─ Community adapters       extra sourcetypes + norm_* fields
```

---

## Cisco Advanced Track (later)

**Reuse:** overlay compose pattern, teach-mode scan APIs, Foundation-Sec as optional second Ollama model, docs honesty that scanners are optional CLIs.

**Do not reuse:** documented `LAB_MODE=enforce` with no caller; implying AcmeGate is Cisco DefenseClaw; embedding DefenseClaw/Skill Scanner without a real tested wire-up.

| Mode | Behavior |
|------|----------|
| absent | Core lab only |
| teach | Scans/log fields; **do not block** unless a tested pre-op caller exists |
| enforce | PLANNED only after tests prove DENY **before** the dangerous operation |

Python must not emit `cisco_*=FAIL` that looks MEASURED if no scanner ran. Label SIMULATED vs OBSERVED.

---

## MLTK Track (later)

Splunk MLTK (and CTSM if present) run **in Splunk** on telemetry fields.

AcmeBank must not write `mltk.detected=true`. Token spikes may be real usage fields from LIVE runs. Synthetic surge fields for demos are SIMULATED and labeled.

---

## MAESTRO (later)

Optional: export architecture description from AgentSec; learner uses official CSA tooling separately. Splunk may show `framework.maestro_layers` only from verified mappings.

---

## Community adapters (later)

Second (third, …) sourcetypes with deliberately different field names. Splunk `norm_*` calculated fields teach SIEM-as-normalization.

Rules:

- Not claimed as vendor product feeds
- SIMULATED or clearly synthetic
- Must not pollute LIVE control-proof KPIs

Phase 1: **no adapters**. One sourcetype.

---

## Secrets and supply chain

- No hardcoded production credentials.
- Lab HEC token / Splunk password only in env example, localhost.
- Optional Cisco CLIs pinned and installed via optional overlay, not the default image, unless a later decision changes that.
- Do not add Kubernetes or extra message buses for integrations.

---

## Major decisions

### Decision: Core lab has zero vendor runtime dependency

**DECISION:** Phase 1 compose has no Cisco overlay, no MLTK requirement, no MAESTRO Node app.

**ALTERNATIVES:** Default-on Cisco flags (AgentWatch `.env.example` vs compose mismatch).

**WHY CHOSEN:** Default must work with Docker + Ollama + Splunk. Inventory showed misleading env.

**SECURITY CONSEQUENCE:** Uninstalled scanners cannot be described as blocking.

**LEARNING VALUE:** Reference controls first; vendor comparison later.

### Decision: Teach-mode vs enforce-mode are not the same

**DECISION:** Teach-mode cannot DENY. Enforce requires a real pre-op hook and tests.

**ALTERNATIVES:** One boolean `CISCO_INTEGRATION_ENABLED` that both logs and “blocks.”

**WHY CHOSEN:** AgentWatch `should_block_from_cisco_scan` had no callers.

**SECURITY CONSEQUENCE:** INV-008 honesty.

**LEARNING VALUE:** Overlay vs enforcement.

### Decision: Adapters are a Splunk lesson, not extra authority

**DECISION:** Normalization in `props.conf`. Adapters cannot ALLOW a loan.

**ALTERNATIVES:** Adapter processes that call Ollama.

**WHY CHOSEN:** Trust boundary stays AcmeBank.

**SECURITY CONSEQUENCE:** Heterogeneous logs cannot grant authority (INV-002 analog at SIEM).

**LEARNING VALUE:** Why enterprises buy a SIEM for agentic apps.
