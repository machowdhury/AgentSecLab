# AgentSec analytics roadmap

**Status:** Phase 8A DESIGN. No MLTK, CDTSM, or metrics index implemented.

Parents: `docs/AGENTSEC_TELEMETRY_ROADMAP.md`, `docs/INTEGRATION_ARCHITECTURE.md`.

Verified Splunk naming (2026): **AI Toolkit** is the current product name for former MLTK. **Cisco Deep Time Series Model (CDTSM)** is a pretrained forecast/anomaly preview (`apply CDTSM`, `mode=anomaly|forecast`). Open weights: Hugging Face `cisco-ai/cisco-time-series-model-1.0`; GitHub `splunk/cisco-time-series-model`. Do not call a `stats count` rule “AI.”

---

## Principle

If a **deterministic hunt** answers the security question, do not add a model.

DET-MCP-001 (DENY then later `mcp.started`) is a sequence predicate. It must not be replaced by an anomaly score.

Behavioral analytics are for questions like: “is this agent’s tool-call rate this hour surprising **relative to its own baseline**?” That is a different question from “was this invoke authorized?”

---

## Candidate measurements

| Signal | Kind | Derivable from 1.4.0? | Security question |
|--------|------|----------------------|-------------------|
| Tool-call frequency | COUNTER / TIME SERIES | Yes (`mcp.started` by agent/time) | Excessive agency / runaway loop |
| Tool diversity | EVENT-DERIVED METRIC | Yes (`dc(gen_ai.tool.name)`) | New tool usage |
| DENY rate | COUNTER | Yes | Control pressure; not “more secure” |
| ERROR rate | COUNTER | Yes | Fail-open vs dependency failure — split by `outcome` |
| Scope changes | EVENT-DERIVED | Yes (`requested_scope` vs `allowed_scope`) | Authorization drift **per event**; time-series of mismatch rate later |
| Resource-access changes | EVENT-DERIVED | Yes (MCP-004 fields) | Same |
| Delegation depth | GAUGE | Partial (one hop today) | Only after chain lab |
| Agent fan-out | COUNTER | Partial (4 coded hops) | ASI08 teaching later |
| Token usage | DISTRIBUTION | Not first-class in schema | Add only if Ollama returns MEASURED usage |
| Latency | DISTRIBUTION | Hop duration exists | Infra vs security — do not conflate |
| LLM failures | COUNTER | `llm.failed` | Dependency, not prevention |
| New MCP server usage | EVENT-DERIVED | **No** (one coded server) | Needs catalog lab |
| Result-derived follow-on | COUNTER | MCP-005 events | Already a hunt, not an ML problem |
| Identity changes | EVENT-DERIVED | Agent id allow-list | Needs impersonation lab |
| Unusual sequences | EVENT-DERIVED | `sequence` + event.name | Start with `eventstats`, not CDTSM |

---

## Approach ladder (later labs)

1. **Baseline count** — last 7 lab days of BASELINE runs only. ATTACK runs are not the baseline.
2. **Moving average / simple threshold** — teaching.
3. **z-score** — only with enough BASELINE points; document sample size.
4. **Seasonality** — usually **not** applicable to a learner lab that runs in bursts.
5. **Splunk AI Toolkit** — optional Enterprise track; never required for core.
6. **CDTSM** — optional; needs a **metric time series**, not raw `mcp.started` rows. First build a summary metric (calls/min by agent). Feature-preview caveats apply.
7. Other defensible methods (IQR residual, quantile) only after the metric exists.

False-positive analysis is mandatory. A spike of DENY during a workshop ATTACK tab is **expected**, not anomalous.

---

## Splunk KO implications (do not create now)

Future: report of per-agent rates; optional alert on z-score **after** the detection gate. CIM: behavioral metrics may be CIM PARTIAL (Endpoint or Application) — decide per field, do not force.

Workshop: LEVEL 6 only. Learners must still prove DET-MCP-001 style predicates first.
