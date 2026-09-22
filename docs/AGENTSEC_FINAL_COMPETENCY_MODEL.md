# AgentSec final competency model

**Status:** DESIGN (Phase 16A). Measurable abilities, not a certificate.  
**Do not start Phase 16B from this file.**  
Viewing dashboards is not completion. 15A stages (FOUNDATION → ARCHITECT) remain in `docs/AGENTSEC_COMPETENCY_MODEL.md`.

A learner who “finishes AgentSec as currently implemented” has finished **Level 1–2 LIVE**, not Level 3. Capstone competency is **DESIGNED**, not testable in product.

---

## Measurable outcomes

| Ability | How you would measure (honest) | Today |
|---------|--------------------------------|-------|
| Diagram an agentic trust model | Sketch source → boundary → request → PDP → execution → Splunk | LIVE labs’ LEARN tabs |
| Identify trust boundaries | Name the boundary for a given lab without the title | Six LIVE manifests |
| Distinguish data from authority | Separate OBSERVE classifier from CTRL-MCP-001 | RAG/memory/identity |
| Reason about provenance | Cite document.id / memory.id / hash / source_run_id | RAG/memory |
| Distinguish authentication from attribution | State WHO AUTHENTICATED = NOT PROVEN given caller_agent_id | Identity LIVE |
| Analyze delegation claims | A+B ≠ new grant; claim ≠ authorization | Identity LIVE |
| Reason about tool authorization | Request vs coded grant vs execution | MCP-001 LIVE; 003/004 REPLAY |
| Investigate RAG influence | Retrieve → OBSERVE → request → MCP | RAG LIVE |
| Investigate memory persistence | Write run ≠ recall run | Memory LIVE |
| Detect goal/task expansion | Goal DENY with MCP ALLOW | Goal LIVE |
| Reconstruct execution | Handler/LLM counts + Splunk corroboration | All LIVE |
| Use Splunk for evidence | Path A on at least one hunt per lab | investigations.json |
| Distinguish observation from enforcement | “Splunk does not” in PROVE | manifests |
| Design ATTACK/RETEST experiments | Same bytes, different server-owned profile | 14E contract |
| Evaluate evidence quality | SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT | PROVE tabs |
| Explain security limitations | HEC, overlay, localhost, regex, no auth | limitations[] |
| Avoid SAFE from missing telemetry | Empty ≠ prevented | DETECT / PROVE |

---

## Knowledge-check pattern (reasoning, not IDs)

**Bad:** “What is CTRL-MCP-001?”

**Better:** “The tool executed after retrieved content requested it. Which evidence distinguishes context influence from actual authorization?”

Expected: RAG OBSERVE + MCP ALLOW/DENY + handler count. Influence is not a grant.

**Classify the statement:**

> “RETEST had no `mcp.started`, so Splunk blocked the tool.”

| Class | Why |
|-------|-----|
| INCORRECT | Splunk is not the PDP |
| NOT PROVEN | Missing rows might be incomplete copy; need runtime count |

> “CTRL-RAG-CONTEXT-001 OBSERVE means the retrieve was allowed to authorize `lookup_customer_tier`.”

INCORRECT. OBSERVE ≠ ALLOW. RETRIEVED CONTENT ≠ AUTHORITY.

> “Identity LIVE proves Agent B authenticated.”

INCORRECT. IDENTITY CLAIM ≠ AUTHENTICATION.

---

## Progress states (no fake store)

NOT STARTED / LEARNED / ATTACKED / INVESTIGATED / DEFENDED / RETESTED / PROVED — **learner-held evidence** (`run.id` + Search), not a platform badge.

---

## What finishing current AgentSec does **not** prove

- Production agent security engineering
- Real A2A / OAuth / SPIFFE
- HITL design
- Dimensional MCP LIVE (003/004 still REPLAY)
- Capstone / campaign reconstruction
- Behavioral analytics
- “Certified” OWASP/NIST/ATLAS compliance
