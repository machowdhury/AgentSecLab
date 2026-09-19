# Goal integrity external tool research

**Status:** DESIGN / RESEARCH ONLY. No integration.

## BUILD VS INTEGRATE

| Capability | Decision |
|------------|----------|
| Frozen TaskContract + deterministic interpreter | **BUILD** (AgentSec core teaching) |
| CTRL-GOAL-INTEGRITY-001 | **BUILD** |
| Promptfoo / garak / PyRIT / NeMo Guardrails | **INTEGRATE LATER** — not the security proof |
| Embeddings / LangChain / LangGraph | **NOT APPLICABLE** for 13A/13B |
| Live A2A / OAuth / SPIFFE | **DEFER** |

## Framework notes (honest)

Sources reviewed at design time: OWASP GenAI / agentic threats, NIST AI RMF / NIST AI 600-1, MITRE ATLAS, vendor agent-security writeups, CSA agentic material.

GOAL-001 (task/goal hijack via untrusted instruction) is **UNMAPPED / REQUIRES REVALIDATION** against a specific ATLAS id. Do not stamp AML.Txxxx without a measured mapping.

REFERENCE: INV-002 already covers “content is not a grant”. This lab applies that to **instructions-as-data** plus a frozen task.
