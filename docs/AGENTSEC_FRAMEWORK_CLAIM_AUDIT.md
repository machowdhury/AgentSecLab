# AgentSec framework claim audit

**Status:** Phase 17C. **Do not expand the framework program.** Schema **1.9.0**.  
**Do not start Phase 17D from this file.**

Historical reports remain historical. This file qualifies what learners currently see.

| Identifier | Where it appears | Classification | Notes |
|------------|------------------|----------------|-------|
| MITRE ATLAS `AML.T0054` | Formerly telemetry `technique.id` on ATK-002 | **RETIRED (revalidated 2026-10-22).** ATLAS 2026.09 defines it as *LLM Jailbreak*; prompt injection is `AML.T0051` (`.000` Direct, `.001` Indirect). No longer emitted. Shown only as a retired label. Original note: | Historically coded in `attacks.py` / `experiment.technique_id_for`. 8A already flagged AML.T0051 as current “LLM Prompt Injection” in public 2026 materials. Learner UI now labels it an **educational label only**. Telemetry field **unchanged** (architecture freeze). |
| MITRE ATLAS `AML.T0050` | Formerly telemetry on MCP-002/003/004 | **RETIRED (revalidated 2026-10-22).** ATLAS 2026.09: *Command and Scripting Interpreter*. No longer emitted. Committed REPLAY specimens keep their historical value. Original note: | Current public ATLAS materials describe AML.T0050 as Command and Scripting Interpreter — **not** an MCP allow-list. Stale / needs review. Not shown as a verified Attack Service teaching id on MCP labs (those pages show attack_id such as MCP-002). |
| MITRE ATLAS `AML.T0070` / `AML.T0080` / `AML.T0053` / `AML.T0073` | Predecessor research docs only | **EXIST (ATLAS 2026.09: RAG Poisoning, AI Agent Context Poisoning, AI Agent Tool Invocation, Impersonation); still UNMAPPED to labs except AML.T0053 as a PROPOSED relationship for MCP-002/003/004.** Earlier note: | Official atlas.mitre.org technique URLs 404’d in 8A/10A/11A/12A research windows. Do not ship as verified workshop mappings. |
| OWASP LLM01 / ASI01-class | PI LIVE matrix | **RELATED** | Educational family, not a certified OWASP assessment. |
| OWASP ASI02 / LLM03 Excessive Agency | MCP-001 related docs | **RELATED** | Over-grant in vulnerable profile. Not a product certification. |
| CWE-74 / CWE-863 | Research pipeline | **RELATED** teaching only | Do not claim a CVE. |
| NIST | Learner Studio | **UNMAPPED** on academy surfaces | No NIST compliance banner on Home/Mastery/labs. |
| Splunk CIM | Hunts | **CIM NOT APPLICABLE / DEFERRED** for agentic fields | Do not force `agentsec.*` into unrelated CIM fields. |

## Rule

If a framework identifier has not been revalidated against a live official page, it must not look authoritative merely because it appears in telemetry or historical docs.

Phase 17C corrected Attack Service PI copy. It did **not** remap `technique_id_for` (emitter freeze).

## Update 2026-10-22 (Batch 1)

Framework identifiers now live in `learning/academy/framework_refs.json` with a verification status, source URL and retrieval date. `technique_id_for` returns `None`, so new telemetry carries no `agentsec.technique.id`. Learner pages show only ids that have a verified entry, plus the two retired labels. Lab-to-technique links are **PROPOSED** or **RELATED** educational relationships, not certified mappings.

Limits of the revalidation: ATLAS was read from MITRE's `atlas-data` release 2026.09 (not from atlas.mitre.org pages); OWASP Agentic 2026 titles came from a summary of OWASP's announcement page; the NIST PDF was not opened. Those entries are `VERIFIED_WITH_LIMITS`. `tests/test_batch1_contracts.py` guards the rules.
