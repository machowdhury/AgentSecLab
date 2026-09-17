# MCP result trust security 101

**Status:** Phase 6A design notes, plus Phase 6B runtime (`docs/learning-notes/mcp-result-trust-runtime.md`).  
**Parents:** `docs/MCP005_RESULT_TRUST_MODEL.md`, `docs/MCP005_LAB_SPECIFICATION.md`.

---

## WHAT IS IT?

**Tool result trust** asks whether **content returned by an already authorized tool** may change what the agent is allowed to do next.

The first call is not the dispute. `lookup_policy` at `policy:read` on `lending-basics` is granted, runs, and completes. The question is about the **bytes that come back**.

LAB-MCP-001: *May this agent call this tool?*  
LAB-MCP-003: *May it call it at this scope?*  
LAB-MCP-004: *May it operate on this resource?*  
LAB-MCP-005: *Can data returned by that permitted operation alter authority?*

## WHY DOES IT EXIST?

Authorization is easy to treat as a one-time door. After the door opens, people (and models) treat the **reply** as the next policy: “the tool said I may now call `lookup_customer_tier`.”

That is INV-002: **data cannot grant authority.** Retrieved or returned content may inform reasoning. It must not mint tools, scopes, resources, roles, or bypasses.

AgentWatch never had a tool result. It regex-scanned **user prompts** and simulated injection. AgentSec already **labels** completed results `untrusted_data` and has `policy_unchanged_by_result()`. MCP-005 is the lab that makes a **malicious data fixture** try — and, on defended, fail — to become a grant.

## HOW DOES IT WORK?

1. First `tools/call` is the usual authorized `lookup_policy`.
2. Handler returns ordinary JSON: `policy_id`, `title`, `summary`, `found`.
3. NORMAL `summary` is boring lending text. MALICIOUS `summary` contains a closed marker such as `SECURITY_OVERRIDE:` naming `lookup_customer_tier`.
4. There is **no** `lab_instruction` field. A command channel on the result would teach the wrong lesson.
5. A **lab interpreter** (not Ollama) looks for that marker and a **closed** follow-on name.
6. **CTRL-MCP-RESULT-001** decides whether those bytes may be **merged** into authority. Defended: **OBSERVE** `result_is_data` — no merge. Vulnerable: **ALLOW** a **per-run overlay** only, reason `vulnerable_profile_fail_open:result_derived_grant`.
7. Any follow-on still goes through **CTRL-MCP-001**. Defended DENYs `tool_not_granted`. Vulnerable ALLOWs because it consulted the overlay.
8. Global `allowed_tools` stays `{lookup_policy}`. Telemetry must still say that.

## WHERE DOES IT SIT IN AGENTSEC?

Same family: `POST /mcp/invoke`, agent `acme-agent-mcp-001`, schema 1.2.0 fields that already exist for results. Later implementation should keep **one run** and do the follow-on in-process so both steps share `run.id`.

Not implemented in 6A. Schema stays 1.2.0 (it cannot emit OBSERVE or `CTRL-MCP-RESULT-001` yet).

## WHAT IS THE TRUST BOUNDARY?

`mcp.tool.result` → RESULT-001 (may this mutate policy?) → if a follow-on intent exists, `acmebank.mcp.authorize` again (may this tool execute?).

Provenance (`mcp.tool.handler`) answers **where it came from**. Content trust (`untrusted_data`) answers **whether it is authority**. Those are different.

Splunk does not authorize. The model does not authorize.

## WHAT COULD AN ATTACKER CONTROL?

In this lab, the **fixture text** behind an authorized tool (mode-selected NORMAL vs MALICIOUS), not the first HTTP grant fields.

They might also try grant-shaped JSON in the result (`role=admin`, `allowed_tools=…`, `approved=true`). That remains DATA.

They cannot set coded policy, profile, or `control.decision` via the result.

## WHAT CAN GO WRONG?

- Treating “the handler is trusted” as “the **content** is a grant.”
- Mutating **global** `ALLOWED_TOOLS` so the next learner’s run is contaminated.
- Building a generic “run whatever the text says” executor (RCE-shaped teaching).
- Adding `requested_tool` on the result so tools look like they have a control plane.
- Calling SANITIZE/QUARANTINE when the JSON is unchanged and still returned.
- DENY-ing the **first** completed call on RETEST (wrong lab story).
- Depending on Ollama to “resist injection.”
- Teaching DET-MCP-001 as sufficient — preferred attack is ALLOW via overlay, no DENY.
- Inventing `TRUSTED_DATA` because provenance was `mcp.tool.handler`.

## WHAT TELEMETRY SHOULD EXIST?

Already on `mcp.completed`: preview ≤200, sha256, `untrusted_data`, `mcp.tool.handler`.

Later (not 6A): RESULT-001 row (OBSERVE vs labeled ALLOW); second CTRL-MCP-001 row; optional `gen_ai.tool.call.id` so two calls in one run stay distinct. Server-owned grant fields must not be rewritten on fail-open.

## HOW WILL SPLUNK SHOW IT?

Existing Q-MCP-* still answer the **first** call. Q-MCP-RESULT / Q-MCP-RESULT-TRUST show the **label**, not “used as authority.”

Future hunts (names only): `Q-MCP-RESULT-AUTHORITY`, `Q-MCP-RESULT-FOLLOWON`. No new SPL in 6A.

DET-MCP-001 stays the DENY-then-start detector. Preferred MCP-005 ATTACK will not fire it. That is the lesson.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on RESULT-001: defended does not apply the overlay; vulnerable applies a **per-run** overlay only.

Follow-on still uses CTRL-MCP-001. Defended DENYs the ungranted tool. Do not bypass the allow-list “because the result asked.”

## WHAT TEST PROVES THE LOGIC?

Not written yet. When implemented: first handler always 1 on A/B/C; RETEST follow-on handler 0; ATTACK follow-on handler 1; `coded_policy()` unchanged after ATTACK; overlay does not leak across runs; interpreter never executes a name outside `{lookup_customer_tier}`; no Ollama in the security tests.

---

## What I should now be able to explain

1. Why tool / scope / resource authorization can all succeed and INV-002 can still fail.
2. Why “came from `mcp.tool.handler`” is provenance, not a grant.
3. Why results stay `untrusted_data` and why `TRUSTED_DATA` would be the wrong lesson.
4. Why a malicious **fixture** is the right attack, and a malicious **binary** is a different problem.
5. Why the instruction lives in `summary` text, not a `lab_instruction` field.
6. Why the interpreter is deterministic and the LLM is optional education only.
7. Why defended RESULT-001 is OBSERVE, not SANITIZE, QUARANTINE, or DENY of the first call.
8. Why the vulnerable bug is a **per-run overlay**, not a rewritten global allow-list.
9. Why DET-MCP-001 does not catch the preferred MCP-005 attack.
10. Why MCP-006 (confused deputy) is a different question than “can data become authority?”
