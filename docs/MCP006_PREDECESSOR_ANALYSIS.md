# MCP-006 predecessor analysis (AgentWatch Range)

**Status:** Phase 7A **DESIGN**. No AgentSec MCP-006 runtime.  
**Predecessor:** `/Users/mahamudc/Documents/workspace/AgentwatchRange` (READ-ONLY).  
**Evidence class:** **OBSERVED** from source. Not a live AgentWatch experiment. Not MEASURED AgentSec MCP-006 behavior.  
**Related:** `docs/MCP_PREDECESSOR_ANALYSIS.md` (tool), `docs/MCP003_PREDECESSOR_ANALYSIS.md` (scope), `docs/MCP004_PREDECESSOR_ANALYSIS.md` (resource), `docs/MCP005_PREDECESSOR_ANALYSIS.md` (result trust). This file is the **delegated authority / confused deputy** slice only.

Do not copy AgentWatch A2A, DID, or privilege-creep code. Do not treat prompt markers or in-memory token sets as INV-001 delegated authorization.

AgentSec `docs/MCP_LAB_PLAN.md` MCP-006 sketch (identity claim in payload) is **superseded** by this design. Identity spoofing remains a **negative test**, not the preferred ATTACK.

---

## Question this document answers

Does AgentWatch authorize a **deputy** to exercise **its own ambient privilege** only when the **caller** actually delegated that operation?

**No.** AgentWatch has no second agent that executes a tool on behalf of a first agent. There is no delegated-grant object, no deputy ambient grant distinct from a caller grant, and no control that runs before a privileged handler using that distinction.

What exists is prompt-regex “A2A verification,” a global used-scope accumulator, and SIMULATED OTel labels.

---

## AgentWatch skepticism (required answers)

| Question | Finding (OBSERVED) |
|----------|-------------------|
| Real agent-to-agent execution? | **No.** Four-agent loan path is sequential LLM hops. No deputy `tools/call`. |
| Identity server-owned? | **Partially.** `agent_id` is passed into `llm_client` from the hop. Request **content** can still contain `did:acme:…` strings that `verify_a2a_message` **parses as** requesting_agent_id. |
| Can request content spoof agent identity? | **Yes, as theater.** DID in the **user message** becomes `requesting_agent_id`. Not a server-owned caller. |
| Delegation represented explicitly? | **No.** A line matching `Delegation-Chain:` is copied as a string, default `"orchestrator-000 → unknown"`. |
| Delegated authority represented explicitly? | **No.** No `{tool, scope, resource}` grant for “what A may ask B to do.” |
| Deputy distinguish own vs caller authority? | **No.** `agent_registry` copies the **same** `APPROVED_TOOLS` string onto every running agent as `mcp_scope`. |
| Authorization before privileged operation? | A2A check runs **before Ollama**, not before a tool handler. There is no privileged deputy operation. |
| Privileges propagate accidentally? | `_AGENT_USED_SCOPE` is **process-global**. `track_agent_scope` accumulates across calls. That is cross-run leakage in the predecessor. |
| Model involved in authorization? | A2A regex may **skip** the model. The model does not decide grants. Prompt markers decide the theater. |
| A2A findings merely labels? | **Mostly.** OTel `delegation.chain`, `cryptographic_passport_valid`, `privilege_creep_detected` can be emitted from marker text / SIMULATED techniques. |
| Confused-deputy behavior actually executed? | **No handler.** No deputy used ambient authority to run `lookup_customer_tier` (or anything) for a caller. |
| Splunk reconstruct the delegation chain? | AgentWatch fields are labels. There is no hop-0 caller / hop-1 deputy / control / `mcp.started` chain. **Not defensible as AgentSec reconstruction.** |
| Existing MITRE mappings defensible for MCP-006? | AgentWatch AML.T0073 (privilege creep) and W8 DID spoofing are **not** confused-deputy execution. **Do not inherit.** |

---

## Code-path traces (OBSERVED)

### a2a_verifier.py — regex on the user prompt

`verify_a2a_message(message, receiving_agent_id)`:

1. Regex `did:acme:[a-z]+:agent:\d{3}:v[\d.]+` in the **message string**.
2. Copy a `Delegation-Chain:` line if present.
3. Derive `requesting_agent_id` from DID path segments (not from the coded hop).
4. Fail if the message contains `FORGED`, `BYPASS_VERIFICATION`, tamper markers, or a truncated hash mismatch.
5. Else `cryptographic_passport_valid=True`. There is no signature, no DID document, no key.

`track_agent_scope` compares a **hardcoded** map (`read:intake`, `write:approve`, …) against a **module-global** `_AGENT_USED_SCOPE`. Triggered when the prompt contains `PRIVILEGE_CREEP_SIM` or technique AML.T0073. It does not authorize MCP.

**Classification:** **DROP** as a control. The *teaching idea* (“do not trust claimed identity in content”) is **REUSE** as a negative-test story only.

### agent_registry.py — inventory, not grants

Every running lab agent gets `mcp_scope = ",".join(sorted(APPROVED_TOOLS))` — the **same** list. Shadow agent is `unscoped`. Trust scores are heuristics.

**Classification:** **DROP** for MCP-006 grants. **REUSE** only the idea that agents have distinct **ids** (AgentSec already has `CREDIT_ID` / `COMPLIANCE_ID`).

### mcp_gateway.py — prompt-as-MCP

Already classified **DROP** for MCP-001–005. Still **DROP** for MCP-006. Confused deputy is not “regex `execute_shell_command(`.”

### workflow_guard.py — A2A branch before LLM

If `agent_id` is `acme-agent-compliance-004` or `acme-agent-creditrisk-003` **and** the user message contains `INTER-AGENT` or `did:acme:`, run `verify_a2a_message`. Failure **skips Ollama**. AgentSec agent ids are `credit-002` / `compliance-004`; do not copy the AgentWatch id.

**Classification:** **REDESIGN** placement only (“control before the dangerous operation”). Move the gate to **before the deputy’s MCP handler**, not before the credit agent’s LLM.

### orchestration_guard.py — Foundry prompt markers

Blocks on `orchestrator_override=true` / `BYPASSED` in the user string.

**Classification:** **DROP** for MCP-006.

### technique_executor.py / chain_engine.py

LIVE posts to the bank HTTP path. SIMULATED writes A2A/MCP-shaped fields without a deputy tool call. Chain KC / AML.T0050 privilege-escalation theater.

**Classification:** **DROP**.

### control_validator.py

YAML/NIST pass-rate scoring from OTel bags. Post-hoc, not enforcement.

**Classification:** **DROP** (same as earlier MCP labs).

---

## Classification table

| Component | Claimed property | Actual | Classification | AgentSec direction |
|-----------|------------------|--------|----------------|--------------------|
| `verify_a2a_message` | Cryptographic A2A / DID | Prompt regex + markers | **DROP** | Server-owned caller/deputy ids |
| DID in message → requesting id | Authenticated caller | Content-derived spoof | **DROP** as identity | Negative test: extra HTTP identity keys rejected |
| `Delegation-Chain:` string | Explicit delegation | Copy-paste label | **DROP** | Coded DelegationTicket (later 7B) |
| `_AGENT_GRANTED_SCOPE` | Per-agent A2A tokens | Unrelated to MCP tools | **DROP** | Separate **caller delegated grant** vs **deputy ambient grant** |
| `_AGENT_USED_SCOPE` | Privilege-creep detector | **Global mutable set** | **DROP** | Per-run only; no global mutation |
| `agent_registry.mcp_scope` | Per-agent MCP grant | Identical list for all | **DROP** | Distinct coded grants |
| `workflow_guard` A2A branch | Block confused deputy | Blocks **LLM** on markers | **REDESIGN** | CTRL-DELEGATION-001 before handler |
| W8 DID spoof workshop | Identity integrity | Marker theater | **REFACTOR** | Teaching contrast only; not preferred ATTACK |
| AML.T0073 privilege creep | Privilege escalation | Marker + token delta | **DROP** mapping | Do not attach to MCP-006 |
| Cisco A2A Scanner | Product control | Overlay | **DROP** | Out of MCP-006 core |
| AgentSec `delegator.agent.id` | Prior hop attribution | Real, in-process, not A2A | **REUSE** | Hop-1 deputy may name hop-0 caller |
| AgentSec coded `McpPolicy` | Server-owned grant | Real for one MCP agent | **REFACTOR** | Two policies: caller delegated vs deputy ambient |
| AgentSec extra-field reject | No client grants | Real on `/mcp/invoke` | **REUSE** | Keep; identity keys stay extra |
| AgentSec AllowTicket (MCP-004) | Check/use bind | Real for resource | **REUSE** idea | DelegationTicket |
| MCP_LAB_PLAN MCP-006 sketch | Confused deputy = spoofed id | Too small; misses ambient authority | **REDESIGN** | Preferred ATTACK is ambient-authority misuse |

---

## What AgentSec already has that MCP-006 must not redo

| Lab | Property | MCP-006 must not become |
|-----|----------|-------------------------|
| MCP-001 | May this **agent** call this **tool**? | Another allow-list of one agent |
| MCP-003 | May it call it at this **scope**? | Scope creep |
| MCP-004 | May it operate on this **resource**? | Resource ACL |
| MCP-005 | May **result data** create authority? | Malicious `summary` overlay |

MCP-006 adds: may **this caller** ask **this deputy** to spend **delegated** authority, not the deputy’s **ambient** grant.

---

## Verdict for Phase 7A

Reuse AgentSec’s coded grants, extra-field rejection, hop/delegator attribution, handler counters, and AllowTicket idea.

Drop AgentWatch DID/passport/global scope/Cisco/SIMULATED A2A labels as enforcement.

Redesign the control as **CTRL-DELEGATION-001** on a real in-process deputy MCP invoke.

Do not implement in 7A.
