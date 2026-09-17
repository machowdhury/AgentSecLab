# MCP catalog / metadata trust model

**Status:** Phase 8B DESIGN. Schema **1.4.0** unchanged. No runtime.  
**Lab:** LAB-MCP-CATALOG. Attack id **MCP-CATALOG-001** (not “MCP-007 because the number exists”).  
**Primary invariant:** INV-002.

---

## Security property

Can attacker-controlled or compromised **MCP tool metadata** influence an agent into **requesting** authority or behavior that the **server-owned** security policy did not grant?

Defended answer:

- Metadata may influence **reasoning / tool selection intent**.
- Metadata **must not become authorization**.
- Server-owned grants (`allowed_tools`, scopes, resources, identity, delegation, control config) stay coded.
- The follow-on handler must not begin unless CTRL-MCP-001 ALLOWs from **policy**, not from text.

---

## Five properties (do not collapse)

| Property | Meaning | This lab’s teaching cut |
|----------|---------|-------------------------|
| **CATALOG INTEGRITY** | Is this the catalog we think it is (fingerprint / pin / mutation)? | **Out of 8B.** Static snapshot only. Rug-pull / `notifications/tools/list_changed` is Phase 9. |
| **METADATA TRUST** | Is `description` / schema text **data**? | **In.** CTRL-MCP-METADATA-001 classifies it. |
| **TOOL SELECTION** | Which `tools/call` does the agent request next? | Lab interpreter emits a **closed** follow-on intent from description prose. Not an LLM. |
| **AUTHORIZATION** | May that call proceed? | **Always CTRL-MCP-001.** Overlay is the vulnerable lie. |
| **EXECUTION** | Did the handler begin? | Registry spy. `mcp.started` ≠ success. |

---

## What “tool-description poisoning” means here

**ESTABLISHED research class, AgentSec teaching model:**

An MCP server exposes a **legitimate registered** tool (`lookup_policy`). Its MCP `description` contains instruction-like text (Invariant Labs TPA: hidden instructions in descriptions). A client/agent that feeds that text into a planner may **request** another tool (`lookup_customer_tier`) that is **registered but not granted**.

That request is **not** a grant. CTRL-MCP-001 must still DENY on the defended profile.

**Not in this definition:**

- Malicious handler binary (supply chain of code)
- Changing `allowed_tools` because a description said so
- `security_override=true` / `grant_tool=` fields (fake authority protocol)
- Rug-pull after approval
- Cross-server tool shadowing (multi-MCP) — later

---

## INV-002 mapping (precise)

Repository text (`docs/SECURITY_INVARIANTS.md`):

> Retrieved content cannot independently authorize privileged actions.

MCP-005 already applied this to **tool results**. LAB-MCP-CATALOG applies it to **tool metadata** obtained from a catalog/`tools/list`-shaped snapshot.

**Forbidden widenings from metadata alone:**

tool grants · scope grants · resource grants · identity · delegation · approval · control configuration · coded `McpPolicy`

**Allowed:** a planner **asks** for a follow-on. Asking is not ALLOW.

No new invariant. INV-002 expresses the property.

| Other INV | Role |
|-----------|------|
| INV-001 | Secondary: follow-on must not receive more than coded delegation. Overlay is the INV-002 violation that *looks* like INV-001 failure. |
| INV-004 | Follow-on still attributable to `run.id` + agent. |
| INV-005 | Description must not mint `gen_ai.agent.id`. |
| INV-007 | Classify metadata; hash/preview; do not dump full descriptions by default. |
| INV-008 | Malformed catalog → ERROR, not ALLOW. Vulnerable fail-open is **labeled** and **per-run**. |

---

## Control placement

```text
catalog snapshot (tools/list-shaped)
        ↓
CTRL-MCP-METADATA-001     ← classify metadata (OBSERVE vs labeled fail-open)
        ↓
(optional) follow-on intent from description  ← lab interpreter, not authority
        ↓
CTRL-MCP-001              ← only authorization of tools/call
        ↓
handler (if ALLOW)
```

First `lookup_policy` call remains a normal MCP-001 ALLOW when the tool is granted. Malicious **description** must **not** DENY the granted tool. That would mix catalog admission with authorization.

---

## CTRL-MCP-METADATA-001 (justified, not fake)

| Item | Design |
|------|--------|
| Purpose | Record that catalog metadata was consumed and **classified**. Does not sanitize. Does not replace CTRL-MCP-001. |
| Dangerous op it sits before | **Follow-on** `tools/call` (and overlay mint). Not the first granted call. |
| Defended + any fixture | `OBSERVE`, reason `metadata_is_data`. No overlay. |
| Vulnerable + malicious fixture + closed follow-on phrase | `ALLOW`, reason `vulnerable_profile_fail_open:metadata_derived_authority`. Mints **per-run** overlay only. |
| Malformed catalog | `ERROR`. No overlay. No follow-on. |
| Scanner JSON | **Not an input** to this control. |

`ALLOW` here means “the lab treated metadata as a grant **source**” (fail-open), matching MCP-005 RESULT-001 ALLOW semantics. It does **not** mean the follow-on handler ran. CTRL-MCP-001 still runs.

Do not use DENY on METADATA-001 for “description looks bad” in 8B. That would be a scanner/admission product, not this teaching cut.

---

## Framework mapping (8B)

| Framework | Mapping | Honesty |
|-----------|---------|---------|
| OWASP ASI02 Tool Misuse | Tool-interface poisoning on a **legitimate** tool | Applicable. ASI02’s own example: poisoned descriptors. |
| OWASP ASI04 Agentic Supply Chain | If the **server/package** is malicious at source | **Partial / not the 8B cut** (tool stays the real `lookup_policy` handler). |
| OWASP LLM01:2026 Prompt Injection | Description as instruction channel | Related (indirect-ish). Do not replace ASI02. |
| MITRE ATLAS | **UNMAPPED / REQUIRES REVALIDATION** | atlas.mitre.org technique URLs 404’d in Phase 8A. Do not reuse stale AgentSec `AML.T0050` / `AML.T0054`. |
| Invariant TPA (2025-04-01) | Research source | **EMERGING** class; AgentSec fixture is a **minimized** harmless analogue. |
| Cisco mcp-scanner taxonomy TOOL POISONING (AISubtech-12.1.2) | Scanner finding class | Mapping of **scanner labels**, not a runtime ATT&CK id. |

Maturity: **EMERGING** (published TPA research). The lab overlay is an **AgentSec teaching model**, not a claim that production MCP clients mint grants from descriptions the same way.

---

## Security review (design)

| Attack / failure | Design response | Residual |
|------------------|-----------------|----------|
| Metadata changes grants | Overlay per-run only; `coded_policy()` immutable | 8C tests must assert policy frozenset identity |
| Client supplies trust labels | Reject like other policy fields | Same request contract as MCP labs |
| Scanner output becomes authority | Scanners not on the authorize path | Overlay later temptation — forbid in 8C |
| Description changes identity / scope / resources | Interpreter only emits closed follow-on tool+scope | Phrase naming other tools → no overlay |
| Global mutable policy | Forbidden | — |
| Unknown tools | Overlay cannot register; ERROR | — |
| Malformed catalog | METADATA-001 ERROR | — |
| Fingerprint mismatch | **Not 8B** (rug-pull) | Phase 9 |
| Scanner FP/FN | Findings ≠ DENY / ≠ safe | — |
| Description truncation | Hash over full string; preview truncated | Preview must not be used as the interpreter input |
| Unicode / case / whitespace | Exact substring, like MCP-005 | Residual bypass if attacker mutates Unicode — acceptable for teaching fixture |
| Metadata injection into logs/UI | Hash + preview only | `/ui-review` later |
| Result vs metadata confusion | Separate markers and control types | Workshop LEARN must contrast MCP-005 |
| DENY after execution | Follow-on DENY **before** handler | Spy count 0 on C |
| Telemetry silence as prevention | Runtime spy authoritative | Splunk blocked until fields exist |

No remaining BLOCKER. HIGH residual: schema gap (1.4.0) — accepted by proposing 1.5.0, not faking events.
